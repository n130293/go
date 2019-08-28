package system

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"maze.io/system.v0/netlink"
)

var (
	// socketTypeMap is a map of "golang type" to Darwin (netstat) type names.
	socketTypeMap = map[string]map[string]bool{
		"tcp":  map[string]bool{"tcp": true, "tcp6": true},
		"tcp4": map[string]bool{"tcp": true},
		"tcp6": map[string]bool{"tcp6": true},
		"udp":  map[string]bool{"udp": true, "udp6": true},
		"udp4": map[string]bool{"udp": true},
		"udp6": map[string]bool{"udp6": true},
		"unix": map[string]bool{"unix": true},
		"any":  map[string]bool{}, // Filled by init
	}

	socketStateMap = map[string]SocketState{
		"00": Unknown,
		"01": Established,
		"02": SYNSent,
		"03": SYNRecv,
		"04": FINWait1,
		"05": FINWait2,
		"06": TimeWait,
		"07": Close,
		"08": CloseWait,
		"09": LastACK,
		"0A": Listen,
		"0B": Closing,
	}
)

func init() {
	for _, m := range socketTypeMap {
		for t := range m {
			socketTypeMap["any"][t] = true
		}
	}
}

func interfaceByName(name string) (*Interface, error) {
	interfaces, err := interfaceTable(0)
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		if iface.Name == name {
			return &iface, nil
		}
	}
	return nil, ErrNotFound
}

// If the ifindex is zero, interfaceTable returns mappings of all
// network interfaces. Otherwise it returns a mapping of a specific
// interface.
func interfaceTable(ifindex int) ([]Interface, error) {
	tab, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return nil, os.NewSyscallError("netlinkrib", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, os.NewSyscallError("parsenetlinkmessage", err)
	}
	var ift []Interface
loop:
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			break loop
		case syscall.RTM_NEWLINK:
			ifim := (*syscall.IfInfomsg)(unsafe.Pointer(&m.Data[0]))
			if ifindex == 0 || ifindex == int(ifim.Index) {
				attrs, err := syscall.ParseNetlinkRouteAttr(&m)
				if err != nil {
					return nil, os.NewSyscallError("parsenetlinkrouteattr", err)
				}
				ift = append(ift, *newLink(ifim, attrs))
				if ifindex == int(ifim.Index) {
					break loop
				}
			}
		}
	}
	return ift, nil
}

const (
	// See linux/if_arp.h.
	// Note that Linux doesn't support IPv4 over IPv6 tunneling.
	sysARPHardwareIPv4IPv4 = 768 // IPv4 over IPv4 tunneling
	sysARPHardwareIPv6IPv6 = 769 // IPv6 over IPv6 tunneling
	sysARPHardwareIPv6IPv4 = 776 // IPv6 over IPv4 tunneling
	sysARPHardwareGREIPv4  = 778 // any over GRE over IPv4 tunneling
	sysARPHardwareGREIPv6  = 823 // any over GRE over IPv6 tunneling
)

func newLink(ifim *syscall.IfInfomsg, attrs []syscall.NetlinkRouteAttr) *Interface {
	ifi := net.Interface{Index: int(ifim.Index), Flags: linkFlags(ifim.Flags)}
	for _, a := range attrs {
		switch a.Attr.Type {
		case syscall.IFLA_ADDRESS:
			// We never return any /32 or /128 IP address
			// prefix on any IP tunnel interface as the
			// hardware address.
			switch len(a.Value) {
			case net.IPv4len:
				switch ifim.Type {
				case sysARPHardwareIPv4IPv4, sysARPHardwareGREIPv4, sysARPHardwareIPv6IPv4:
					continue
				}
			case net.IPv6len:
				switch ifim.Type {
				case sysARPHardwareIPv6IPv6, sysARPHardwareGREIPv6:
					continue
				}
			}
			var nonzero bool
			for _, b := range a.Value {
				if b != 0 {
					nonzero = true
					break
				}
			}
			if nonzero {
				ifi.HardwareAddr = a.Value[:]
			}
		case syscall.IFLA_IFNAME:
			ifi.Name = string(a.Value[:len(a.Value)-1])
		case syscall.IFLA_MTU:
			ifi.MTU = int(*(*uint32)(unsafe.Pointer(&a.Value[:4][0])))
		}
	}
	return &Interface{ifi, ifim}
}

func linkFlags(rawFlags uint32) net.Flags {
	var f net.Flags
	if rawFlags&syscall.IFF_UP != 0 {
		f |= net.FlagUp
	}
	if rawFlags&syscall.IFF_BROADCAST != 0 {
		f |= net.FlagBroadcast
	}
	if rawFlags&syscall.IFF_LOOPBACK != 0 {
		f |= net.FlagLoopback
	}
	if rawFlags&syscall.IFF_POINTOPOINT != 0 {
		f |= net.FlagPointToPoint
	}
	if rawFlags&syscall.IFF_MULTICAST != 0 {
		f |= net.FlagMulticast
	}
	return f
}

// Counters returns the actual interface counters.
func (iface *Interface) Counters() (*InterfaceCounters, error) {
	var (
		base = filepath.Join(SysPath, "class/net", iface.Name, "statistics")
		c    = new(InterfaceCounters)
	)
	if err := procMap(base, map[string]interface{}{
		"rx_bytes":   &c.RxBytes,
		"rx_packets": &c.RxPackets,
		"rx_errors":  &c.RxErrors,
		"rx_dropped": &c.RxDropped,
		"tx_bytes":   &c.TxBytes,
		"tx_packets": &c.TxPackets,
		"tx_errors":  &c.TxErrors,
		"tx_dropped": &c.TxDropped,
		"collisions": &c.Collisions,
		"multicast":  &c.Multicast,
	}); err != nil {
		return nil, err
	}

	return c, nil
}

type socketTypeParser func(string, string, chan Socket)

func getSocketsType(t string) <-chan Socket {
	ch := make(chan Socket)
	if err := getSocketsTypeFromNetlink(t, ch); err != nil {
		// Netlink failed, let's resort to proc *slooowwww*
		go getSocketsTypeFromProc(t, ch)
	}
	return ch
}

func getSocketsTypeFromNetlink(t string, ch chan Socket) (err error) {
	// See if we can create netlink socket.
	if _, err := netlink.NewSocket(0, 0); err != nil {
		return nil
	}

	var queries []netlinkQuery
	switch t {
	case any:
		queries = append(queries, netlinkQuery{netlink.INET, netlink.TCP, netlink.StatesConnected})
		queries = append(queries, netlinkQuery{netlink.INET6, netlink.TCP, netlink.StatesConnected})
		queries = append(queries, netlinkQuery{netlink.INET, netlink.UDP, netlink.StatesEstablished})
		queries = append(queries, netlinkQuery{netlink.INET6, netlink.UDP, netlink.StatesEstablished})
	case tcp:
		queries = append(queries, netlinkQuery{netlink.INET, netlink.TCP, netlink.StatesConnected})
		queries = append(queries, netlinkQuery{netlink.INET6, netlink.TCP, netlink.StatesConnected})
	case tcp4:
		queries = append(queries, netlinkQuery{netlink.INET, netlink.TCP, netlink.StatesConnected})
	case tcp6:
		queries = append(queries, netlinkQuery{netlink.INET6, netlink.TCP, netlink.StatesConnected})
	case udp:
		queries = append(queries, netlinkQuery{netlink.INET, netlink.UDP, netlink.StatesEstablished})
		queries = append(queries, netlinkQuery{netlink.INET6, netlink.UDP, netlink.StatesEstablished})
	case udp4:
		queries = append(queries, netlinkQuery{netlink.INET, netlink.UDP, netlink.StatesEstablished})
	case udp6:
		queries = append(queries, netlinkQuery{netlink.INET6, netlink.UDP, netlink.StatesEstablished})
	}

	if len(queries) == 0 {
		return errors.New("no queries")
	}

	ipMap := InodesWithPIDs()
	go func() {
		for _, q := range queries {
			q.run(ch, ipMap)
		}
		close(ch)
	}()

	return nil
}

type netlinkQuery struct {
	f netlink.Family
	p netlink.Protocol
	s netlink.States
}

func (q *netlinkQuery) run(ch chan Socket, ipMap map[Inode]PID) {
	if ch == nil {
		return
	}

	r := netlink.NewRequest()
	i := netlink.NewInetDiagRequestV2(q.f, q.p, q.s)

	i.Ext |= (1 << (netlink.INET_DIAG_INFO - 1))
	i.Ext |= (1 << (netlink.INET_DIAG_VEGASINFO - 1))
	i.Ext |= (1 << (netlink.INET_DIAG_CONG - 1))

	r.Type = netlink.SOCK_DIAG_BY_FAMILY
	r.Flags = netlink.NLM_F_ROOT | netlink.NLM_F_MATCH | netlink.NLM_F_REQUEST
	r.Seq = 2342
	r.Add(i)

	messages, err := r.Do(netlink.NETLINK_INET_DIAG, 0)
	if err != nil {
		return
	}

	for _, data := range messages {
		var (
			msg    = netlink.UnmarshalInetDiagMsg(data)
			socket Socket
		)

		socket.State = SocketState(msg.State)
		socket.Inode = Inode(msg.Inode)
		socket.UID = msg.UID
		socket.PID = ipMap[socket.Inode]

		switch q.p {
		case netlink.TCP:
			switch q.f {
			case netlink.INET:
				socket.Net = tcp4
			case netlink.INET6:
				socket.Net = tcp6
			default:
				socket.Net = tcp
			}
			socket.LocalAddr = &net.TCPAddr{
				IP:   msg.ID.SrcIP(q.f),
				Port: int(msg.ID.SrcPort),
			}
			socket.RemoteAddr = &net.TCPAddr{
				IP:   msg.ID.DstIP(q.f),
				Port: int(msg.ID.DstPort),
			}
		case netlink.UDP:
			switch q.f {
			case netlink.INET:
				socket.Net = udp4
			case netlink.INET6:
				socket.Net = udp6
			default:
				socket.Net = udp
			}
			socket.LocalAddr = &net.UDPAddr{
				IP:   msg.ID.SrcIP(q.f),
				Port: int(msg.ID.SrcPort),
			}
			socket.RemoteAddr = &net.UDPAddr{
				IP:   msg.ID.DstIP(q.f),
				Port: int(msg.ID.DstPort),
			}
		}

		ch <- socket
	}
}

func getSocketsTypeFromProc(t string, ch chan Socket) {
	names, ok := socketTypeMap[t]
	if !ok {
		close(ch)
		return // fmt.Errorf(`host: unsupported socket type %s`, t)
	}

	go func() {
		for name := range names {
			var p socketTypeParser

			switch name {
			case tcp, tcp6, udp, udp6:
				p = parseInternetSocket
			case "unix":
				p = parseUNIXSocket
			default:
				//return fmt.Errorf(`host: unsupported socket type %s`, name)
				continue
			}

			var (
				f   *os.File
				err error
			)
			if f, err = os.Open(filepath.Join(ProcPath, "net", name)); err != nil {
				continue
			}
			defer f.Close()

			r := bufio.NewReader(f)

			// Skip table header
			if _, err = r.ReadString('\n'); err != nil {
				continue
			}

			for {
				var l string
				if l, err = r.ReadString('\n'); err != nil {
					break
				}

				p(name, l, ch)
			}
		}

		close(ch)
	}()
}

/*
func (list *Sockets) getPIDs() (pidMap map[Socket]PID, err error) {
	// Firstly we map all PIDs to their file descriptors.
	var pids ProcessList
	if pids, err = GetProcessList(); err != nil {
		return
	}

	inodeMap := make(map[uint64]Socket)
	for _, socket := range *list {
		inodeMap[socket.Inode] = socket
	}

	pidMap = make(map[Socket]PID)
	for _, pid := range pids {
		var fds []string
		if fds, err = pid.fileDescriptors(); err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				err = nil
				continue
			}
		}

		for _, fd := range fds {
			var base = path.Base(fd)
			if !strings.HasPrefix(base, "socket:") {
				continue
			}
			base = base[7:]              // Strip prefix
			base = base[1 : len(base)-1] // Stip brackets
			if inode, err := strconv.ParseUint(base, 10, 64); err != nil {
				continue
			} else if socket := inodeMap[inode]; socket.Inode != 0 {
				pidMap[socket] = pid
			}
		}
	}

	return
}
*/

func parseInternetSocket(t, l string, ch chan Socket) {
	var (
		socket Socket
		field  = strings.Fields(l)
		err    error
	)

	if socket.LocalAddr, err = parseAddrType(t, field[1]); err != nil {
		return
	}
	if socket.RemoteAddr, err = parseAddrType(t, field[2]); err != nil {
		return
	}

	socket.State = socketStateMap[field[3]]

	queues := strings.SplitN(field[4], ":", 2)
	socket.TxQueue, _ = strconv.ParseUint(queues[0], 16, 64)
	socket.RxQueue, _ = strconv.ParseUint(queues[1], 16, 64)
	socket.Retransmit, _ = strconv.ParseUint(field[6], 16, 64)
	socket.Timeout, _ = strconv.ParseUint(field[8], 10, 64)

	var uid64, ino uint64
	uid64, _ = strconv.ParseUint(field[7], 10, 32)
	socket.UID = uint32(uid64)

	ino, _ = strconv.ParseUint(field[9], 10, 64)
	socket.Inode = Inode(ino)

	ch <- socket
}

func parseUNIXSocket(t, l string, ch chan Socket) {
	/*
		Num               RefCount Protocol Flags    Type St Inode Path
		ffff88027691b480: 00000002 00000000 00000000 0002 01   512 /run/systemd/shutdownd
		ffff8801ea53c400: 00000002 00000000 00010000 0001 01 46136 public/cleanup
	*/
	var (
		socket = Socket{Net: "unix"}
		f      = strings.Fields(l)
	)

	socket.State = socketStateMap[f[5]]

	var addr = &net.UnixAddr{}
	if len(f) >= 8 {
		addr.Name = f[7]
	}
	socket.LocalAddr = addr

	ch <- socket

	return
}

func parseAddr(addr string) (ip net.IP, port int, err error) {
	var pos = strings.LastIndexByte(addr, ':')
	if pos < 0 {
		return nil, 0, fmt.Errorf(`host: invalid address %q`, addr)
	}

	var (
		hexHost = addr[:pos]
		hexPort = addr[pos+1:]
	)

	if ip, err = hex.DecodeString(hexHost); err != nil {
		return
	}

	// Fix byte order.
	switch len(ip) {
	case 4:
		reverseBytes(ip)
	case 16:
		reverseBytes(ip[0:4])
		reverseBytes(ip[4:8])
		reverseBytes(ip[8:12])
		reverseBytes(ip[12:16])
	}

	var port64 int64
	if port64, err = strconv.ParseInt(hexPort, 16, 0); err != nil {
		return
	}
	port = int(port64)

	return
}

func parseAddrType(t, s string) (addr net.Addr, err error) {
	switch t {
	case tcp, tcp4, tcp6, "tcp46":
		tcpAddr := &net.TCPAddr{}
		tcpAddr.IP, tcpAddr.Port, err = parseAddr(s)
		addr = tcpAddr

	case udp, udp4, udp6, "udp46":
		udpAddr := &net.TCPAddr{}
		udpAddr.IP, udpAddr.Port, err = parseAddr(s)
		addr = udpAddr

	default:
		err = fmt.Errorf(`host: unsupported address type %T`, t)
	}
	return
}

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}
