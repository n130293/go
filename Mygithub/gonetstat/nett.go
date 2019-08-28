package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/cakturk/go-netstat/netstat"
)

var (
	udp       = flag.Bool("udp", false, "display UDP sockets")           //824634064984
	tcp       = flag.Bool("tcp", false, "display TCP sockets")           //824634064984
	listening = flag.Bool("lis", false, "display only listening sockets")//824633786512
	all       = flag.Bool("all", false, "display both listening and non-listening sockets")//824634064984
	resolve   = flag.Bool("res", false, "lookup symbolic names for host addresses")//824634064984
	ipv4      = flag.Bool("4", false, "display only IPv4 sockets")        //824634064984
	ipv6      = flag.Bool("6", false, "display only IPv6 sockets")        //824633786512
	help      = flag.Bool("help", false, "display this help screen")      //824633786513
)

const (
	protoIPv4 = 0x01       //1
	protoIPv6 = 0x02       //2
)

func main() {
	flag.Parse()           //After all flags are defined, call

	if *help {             //*help=false
		flag.Usage()
		os.Exit(0)
	}

	var proto uint     
	if *ipv4 {
		proto |= protoIPv4
	}
	if *ipv6 {
		proto |= protoIPv6
	}
	if proto == 0x00 {
		proto = protoIPv4 | protoIPv6        //proto=3
	}

	if os.Geteuid() != 0 {   //  Return the current process’s effective user id.  true condition
		fmt.Println("Not all processes could be identified, you would have to be root to see it all.")
	}
	fmt.Printf("Proto %-23s %-23s %-12s %-16s\n", "Local Addr", "Foreign Addr", "State", "PID/Program name")

	if *udp {
		if proto&protoIPv4 == protoIPv4 {
			tabs, err := netstat.UDPSocks(netstat.NoopFilter)
			if err == nil {
				displaySockInfo("udp", tabs)
			}
		}
		if proto&protoIPv6 == protoIPv6 {
			tabs, err := netstat.UDP6Socks(netstat.NoopFilter)
			if err == nil {
				displaySockInfo("udp6", tabs)
			}
		}
	} else {
		*tcp = true
	}

	if *tcp {
		var fn netstat.AcceptFn   
		
        /*AcceptFn is used to filter socket    entries. The value returned indicates whether the element is to be appended to the socket list.*/
		
		switch {
		case *all:
			fn = func(*netstat.SockTabEntry) bool { return true }
		case *listening:
			fn = func(s *netstat.SockTabEntry) bool {
				return s.State == netstat.Listen
			}
		default:
			fn = func(s *netstat.SockTabEntry) bool {
				return s.State != netstat.Listen
			}
		}

		if proto&protoIPv4 == protoIPv4{            //3&1==1  true condition Tcp Sockets
			tabs, err := netstat.TCPSocks(fn)
			if err == nil {
				displaySockInfo("tcp", tabs)
			}
		}
		if proto&protoIPv6 == protoIPv6 {            //3&2==1  false condition 
			tabs, err := netstat.TCP6Socks(fn)
			if err == nil {
				displaySockInfo("tcp6", tabs)
			}
		}
	}
}

func displaySockInfo(proto string, s []netstat.SockTabEntry) {
	lookup := func(skaddr *netstat.SockAddr) string { //addr with port
		const IPv4Strlen = 17
		addr := skaddr.IP.String()
		if *resolve {
			names, err := net.LookupAddr(addr)
			if err == nil && len(names) > 0 {
				addr = names[0]
			}
		}
		if len(addr) > IPv4Strlen {          // 23>17
			addr = addr[:IPv4Strlen]         // total address (0:n)
		}
		return fmt.Sprintf("%s:%d", addr, skaddr.Port)
	}

	for _, e := range s {
		p := ""
		if e.Process != nil {
			p = e.Process.String()
		}
		saddr := lookup(e.LocalAddr)            //local address
		daddr := lookup(e.RemoteAddr)           //foreign address
		fmt.Printf("%-5s %-23.23s %-23.23s %-12s %-16s\n", proto, saddr, daddr, e.State, p)
	}
}