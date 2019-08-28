package main

import (
    "fmt"

	"github.com/cakturk/go-netstat/netstat"
)
func main() {
 
fmt.Printf("Proto %16s %20s %14s %24s\n", "Local Adress", "Foregin Adress","State", "Pid/Program")
	tcp6:=true
	 
	if tcp6 {
		var fn netstat.AcceptFn   
		switch {
		case tcp6:
			fn = func(s *netstat.SockTabEntry) bool {
				return s.State != netstat.Listen
			}
		}
		tabs, _:= netstat.TCP6Socks(fn)
		displaySockInfo("tcp6", tabs)
   }
}

func displaySockInfo(proto string, s []netstat.SockTabEntry) {
	lookup := func(skaddr *netstat.SockAddr) string { //addr with port
		const IPv4Strlen = 17
		addr := skaddr.IP.String()
		
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
   