package main

import (
    "fmt"
    "github.com/drael/GOnetstat"
)

func main() {
     d := GOnetstat.Tcp()

     fmt.Printf("Proto %16s %20s %14s %24s\n", "Local Adress", "Foregin Adress","State", "Pid/Program")
     for _, p := range(d) {
        ip_port := fmt.Sprintf("%v:%v", p.Ip, p.Port)
        fip_port := fmt.Sprintf("%v:%v", p.ForeignIp, p.ForeignPort)
        pid_program := fmt.Sprintf("%v/%v", p.Pid, p.Name)

        fmt.Printf("udp %16v %20v %16v %20v\n", ip_port, fip_port,
                            p.State, pid_program)
     }
	
}