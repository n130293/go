package main

import (
	"fmt"
	"log"

	"github.com/pytimer/win-netstat"
)

func tcp4() {
	conns, err := winnetstat.Connections("tcp4")
	if err != nil {
		log.Fatal(err)
	}
	for _, conn := range conns {

		fmt.Printf("tcp %16s:%d  %20d %24s\n", conn.LocalAddr, conn.LocalPort, conn.OwningPid, conn.State)

	}
}

func main() {
fmt.Printf("proto %16s %20s %24s\n", "Local Adress port ", "pid","State")
	 tcp4()
}