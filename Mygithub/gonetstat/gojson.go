package main

import (
    "fmt"
    "encoding/json"
    "github.com/drael/GOnetstat"
)
func main () {
    d := GOnetstat.Tcp()

    // Marshal in prety print way
    output, err := json.MarshalIndent(d, "", "    ")
    if err != nil {
        fmt.Println(err)
    }

    fmt.Println(string(output))
}