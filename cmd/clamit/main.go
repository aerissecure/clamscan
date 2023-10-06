package main

import (
	"fmt"
	"os"

	"github.com/aerissecure/clamscan"
)

func main() {

	engine, err := clamscan.New(clamscan.ClamdscanExe)
	if err != nil {
		fmt.Println("Error creating engine:", err)
		os.Exit(1)
	}
	file, _ := os.Open(os.Args[1])
	infected, name, err := engine.Scan(file)
	fmt.Println("Infected:", infected)
	fmt.Println("Name:", name)
	fmt.Println("Error:", err)

	v, err := engine.Version()
	fmt.Println("ClamAVVersion:", v.ClamAVVersion)
	fmt.Println("SignatureVersion:", v.SignatureVersion)
	fmt.Println("SignatureDate:", v.SignatureDate)
	fmt.Println("Error:", err)
}
