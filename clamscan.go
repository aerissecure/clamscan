package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
)

const (
	clamscanExe  = "clamscan"
	clamdscanExe = "clamdscan"
)

var (
	virusFound = regexp.MustCompile(`\w+\:\s+(.+)\s+FOUND`)
)

func virusName(stdout string) string {
	matches := virusFound.FindStringSubmatch(stdout)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("missing required file arguments")
		os.Exit(1)
	}

	exe := ""

	if _, err := exec.LookPath("clamscan"); err == nil {
		exe = clamscanExe
	}

	if _, err := exec.LookPath("clamdscan"); err == nil {
		exe = clamdscanExe
	}

	if exe == "" {
		fmt.Printf("%s / %s executables not found\n", clamscanExe, clamdscanExe)
		os.Exit(1)
	}

	for _, f := range os.Args[1:] {
		file, err := os.Open(f)
		if err != nil {
			fmt.Printf("Error opening %s: %v\n", f, err)
			continue
		}

		cmd := exec.Command(exe, "-")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			fmt.Printf("Error opening stdin (%s): %v\n", f, err)
		}
		// defer stdin.Close()

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		go func() {
			defer stdin.Close()
			io.Copy(stdin, file)
		}()

		err = cmd.Run()
		ec := -1

		if err == nil {
			// Here when everything was OK with the command and 0 return code
			fmt.Println("NO VIRUS FOUND")
			os.Exit(0)
		}

		if err != nil {
			exitErr, ok := err.(*exec.ExitError)
			if ok {
				ec = exitErr.ExitCode()
			}
			if !ok {
				fmt.Printf("Error running %s: %v", exe, err)
				os.Exit(1)
			}
		}

		// fmt.Println("exit code:", ec)

		if ec == 0 {
			// Here when everything was was not OK with the command and 0 return code
			fmt.Println("NO VIRUS FOUND")
			os.Exit(0)
		}

		if ec == 1 {
			fmt.Println("FOUND VIRUS:", virusName(stdout.String()))
		}

		// We want to check stderr:

		// 0 : No virus found.
		// 1 : Virus(es) found.
		// 2 : Some error(s) occured.

		// TODO: Not sure what to do with returne stderr content
		// if stderr.String() != "" {
		// 	fmt.Println("ERROR:", stderr.String())
		// 	os.Exit(1)
		// }

		// fmt.Println("STDOUT:")
		// fmt.Println(stdout.String())
		// fmt.Println()

	}

}
