package clamscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	ClamscanExe  = "clamscan"
	ClamdscanExe = "clamdscan"
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

type Engine struct {
	exe string
}

type Version struct {
	ClamAVVersion    string
	SignatureVersion string
	SignatureDate    time.Time
}

func New(exe string) (Engine, error) {
	// Systemd will automatically start clamav-daemon through its socket in most
	// cases, so there isn't a good (dependency free) way to check if clamdscan
	// is running without starting it.

	e := Engine{}

	path, err := exec.LookPath(exe)
	if err != nil {
		return e, err
	}

	// Use full path
	e.exe = path

	return e, nil
}

// Parses the result of `clamscan --version`, and parses result of the form:
// `0.104.1/26419/Tue Jan 11 01:24:18 2022`
func (e Engine) Version() (Version, error) {
	cmd := exec.Command(e.exe, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return Version{}, err
	}

	ver := strings.TrimSpace(string(out))
	fields := strings.Split(ver, "/")

	if len(fields) < 3 {
		return Version{}, fmt.Errorf("unexpected output: %s", ver)
	}

	v := Version{
		ClamAVVersion:    fields[0],
		SignatureVersion: fields[1],
	}

	date, err := time.Parse("Mon Jan 02 15:05:05 2006", fields[2])
	if err != nil {
		return v, err
	}

	v.SignatureDate = date
	return v, nil
}

func (e Engine) Scan(file io.Reader) (infected bool, name string, err error) {
	return e.ScanContext(context.Background(), file)
}

func (e Engine) ScanContext(ctx context.Context, file io.Reader) (infected bool, name string, err error) {
	cmd := exec.CommandContext(ctx, e.exe, "-")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, "", err
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	go func() {
		defer stdin.Close()
		io.Copy(stdin, file)
	}()

	ec := -1
	err = cmd.Run()

	if err == nil {
		// Everything was OK with the command and return code is 0
		return false, "", nil
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit codes:
			// 0 : No virus found.
			// 1 : Virus(es) found.
			// 2 : Some error(s) occured.
			ec = exitErr.ExitCode()
		} else {
			// Unknown error occured
			return false, "", fmt.Errorf("unknown error: %w", err)
		}
	}

	if ec == 1 {
		// Note, empty virus name is not currently handled.
		return true, virusName(stdout.String()), nil
	}

	// If ec==0, everything was was NOT OK with the command and return code is 0.
	if ec == 0 && stdout.Len() == 0 {
		return false, "", nil
	}

	// Consider everything else an error.
	return false, "", errors.New(stdout.String())
}
