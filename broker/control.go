package broker

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// maxKeySize bounds what the control socket reads.
const maxKeySize = 64 << 10

// ListenControl creates the control socket. Access is decided by file
// permissions: mode 0660, owner and group of the broker process. Give the
// group only to the account that delivers the key.
func ListenControl(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// ServeControl answers the control protocol: one command line ("unseal",
// "seal" or "status"), then, for unseal, the key until the client closes its
// side. The answer is a single line starting with "ok" or "error".
func ServeControl(l net.Listener, u Unsealer, sealed func() bool) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(30 * time.Second))
			br := bufio.NewReader(io.LimitReader(c, maxKeySize))
			cmd, _ := br.ReadString('\n')
			switch strings.TrimSpace(cmd) {
			case "unseal":
				key, err := io.ReadAll(br)
				if err != nil {
					fmt.Fprintf(c, "error: %v\n", err)
					return
				}
				n, err := u.Unseal(key)
				clear(key)
				if err != nil {
					log.Printf("unseal failed: %v", err)
					fmt.Fprintf(c, "error: %v\n", err)
					return
				}
				log.Printf("unsealed: %d secrets loaded", n)
				fmt.Fprintf(c, "ok: unsealed, %d secrets loaded\n", n)
			case "seal":
				u.Seal()
				log.Printf("sealed")
				fmt.Fprintln(c, "ok: sealed")
			case "status":
				fmt.Fprintf(c, "ok: sealed=%t\n", sealed())
			default:
				fmt.Fprintln(c, "error: unknown command")
			}
		}()
	}
}

// Control sends one command to the control socket and returns the answer.
// For unseal, key is streamed from in (typically standard input).
func Control(socket, cmd string, in io.Reader) (string, error) {
	c, err := net.Dial("unix", socket)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if _, err := fmt.Fprintln(c, cmd); err != nil {
		return "", err
	}
	if in != nil {
		if _, err := io.Copy(c, in); err != nil {
			return "", err
		}
	}
	if err := c.(*net.UnixConn).CloseWrite(); err != nil {
		return "", err
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	reply = strings.TrimSpace(reply)
	if err != nil && reply == "" {
		return "", err
	}
	if !strings.HasPrefix(reply, "ok") {
		return reply, errors.New(reply)
	}
	return reply, nil
}
