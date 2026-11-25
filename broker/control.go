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
// group only to the accounts that deliver the key or answer requests.
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

// Control answers the control socket. The protocol is one command line,
// then, for unseal, the key until the client closes its side. The answer
// starts with a line beginning with "ok" or "error"; lists follow it, one
// item per line.
//
//	unseal                     open the store with the key that follows
//	seal                       forget the key and every secret
//	status                     sealed or not
//	pending                    requests waiting for approval
//	approve ID DURATION        grant a request, e.g. "approve 3f9a1c22 1h"
//	deny ID                    refuse a request
//	grants                     grants in force
//	revoke PRINCIPAL|all       end grants before they expire
type Control struct {
	Unsealer Unsealer // nil when the store does not seal
	Sealed   func() bool
	Grants   *Grants // nil when approval is not configured
}

// Serve handles connections until the listener is closed.
func (c *Control) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			br := bufio.NewReader(io.LimitReader(conn, maxKeySize))
			line, _ := br.ReadString('\n')
			reply, err := c.run(strings.Fields(line), br)
			if err != nil {
				reply = "error: " + err.Error()
			}
			fmt.Fprintln(conn, reply)
		}()
	}
}

func (c *Control) run(args []string, rest io.Reader) (string, error) {
	if len(args) == 0 {
		return "", errors.New("empty command")
	}
	cmd, args := args[0], args[1:]
	switch {
	case cmd == "status" && len(args) == 0:
		return fmt.Sprintf("ok: sealed=%t", c.Sealed()), nil
	case cmd == "unseal" || cmd == "seal":
		if c.Unsealer == nil || len(args) != 0 {
			return "", errors.New("this store cannot be sealed or unsealed")
		}
		if cmd == "seal" {
			c.Unsealer.Seal()
			log.Printf("sealed")
			return "ok: sealed", nil
		}
		key, err := io.ReadAll(rest)
		if err != nil {
			return "", err
		}
		n, err := c.Unsealer.Unseal(key)
		clear(key)
		if err != nil {
			log.Printf("unseal failed: %v", err)
			return "", err
		}
		log.Printf("unsealed: %d secrets loaded", n)
		return fmt.Sprintf("ok: unsealed, %d secrets loaded", n), nil
	case c.Grants == nil:
		return "", errors.New("unknown command, or approval is not configured")
	case cmd == "pending" && len(args) == 0:
		reqs := c.Grants.Pending()
		out := fmt.Sprintf("ok: %d waiting", len(reqs))
		for _, r := range reqs {
			out += fmt.Sprintf("\n%s  %s  %q  credential=%s  hosts=%s  since=%s", r.ID, r.Principal.ID,
				r.Principal.Name, strings.Join(r.Credentials, ","), strings.Join(r.Hosts, ","), r.Created.Format(time.RFC3339))
			if r.Suggested > 0 {
				out += "  suggested=" + r.Suggested.String()
			}
		}
		return out, nil
	case cmd == "grants" && len(args) == 0:
		grants := c.Grants.Active()
		out := fmt.Sprintf("ok: %d in force", len(grants))
		for _, g := range grants {
			out += fmt.Sprintf("\n%s  credential=%s  until=%s", g.Principal, g.Credential, g.Until.Format(time.RFC3339))
		}
		return out, nil
	case cmd == "approve" && len(args) == 2:
		d, err := time.ParseDuration(args[1])
		if err != nil || d <= 0 {
			return "", errors.New("approve needs a positive duration, such as 1h")
		}
		if err := c.Grants.Decide(args[0], d, "control socket"); err != nil {
			return "", err
		}
		return "ok: granted for " + d.String(), nil
	case cmd == "deny" && len(args) == 1:
		if err := c.Grants.Decide(args[0], 0, "control socket"); err != nil {
			return "", err
		}
		return "ok: refused", nil
	case cmd == "revoke" && len(args) == 1:
		return fmt.Sprintf("ok: %d grants revoked", c.Grants.Revoke(args[0], "control socket")), nil
	}
	return "", errors.New("unknown command or wrong arguments")
}

// ControlRequest sends one command to the control socket and returns the
// answer. For unseal, the key is streamed from in (typically standard
// input).
func ControlRequest(socket, cmd string, in io.Reader) (string, error) {
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
	raw, err := io.ReadAll(io.LimitReader(c, 1<<20))
	reply := strings.TrimSpace(string(raw))
	if err != nil && reply == "" {
		return "", err
	}
	if !strings.HasPrefix(reply, "ok") {
		return reply, errors.New(strings.TrimPrefix(reply, "error: "))
	}
	return reply, nil
}
