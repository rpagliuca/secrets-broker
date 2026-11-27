package web

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/rpagliuca/secrets-broker/broker"
)

// Broker is what the panel sees of the broker: the commands of the control
// socket and the audit log.
type Broker interface {
	Sealed() (bool, error)
	Pending() ([]broker.Request, error)
	Grants() ([]broker.Grant, error)
	// Approve grants a request. codes has the one-time code of each
	// credential that needs one; only, when not empty, lists the
	// credentials granted (the rest is refused); why is what the client
	// reads about what was refused.
	Approve(id string, d time.Duration, codes map[string]string, only []string, why string) error
	Deny(id, why string) error
	// Revoke ends the grants of a client, or of all with "all".
	Revoke(who string) (int, error)
	Events(since time.Time) ([]broker.Event, error)
	// Blocked lists the cooldowns in force; Unblock ends those of a client,
	// or of all with "all". Unblocking grants nothing: it lets ask again.
	Blocked() ([]broker.Block, error)
	Unblock(who string) (int, error)
	// Unseal hands the vault key to the broker; Seal seals it.
	Unseal(key []byte) (string, error)
	Seal() (string, error)
}

// SocketBroker talks to a broker through its control socket and reads its
// audit log from the user journal of its systemd unit.
type SocketBroker struct {
	Socket string
	Unit   string
}

// Only simple identifiers reach the socket: a command is one line of text.
var identifier = regexp.MustCompile(`^[A-Za-z0-9:_./-]{1,120}$`)

func (c *SocketBroker) command(parts ...string) (string, error) {
	for _, p := range parts[1:] {
		if !identifier.MatchString(p) {
			return "", fmt.Errorf("invalid argument: %q", p)
		}
	}
	return broker.ControlRequest(c.Socket, strings.Join(parts, " "), nil)
}

func (c *SocketBroker) Sealed() (bool, error) {
	r, err := c.command("status")
	if err != nil {
		return false, err
	}
	return strings.Contains(r, "sealed=true"), nil
}

// jsonList reads the list after the "ok" line of a "… json" command.
func jsonList(answer string, v any) error {
	_, raw, ok := strings.Cut(answer, "\n")
	if !ok {
		return fmt.Errorf("answer without a list: %q", answer)
	}
	return json.Unmarshal([]byte(raw), v)
}

func (c *SocketBroker) Pending() ([]broker.Request, error) {
	r, err := c.command("pending", "json")
	if err != nil {
		return nil, err
	}
	var out []broker.Request
	return out, jsonList(r, &out)
}

func (c *SocketBroker) Grants() ([]broker.Grant, error) {
	r, err := c.command("grants", "json")
	if err != nil {
		return nil, err
	}
	var out []broker.Grant
	return out, jsonList(r, &out)
}

var oneTimeCode = regexp.MustCompile(`^[0-9]{6,8}$`)

func (c *SocketBroker) Approve(id string, d time.Duration, codes map[string]string, only []string, why string) error {
	if d <= 0 {
		return errors.New("the duration must be positive")
	}
	if !identifier.MatchString(id) {
		return fmt.Errorf("invalid argument: %q", id)
	}
	parts := []string{"approve", id, d.String()}
	if len(only) > 0 {
		for _, name := range only {
			if !identifier.MatchString(name) {
				return fmt.Errorf("invalid argument: %q", name)
			}
		}
		parts = append(parts, "-only", strings.Join(only, ","))
	}
	for name, code := range codes {
		if !identifier.MatchString(name) || !oneTimeCode.MatchString(code) {
			return fmt.Errorf("invalid one-time code for %q", name)
		}
		parts = append(parts, name+"="+code)
	}
	if w := cleanWhy(why); w != "" {
		parts = append(parts, "-why", w)
	}
	_, err := broker.ControlRequest(c.Socket, strings.Join(parts, " "), nil)
	return err
}

// maxWhy is the longest refusal text, as in the broker.
const maxWhy = 300

// cleanWhy puts a refusal text on one line, without control characters and
// with at most maxWhy bytes: it goes last on the control socket line.
func cleanWhy(m string) string {
	m = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, m)
	m = strings.Join(strings.Fields(m), " ")
	if len(m) > maxWhy {
		m = strings.ToValidUTF8(m[:maxWhy], "")
	}
	return m
}

func (c *SocketBroker) Deny(id, why string) error {
	if !identifier.MatchString(id) {
		return fmt.Errorf("invalid argument: %q", id)
	}
	line := "deny " + id
	if w := cleanWhy(why); w != "" {
		line += " " + w
	}
	_, err := broker.ControlRequest(c.Socket, line, nil)
	return err
}

var (
	revokedAnswer   = regexp.MustCompile(`^ok: (\d+) grants revoked`)
	unblockedAnswer = regexp.MustCompile(`^ok: (\d+) cooldowns ended`)
	blockedLine     = regexp.MustCompile(`^(\S+)  credential=(\S+)  until=(\S+)$`)
)

func (c *SocketBroker) count(re *regexp.Regexp, parts ...string) (int, error) {
	r, err := c.command(parts...)
	if err != nil {
		return 0, err
	}
	m := re.FindStringSubmatch(r)
	if m == nil {
		return 0, fmt.Errorf("unexpected answer from the broker: %q", r)
	}
	return strconv.Atoi(m[1])
}

func (c *SocketBroker) Revoke(who string) (int, error) { return c.count(revokedAnswer, "revoke", who) }

func (c *SocketBroker) Unblock(who string) (int, error) {
	return c.count(unblockedAnswer, "unblock", who)
}

func (c *SocketBroker) Seal() (string, error) { return broker.ControlRequest(c.Socket, "seal", nil) }

func (c *SocketBroker) Unseal(key []byte) (string, error) {
	return broker.ControlRequest(c.Socket, "unseal", bytes.NewReader(key))
}

func (c *SocketBroker) Blocked() ([]broker.Block, error) {
	r, err := c.command("blocked")
	if err != nil {
		return nil, err
	}
	var out []broker.Block
	for _, line := range strings.Split(r, "\n")[1:] {
		m := blockedLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("unexpected cooldown line: %q", line)
		}
		until, err := time.Parse(time.RFC3339, m[3])
		if err != nil {
			return nil, err
		}
		out = append(out, broker.Block{Principal: m[1], Credential: m[2], Until: until})
	}
	return out, nil
}

// Events reads the audit log, which the broker writes as JSON lines on its
// standard output and systemd keeps in the user journal.
func (c *SocketBroker) Events(since time.Time) ([]broker.Event, error) {
	cmd := exec.Command("journalctl", "--user", "-u", c.Unit, "-o", "cat", "--no-pager",
		"--since", "@"+strconv.FormatInt(since.Unix(), 10))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("journalctl: %w", err)
	}
	return parseEvents(out), nil
}

// parseEvents skips lines that are not events (ordinary log messages).
func parseEvents(out []byte) []broker.Event {
	var events []broker.Event
	lines := bufio.NewScanner(bytes.NewReader(out))
	lines.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for lines.Scan() {
		line := bytes.TrimSpace(lines.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev broker.Event
		if json.Unmarshal(line, &ev) == nil && ev.Decision != "" {
			events = append(events, ev)
		}
	}
	return events
}
