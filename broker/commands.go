package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Command is a program the broker runs for a client: something that needs a
// secret the client must not hold, such as a VPN. The program and its
// arguments come only from the configuration; the client gives a name. The
// secrets are written to a directory of the broker while the command runs
// and removed when it stops, which happens when the client asks, when its
// grant or token ends, or when the broker is sealed or stopped.
type Command struct {
	// Name is what the client asks for: POST /commands/<name>/start.
	Name string `json:"name"`
	// Groups are the client groups allowed to run the command.
	Groups []string `json:"groups"`
	// Start and Stop are argument vectors, the first element an absolute
	// path. "{dir}" is replaced by the directory holding the files. Start
	// must return once the service is up; Stop must undo it.
	Start []string `json:"start"`
	Stop  []string `json:"stop"`
	// Files are the secrets written before Start. Each secret must be bound
	// to the host "command:<name>".
	Files []CommandFile `json:"files"`
	// Env is added to a minimal environment; "{dir}" is replaced.
	Env map[string]string `json:"env,omitempty"`
	// Dir is the working directory.
	Dir string `json:"dir,omitempty"`
	// Forwards are what the command makes reachable, and only through the
	// broker: a destination the client names with "ssh -L" (the SSH user is
	// the command name) mapped to a Unix socket the command creates in
	// "{dir}". The directory belongs to the broker, so the client that
	// started the command, while its grant lasts, is the only one let in.
	Forwards map[string]string `json:"forwards,omitempty"`
}

// CommandFile is one secret written as one file.
type CommandFile struct {
	Secret string `json:"secret"`
	Name   string `json:"name"`
}

var fileNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

const (
	commandStartTimeout = 10 * time.Minute
	commandStopTimeout  = 2 * time.Minute
	commandMaxOutput    = 64 << 10
)

func (c *Command) grantName() string { return grantName("command", c.Name) }

func (c *Command) validate() error {
	if !pathNameRE.MatchString(c.Name) || len(c.Groups) == 0 || slices.Contains(c.Groups, "") {
		return fmt.Errorf("command %q: needs a valid name and at least one group", c.Name)
	}
	for _, argv := range [][]string{c.Start, c.Stop} {
		if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
			return fmt.Errorf("command %q: start and stop need an absolute program path", c.Name)
		}
	}
	if c.Dir != "" && !filepath.IsAbs(c.Dir) {
		return fmt.Errorf("command %q: dir must be absolute", c.Name)
	}
	for _, f := range c.Files {
		if !nameRE.MatchString(f.Secret) || !fileNameRE.MatchString(f.Name) {
			return fmt.Errorf("command %q: invalid file %q for secret %q", c.Name, f.Name, f.Secret)
		}
	}
	for dest, sock := range c.Forwards {
		if host, port, err := net.SplitHostPort(dest); err != nil || host == "" || port == "" || !fileNameRE.MatchString(sock) {
			return fmt.Errorf("command %q: forward %q must map host:port to a socket file name", c.Name, dest)
		}
	}
	return nil
}

// CommandKnown reports whether a client of these groups may use the command.
func (s *Server) CommandKnown(name string, groups []string) bool {
	cfg, _ := s.state()
	return cfg.commandFor(name, groups) != nil
}

// CommandActive reports whether the command is running for this client and
// its grant is still in force.
func (s *Server) CommandActive(p Principal, name string) bool {
	s.runMu.Lock()
	run := s.running[name]
	s.runMu.Unlock()
	return run != nil && run.by.ID == p.ID && (s.Approver == nil || s.Approver.Granted(p.ID, run.grant))
}

// CommandForward returns the Unix socket behind a destination of a command
// that is running for this client.
func (s *Server) CommandForward(p Principal, name, dest string) (string, error) {
	if !s.CommandActive(p, name) {
		return "", errors.New("the command is not running for this client")
	}
	s.runMu.Lock()
	run := s.running[name]
	s.runMu.Unlock()
	if run == nil {
		return "", errors.New("the command is not running for this client")
	}
	sock, ok := run.cmd.Forwards[dest]
	if !ok {
		return "", errors.New("forwarding to this destination is not configured")
	}
	return filepath.Join(run.dir, sock), nil
}

func (c *Config) commandFor(name string, groups []string) *Command {
	for i := range c.Commands {
		cm := &c.Commands[i]
		if cm.Name == name && slices.ContainsFunc(cm.Groups, func(g string) bool { return slices.Contains(groups, g) }) {
			return cm
		}
	}
	return nil
}

type runningCommand struct {
	cmd     Command // as configured when it started
	grant   string  // the grant that keeps it up: its own, or an SSH target's (Via)
	by      Principal
	token   string
	since   time.Time
	dir     string
	needles [][]byte
}

// command serves GET /commands/<name>, POST /commands/<name>/start and
// POST /commands/<name>/stop.
func (s *Server) command(w http.ResponseWriter, r *http.Request) {
	// The name may be a path; the action, when there is one, comes last.
	name, action := strings.TrimPrefix(r.URL.Path, "/commands/"), "status"
	for _, a := range []string{"start", "stop"} {
		if rest, ok := strings.CutSuffix(name, "/"+a); ok {
			name, action = rest, a
		}
	}
	ev := Event{Time: time.Now().UTC(), Method: "command-" + action, Credential: grantName("command", name)}
	deny := func(code int, reason string) {
		ev.Decision, ev.Reason, ev.Status = "denied", reason, code
		s.audit.Record(ev)
		http.Error(w, "secrets-broker: "+reason, code)
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		deny(http.StatusUnauthorized, "missing token")
		return
	}
	p, err := s.auth.Authenticate(r.Context(), token)
	if err != nil {
		deny(http.StatusUnauthorized, "invalid token")
		return
	}
	ev.Principal, ev.Groups = p.ID, p.Groups
	cfg, _ := s.state()
	cm := cfg.commandFor(name, p.Groups)
	if cm == nil {
		deny(http.StatusForbidden, "no such command for this client")
		return
	}
	wantPost := action != "status"
	if (r.Method == http.MethodPost) != wantPost || (r.Method != http.MethodPost && r.Method != http.MethodGet) {
		deny(http.StatusMethodNotAllowed, "use GET for the status and POST for start and stop")
		return
	}

	s.cmdMu.Lock()
	defer s.cmdMu.Unlock()
	run := s.running[name]
	switch action {
	case "status":
		out := map[string]any{"running": run != nil}
		if run != nil {
			out["since"], out["by"] = run.since.UTC(), run.by.ID
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	case "stop":
		if run == nil {
			fmt.Fprintln(w, "not running")
			return
		}
		out := s.stopCommand(name, "stopped by "+p.ID)
		w.Write(out)
	case "start":
		if run != nil && run.by.ID != p.ID {
			deny(http.StatusConflict, "in use by another client")
			return
		}
		if run != nil {
			fmt.Fprintln(w, "already running")
			return
		}
		out, status, err := s.startCommand(cfg, cm, p, token, cm.grantName(), true)
		if err != nil {
			if status == http.StatusBadGateway {
				ev.Decision, ev.Reason, ev.Status = "denied", err.Error(), status
				s.audit.Record(ev)
				w.WriteHeader(status)
				w.Write(out)
				return
			}
			deny(status, err.Error())
			return
		}
		ev.Decision, ev.Status = "allowed", http.StatusOK
		s.audit.Record(ev)
		w.Write(out)
	default:
		deny(http.StatusNotFound, "unknown action")
	}
}

// startCommand writes the files of a command and runs Start, for client p.
// With authorize, the grant is checked first (and asked for when missing).
// It returns the output, and on failure the HTTP status to answer with. The
// caller holds cmdMu.
func (s *Server) startCommand(cfg *Config, cm *Command, p Principal, token, grant string, authorize bool) ([]byte, int, error) {
	files := make([][]byte, len(cm.Files))
	var needles [][]byte
	for i, f := range cm.Files {
		sec, err := s.store.Get(f.Secret)
		if err == nil && !slices.Contains(sec.Hosts, cm.grantName()) {
			err = errHostNotBound
		}
		if err != nil {
			return nil, statusFor(err), err
		}
		files[i] = sec.Value
		needles = append(needles, sec.Value)
		for _, line := range bytes.Split(sec.Value, []byte("\n")) {
			if line = bytes.TrimSpace(line); len(line) >= 12 {
				needles = append(needles, line)
			}
		}
	}
	if authorize && s.Approver != nil {
		if err := s.Approver.Authorize(p, cm.grantName(), []string{cm.grantName()}); err != nil {
			return nil, http.StatusForbidden, err
		}
	}
	// One directory per command, also when its name is a path.
	dir := filepath.Join(cfg.CommandsDir, strings.ReplaceAll(cm.Name, "/", "__"))
	os.RemoveAll(dir)
	err := os.MkdirAll(dir, 0o700)
	for i, f := range cm.Files {
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, f.Name), files[i], 0o600)
		}
	}
	if err != nil {
		os.RemoveAll(dir)
		return nil, http.StatusInternalServerError, errors.New("cannot prepare the files of the command")
	}
	out, err := runArgv(commandStartTimeout, cm, cm.Start, dir, needles)
	if err != nil {
		runArgv(commandStopTimeout, cm, cm.Stop, dir, needles)
		os.RemoveAll(dir)
		return out, http.StatusBadGateway, errors.New("start failed: " + err.Error())
	}
	s.runMu.Lock()
	if s.running == nil {
		s.running = map[string]*runningCommand{}
	}
	s.running[cm.Name] = &runningCommand{cmd: *cm, grant: grant, by: p, token: token, since: time.Now(), dir: dir, needles: needles}
	s.runMu.Unlock()
	return out, http.StatusOK, nil
}

// CommandVia returns the socket behind dest of a command, for an SSH target
// that reaches its host through the command. The command is started for the
// client when it is not running, and is then kept up by grant (the target's)
// instead of a grant of its own; one running for another client is not
// shared.
func (s *Server) CommandVia(p Principal, token, name, dest, grant string) (string, error) {
	cfg, _ := s.state()
	var cm *Command
	for i := range cfg.Commands {
		if cfg.Commands[i].Name == name {
			cm = &cfg.Commands[i]
		}
	}
	if cm == nil {
		return "", errors.New("no such command")
	}
	sock, ok := cm.Forwards[dest]
	if !ok {
		return "", errors.New("the command does not forward to this destination")
	}
	s.cmdMu.Lock()
	defer s.cmdMu.Unlock()
	s.runMu.Lock()
	run := s.running[name]
	s.runMu.Unlock()
	switch {
	case run != nil && run.by.ID != p.ID:
		return "", errors.New("in use by another client")
	case run == nil:
		ev := Event{Time: time.Now().UTC(), Method: "command-start", Credential: cm.grantName(), Principal: p.ID, Groups: p.Groups, Reason: "for " + grant}
		if _, _, err := s.startCommand(cfg, cm, p, token, grant, false); err != nil {
			ev.Decision, ev.Reason = "denied", ev.Reason+": "+err.Error()
			s.audit.Record(ev)
			return "", err
		}
		ev.Decision = "allowed"
		s.audit.Record(ev)
		s.runMu.Lock()
		run = s.running[name]
		s.runMu.Unlock()
	}
	return filepath.Join(run.dir, sock), nil
}

// stopCommand runs Stop and removes the files. The caller holds cmdMu.
func (s *Server) stopCommand(name, reason string) []byte {
	run := s.running[name]
	if run == nil {
		return nil
	}
	// Out of the table first: forwards stop being accepted at once.
	s.runMu.Lock()
	delete(s.running, name)
	s.runMu.Unlock()
	out, err := runArgv(commandStopTimeout, &run.cmd, run.cmd.Stop, run.dir, run.needles)
	os.RemoveAll(run.dir)
	if err != nil {
		reason += " (stop failed: " + err.Error() + ")"
	}
	s.audit.Record(Event{Time: time.Now().UTC(), Decision: "allowed", Reason: reason, Method: "command-stop",
		Principal: run.by.ID, Groups: run.by.Groups, Credential: run.cmd.grantName()})
	return out
}

// WatchCommands stops running commands whose client lost its token or grant,
// or whose secrets were sealed, and stops them all when ctx ends.
func (s *Server) WatchCommands(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			s.cmdMu.Lock()
			for name := range s.running {
				s.stopCommand(name, "the broker is stopping")
			}
			s.cmdMu.Unlock()
			return
		case <-tick.C:
		}
		s.cmdMu.Lock()
		for name, run := range s.running {
			reason := ""
			actx, cancel := context.WithTimeout(ctx, 10*time.Second)
			pr, err := s.auth.Authenticate(actx, run.token)
			cancel()
			switch {
			case err != nil || pr.ID != run.by.ID:
				reason = "token is no longer valid"
			case s.Approver != nil && !s.Approver.Granted(run.by.ID, run.grant):
				reason = "grant ended"
			case s.Sealed():
				reason = ErrSealed.Error()
			}
			if reason != "" {
				s.stopCommand(name, reason)
			}
		}
		s.cmdMu.Unlock()
	}
}

// runArgv runs one configured program and returns its output with the
// secrets blanked out.
func runArgv(timeout time.Duration, cm *Command, argv []string, dir string, needles [][]byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	fill := func(s string) string { return strings.ReplaceAll(s, "{dir}", dir) }
	args := make([]string, len(argv))
	for i, a := range argv {
		args[i] = fill(a)
	}
	c := exec.CommandContext(ctx, args[0], args[1:]...)
	c.Dir = cm.Dir
	c.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + os.Getenv("HOME")}
	for k, v := range cm.Env {
		c.Env = append(c.Env, k+"="+fill(v))
	}
	out, err := c.CombinedOutput()
	if len(out) > commandMaxOutput {
		out = out[len(out)-commandMaxOutput:]
	}
	for _, n := range needles {
		out = bytes.ReplaceAll(out, n, []byte("[redacted]"))
	}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return out, errors.New("the program could not run")
		}
		return out, fmt.Errorf("exit status %d", exit.ExitCode())
	}
	return out, nil
}
