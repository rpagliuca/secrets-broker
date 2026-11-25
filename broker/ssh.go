package broker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH configures the SSH proxy. A client opens an SSH connection to the
// broker with the name of a target as the user and its token as the
// password. The broker connects to the target with a private key from the
// store and relays the session, so the client never holds the key.
type SSH struct {
	// Listen is the address of the proxy, with an explicit host.
	Listen string `json:"listen"`
	// KnownHostsFile is where the host key of the proxy is written at
	// start-up, in known_hosts format. The key is new at every start.
	KnownHostsFile string `json:"known_hosts_file,omitempty"`

	Targets []SSHTarget `json:"targets"`
}

// SSHTarget is one account on one machine.
type SSHTarget struct {
	// Name is what the client gives as the SSH user.
	Name string `json:"name"`
	// Secret is the name, in the Store, of the private key (OpenSSH format,
	// no passphrase). Defaults to Name. The secret must be bound to the host
	// part of Address.
	Secret string `json:"secret,omitempty"`
	// Address is host:port of the target.
	Address string `json:"address"`
	// User is the account on the target.
	User string `json:"user"`
	// HostKeys are the public host keys accepted from the target, as in
	// authorized_keys ("ssh-ed25519 AAAA..."). There is no trust on first
	// use: at least one is required.
	HostKeys []string `json:"host_keys"`
	// Groups are the client groups allowed to use the target.
	Groups []string `json:"groups"`
	// Jump names another target to connect through.
	Jump string `json:"jump,omitempty"`
	// Forward lists the host:port destinations the client may reach with
	// local port forwarding (ssh -L). Empty means no forwarding.
	Forward []string `json:"forward,omitempty"`
}

func (t *SSHTarget) secretName() string {
	if t.Secret != "" {
		return t.Secret
	}
	return t.Name
}

// grantName is the name of the target in grants and in the audit log. The
// prefix keeps it apart from HTTP credentials.
func (t *SSHTarget) grantName() string { return "ssh:" + t.Name }

func (c *SSH) target(name string) *SSHTarget {
	for i := range c.Targets {
		if c.Targets[i].Name == name {
			return &c.Targets[i]
		}
	}
	return nil
}

// chain returns the targets to connect through, ending with t.
func (c *SSH) chain(t *SSHTarget) ([]*SSHTarget, error) {
	out := []*SSHTarget{t}
	for t.Jump != "" {
		t = c.target(t.Jump)
		if t == nil || slices.Contains(out, t) {
			return nil, fmt.Errorf("ssh target %q: jump must name another target, without a loop", out[0].Name)
		}
		out = append(out, t)
	}
	slices.Reverse(out)
	return out, nil
}

func (c *SSH) validate() error {
	if host, _, err := net.SplitHostPort(c.Listen); err != nil || host == "" {
		return fmt.Errorf("ssh listen %q: must be host:port with an explicit host", c.Listen)
	}
	if len(c.Targets) == 0 {
		return errors.New("ssh: no targets configured")
	}
	names := map[string]bool{}
	for i := range c.Targets {
		t := &c.Targets[i]
		if !nameRE.MatchString(t.Name) || names[t.Name] {
			return fmt.Errorf("ssh target %d: invalid or duplicate name %q", i, t.Name)
		}
		names[t.Name] = true
		if t.Secret != "" && !nameRE.MatchString(t.Secret) {
			return fmt.Errorf("ssh target %q: invalid secret name %q", t.Name, t.Secret)
		}
		if host, port, err := net.SplitHostPort(t.Address); err != nil || host == "" || port == "" {
			return fmt.Errorf("ssh target %q: address must be host:port", t.Name)
		}
		if t.User == "" || len(t.Groups) == 0 || slices.Contains(t.Groups, "") {
			return fmt.Errorf("ssh target %q: needs a user and at least one group", t.Name)
		}
		if _, err := parseHostKeys(t.HostKeys); err != nil {
			return fmt.Errorf("ssh target %q: %w", t.Name, err)
		}
		for _, f := range t.Forward {
			if host, port, err := net.SplitHostPort(f); err != nil || host == "" || port == "" {
				return fmt.Errorf("ssh target %q: forward %q must be host:port", t.Name, f)
			}
		}
	}
	for i := range c.Targets {
		if _, err := c.chain(&c.Targets[i]); err != nil {
			return err
		}
	}
	return nil
}

func parseHostKeys(lines []string) ([]ssh.PublicKey, error) {
	if len(lines) == 0 {
		return nil, errors.New("at least one host key is required")
	}
	var out []ssh.PublicKey
	for _, line := range lines {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("host key %q: %w", line, err)
		}
		out = append(out, key)
	}
	return out, nil
}

// SSHProxy is the SSH side of the broker.
type SSHProxy struct {
	cfg    atomic.Pointer[SSH]
	store  Store
	auth   Authenticator
	audit  Auditor
	signer ssh.Signer

	// Approver, when set, must authorise each client for each target.
	Approver Approver
	// Commands, when set, lets clients reach what a running command
	// exposes: the SSH user is the command name and only "ssh -L" works.
	Commands CommandForwarder
	// Dial opens the TCP connection to the first target of a chain.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Recheck is how often an open connection is checked again: token,
	// grant and store. Default 5s.
	Recheck time.Duration

	slots chan struct{}
}

const (
	sshVersion      = "SSH-2.0-secrets-broker"
	sshHandshake    = 20 * time.Second
	sshMaxConns     = 64
	sshMaxCommand   = 512
	sshConnect      = "ssh-connect" // Method of connection events in the audit log
	sshDeniedToUser = "permission denied"
)

// CommandForwarder is the part of Server the SSH proxy needs for commands.
type CommandForwarder interface {
	CommandKnown(name string, groups []string) bool
	CommandActive(p Principal, name string) bool
	CommandForward(p Principal, name, dest string) (string, error)
}

// NewSSHProxy creates the proxy with a new host key.
func NewSSHProxy(cfg *SSH, store Store, auth Authenticator, audit Auditor) (*SSHProxy, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if audit == nil {
		audit = discard{}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	p := &SSHProxy{
		store: store, auth: auth, audit: audit, signer: signer,
		Dial:    (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		Recheck: 5 * time.Second,
		slots:   make(chan struct{}, sshMaxConns),
	}
	p.cfg.Store(cfg)
	return p, nil
}

// SetConfig replaces the targets while the proxy runs. Connections already
// open keep the target they were opened with, until their grant ends.
func (p *SSHProxy) SetConfig(cfg *SSH) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	p.cfg.Store(cfg)
	return nil
}

// HostKey returns the public host key of the proxy.
func (p *SSHProxy) HostKey() ssh.PublicKey { return p.signer.PublicKey() }

// KnownHosts returns the host key as a known_hosts line for addr.
func (p *SSHProxy) KnownHosts(addr string) []byte {
	host, port, _ := net.SplitHostPort(addr)
	if port != "22" {
		host = "[" + host + "]:" + port
	}
	return append([]byte(host+" "), ssh.MarshalAuthorizedKey(p.HostKey())...)
}

// Serve accepts connections until l is closed.
func (p *SSHProxy) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		select {
		case p.slots <- struct{}{}:
			go func() {
				defer func() { <-p.slots }()
				p.handle(c)
			}()
		default:
			c.Close()
		}
	}
}

func (p *SSHProxy) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(sshHandshake))

	var (
		who     Principal
		token   string
		target  *SSHTarget
		command string // set instead of target for the forwards of a command
	)
	sc := &ssh.ServerConfig{
		MaxAuthTries:  2,
		ServerVersion: sshVersion,
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			pr, err := p.auth.Authenticate(ctx, string(password))
			if err != nil {
				p.audit.Record(Event{Time: time.Now().UTC(), Decision: "denied", Reason: "invalid token", Method: sshConnect})
				return nil, errors.New(sshDeniedToUser)
			}
			t := p.cfg.Load().target(meta.User())
			if t == nil && p.Commands != nil && p.Commands.CommandKnown(meta.User(), pr.Groups) {
				who, token, command = pr, string(password), meta.User()
				return nil, nil
			}
			if t == nil || !slices.ContainsFunc(t.Groups, func(g string) bool { return slices.Contains(pr.Groups, g) }) {
				// The same answer for a target that does not exist and for
				// one of another group: names are not confirmed to clients.
				p.audit.Record(Event{Time: time.Now().UTC(), Decision: "denied", Reason: "no such target for this client",
					Principal: pr.ID, Groups: pr.Groups, Method: sshConnect})
				return nil, errors.New(sshDeniedToUser)
			}
			who, token, target = pr, string(password), t
			return nil, nil
		},
	}
	sc.AddHostKey(p.signer)
	conn, chans, reqs, err := ssh.NewServerConn(c, sc)
	if err != nil {
		return
	}
	defer conn.Close()
	c.SetDeadline(time.Time{})
	// Global requests from the client (remote forwarding, keep-alives) are
	// all answered with a failure.
	go ssh.DiscardRequests(reqs)
	if command != "" {
		p.serveCommand(conn, chans, who, token, command)
		return
	}

	ev := Event{Principal: who.ID, Groups: who.Groups, Credential: target.grantName(), Host: target.Address}
	up, err := p.open(who, target)
	if err != nil {
		reason, detail := sshReason(err)
		p.record(ev, "denied", detail, sshConnect, "")
		// The reason reaches the client as the refusal of its first channel.
		select {
		case nc, ok := <-chans:
			if ok {
				nc.Reject(ssh.Prohibited, reason)
			}
		case <-time.After(sshHandshake):
		}
		return
	}
	defer up.Close()
	p.record(ev, "allowed", "", sshConnect, "")

	done := make(chan struct{})
	defer close(done)
	go p.watch(done, conn, up, who, token, target, ev)
	go func() { up.Wait(); conn.Close() }()

	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			go p.session(nc, up, ev)
		case "direct-tcpip":
			go p.forward(nc, up, target, ev)
		default:
			nc.Reject(ssh.UnknownChannelType, "channel type not supported")
		}
	}
}

// serveCommand relays "ssh -L" channels to the Unix sockets of a command
// that is running for this client. There is no shell and no target.
func (p *SSHProxy) serveCommand(conn ssh.Conn, chans <-chan ssh.NewChannel, who Principal, token, name string) {
	ev := Event{Principal: who.ID, Groups: who.Groups, Credential: "command:" + name}
	done := make(chan struct{})
	defer close(done)
	go func() {
		tick := time.NewTicker(p.Recheck)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			pr, err := p.auth.Authenticate(ctx, token)
			cancel()
			if err != nil || pr.ID != who.ID || !p.Commands.CommandActive(who, name) {
				p.record(ev, "denied", "connection closed: the command, the grant or the token ended", sshConnect, "")
				conn.Close()
				return
			}
		}
	}()
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.Prohibited, "a command only offers port forwarding")
			continue
		}
		go func(nc ssh.NewChannel) {
			var m struct {
				Host     string
				Port     uint32
				OrigHost string
				OrigPort uint32
			}
			ssh.Unmarshal(nc.ExtraData(), &m)
			dest := net.JoinHostPort(m.Host, strconv.Itoa(int(m.Port)))
			sock, err := p.Commands.CommandForward(who, name, dest)
			if err != nil {
				p.record(ev, "denied", err.Error(), "ssh-forward", dest)
				nc.Reject(ssh.Prohibited, err.Error())
				return
			}
			uc, err := net.DialTimeout("unix", sock, 5*time.Second)
			if err != nil {
				p.record(ev, "denied", "the command is not listening for this destination", "ssh-forward", dest)
				nc.Reject(ssh.ConnectionFailed, "the command is not listening for this destination yet")
				return
			}
			defer uc.Close()
			dc, dreqs, err := nc.Accept()
			if err != nil {
				return
			}
			defer dc.Close()
			p.record(ev, "allowed", "", "ssh-forward", dest)
			go ssh.DiscardRequests(dreqs)
			go func() { io.Copy(uc, dc); uc.Close() }()
			io.Copy(dc, uc)
		}(nc)
	}
}

// sshReason splits an error of open into what the client reads and what the
// audit log keeps. Network and key errors stay in the log.
func sshReason(err error) (client, detail string) {
	var ae *ApprovalError
	switch {
	case errors.As(err, &ae), errors.Is(err, ErrSealed):
		return err.Error(), err.Error()
	}
	return "the broker cannot open this target", err.Error()
}

// upstream is the connection to a target and the jump connections under it.
type upstream struct {
	ssh.Conn
	jumps []*ssh.Client
}

func (u *upstream) Close() error {
	err := u.Conn.Close()
	for i := len(u.jumps) - 1; i >= 0; i-- {
		u.jumps[i].Close()
	}
	return err
}

// open checks the secrets, then the grant, then connects. The order keeps a
// sealed or misconfigured broker from asking a person for approval.
func (p *SSHProxy) open(who Principal, t *SSHTarget) (*upstream, error) {
	hops, err := p.cfg.Load().chain(t)
	if err != nil {
		return nil, err
	}
	configs := make([]*ssh.ClientConfig, len(hops))
	for i, hop := range hops {
		if configs[i], err = p.clientConfig(hop); err != nil {
			return nil, fmt.Errorf("target %s: %w", hop.Name, err)
		}
	}
	if p.Approver != nil {
		if err := p.Approver.Authorize(who, t.grantName(), []string{t.Address}); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), sshHandshake)
	defer cancel()
	up := &upstream{}
	for i, hop := range hops {
		var raw net.Conn
		if i == 0 {
			raw, err = p.Dial(ctx, "tcp", hop.Address)
		} else {
			raw, err = up.jumps[i-1].Dial("tcp", hop.Address)
		}
		if err != nil {
			up.closeJumps()
			return nil, fmt.Errorf("target %s: %w", hop.Name, err)
		}
		raw.SetDeadline(time.Now().Add(sshHandshake)) // not supported through a jump; harmless
		cc, chans, reqs, err := ssh.NewClientConn(raw, hop.Address, configs[i])
		if err != nil {
			raw.Close()
			up.closeJumps()
			return nil, fmt.Errorf("target %s: %w", hop.Name, err)
		}
		raw.SetDeadline(time.Time{})
		if i < len(hops)-1 {
			up.jumps = append(up.jumps, ssh.NewClient(cc, chans, reqs))
			continue
		}
		up.Conn = cc
		// Nothing the target opens towards the client is relayed: no agent,
		// X11 or remote forwarding.
		go func() {
			for nc := range chans {
				nc.Reject(ssh.Prohibited, "not relayed")
			}
		}()
		go ssh.DiscardRequests(reqs)
	}
	return up, nil
}

func (u *upstream) closeJumps() {
	for i := len(u.jumps) - 1; i >= 0; i-- {
		u.jumps[i].Close()
	}
}

func (p *SSHProxy) clientConfig(t *SSHTarget) (*ssh.ClientConfig, error) {
	sec, err := p.store.Get(t.secretName())
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(t.Address)
	if !slices.Contains(sec.Hosts, host) {
		return nil, errHostNotBound
	}
	signer, err := ssh.ParsePrivateKey(sec.Value)
	if err != nil {
		// The parser's error is dropped: it must never quote the key.
		return nil, errors.New("the secret is not an SSH private key without passphrase")
	}
	keys, err := parseHostKeys(t.HostKeys)
	if err != nil {
		return nil, err
	}
	var algos []string
	for _, k := range keys {
		if k.Type() == ssh.KeyAlgoRSA {
			algos = append(algos, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
		} else {
			algos = append(algos, k.Type())
		}
	}
	return &ssh.ClientConfig{
		User:          t.User,
		Auth:          []ssh.AuthMethod{ssh.PublicKeys(signer)},
		ClientVersion: sshVersion,
		// Only the configured key types are negotiated, and the key itself
		// is compared before the private key signs anything.
		HostKeyAlgorithms: algos,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			for _, k := range keys {
				if bytes.Equal(k.Marshal(), key.Marshal()) {
					return nil
				}
			}
			return errors.New("host key is not one of the configured keys")
		},
	}, nil
}

// watch ends an open connection when the token, the grant or the store stop
// being valid. Without it a session would outlive its grant.
func (p *SSHProxy) watch(done <-chan struct{}, conn ssh.Conn, up *upstream, who Principal, token string, t *SSHTarget, ev Event) {
	tick := time.NewTicker(p.Recheck)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
		}
		reason := ""
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		pr, err := p.auth.Authenticate(ctx, token)
		cancel()
		switch {
		case err != nil || pr.ID != who.ID:
			reason = "token is no longer valid"
		case p.Approver != nil && !p.Approver.Granted(who.ID, t.grantName()):
			reason = "grant ended"
		default:
			if _, err := p.store.Get(t.secretName()); err != nil {
				reason = err.Error()
			}
		}
		if reason != "" {
			p.record(ev, "denied", "connection closed: "+reason, sshConnect, "")
			conn.Close()
			up.Close()
			return
		}
	}
}

// sessionRequests are the session requests relayed to the target. Agent and
// X11 forwarding are not in the list.
var sessionRequests = []string{"exec", "shell", "subsystem", "pty-req", "env", "window-change", "signal", "break", "eow@openssh.com"}

func (p *SSHProxy) session(nc ssh.NewChannel, up *upstream, ev Event) {
	uc, ureqs, err := up.OpenChannel("session", nil)
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, "the target refused the session")
		return
	}
	dc, dreqs, err := nc.Accept()
	if err != nil {
		uc.Close()
		return
	}
	var out sync.WaitGroup
	out.Add(2)
	go func() { io.Copy(dc, uc); out.Done() }()
	go func() { io.Copy(dc.Stderr(), uc.Stderr()); out.Done() }()
	go func() { io.Copy(uc, dc); uc.CloseWrite() }()
	// reqMu is held while one client request is relayed and answered. The
	// channel is only closed with it: a fast command would otherwise end the
	// channel before the client got the answer to its "exec".
	var reqMu sync.Mutex
	go func() {
		for r := range dreqs {
			if !slices.Contains(sessionRequests, r.Type) {
				if r.WantReply {
					r.Reply(false, nil)
				}
				continue
			}
			reqMu.Lock()
			switch r.Type {
			case "exec":
				var m struct{ Command string }
				ssh.Unmarshal(r.Payload, &m)
				p.record(ev, "allowed", "", "ssh-exec", m.Command)
			case "subsystem":
				var m struct{ Name string }
				ssh.Unmarshal(r.Payload, &m)
				p.record(ev, "allowed", "", "ssh-subsystem", m.Name)
			case "shell":
				p.record(ev, "allowed", "", "ssh-shell", "")
			}
			ok, err := uc.SendRequest(r.Type, r.WantReply, r.Payload)
			if r.WantReply {
				r.Reply(ok && err == nil, nil)
			}
			reqMu.Unlock()
		}
		uc.Close()
	}()
	// Exit status and signals come back as requests from the target.
	for r := range ureqs {
		ok, err := dc.SendRequest(r.Type, r.WantReply, r.Payload)
		if r.WantReply {
			r.Reply(ok && err == nil, nil)
		}
	}
	out.Wait()
	reqMu.Lock()
	dc.CloseWrite()
	dc.Close()
	reqMu.Unlock()
}

func (p *SSHProxy) forward(nc ssh.NewChannel, up *upstream, t *SSHTarget, ev Event) {
	var m struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	ssh.Unmarshal(nc.ExtraData(), &m)
	dest := net.JoinHostPort(m.Host, strconv.Itoa(int(m.Port)))
	if !slices.Contains(t.Forward, dest) {
		p.record(ev, "denied", "forwarding to this destination is not configured", "ssh-forward", dest)
		nc.Reject(ssh.Prohibited, "forwarding to this destination is not allowed")
		return
	}
	uc, ureqs, err := up.OpenChannel("direct-tcpip", nc.ExtraData())
	if err != nil {
		p.record(ev, "denied", "the target refused the forwarding", "ssh-forward", dest)
		nc.Reject(ssh.ConnectionFailed, "the target refused the forwarding")
		return
	}
	dc, dreqs, err := nc.Accept()
	if err != nil {
		uc.Close()
		return
	}
	p.record(ev, "allowed", "", "ssh-forward", dest)
	go ssh.DiscardRequests(ureqs)
	go ssh.DiscardRequests(dreqs)
	go func() { io.Copy(uc, dc); uc.CloseWrite() }()
	io.Copy(dc, uc)
	dc.Close()
	uc.Close()
}

func (p *SSHProxy) record(ev Event, decision, reason, method, path string) {
	if len(path) > sshMaxCommand {
		path = path[:sshMaxCommand]
	}
	ev.Time, ev.Decision, ev.Reason, ev.Method, ev.Path = time.Now().UTC(), decision, reason, method, path
	p.audit.Record(ev)
}
