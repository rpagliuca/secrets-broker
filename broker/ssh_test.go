package broker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newSSHKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(block)
}

// fakeTarget is an SSH server that accepts one public key for the user
// "deploy". "exec" answers "ran: <command>" with exit status 3, except for
// "sleep", which stays open. direct-tcpip is dialled for real.
type fakeTarget struct {
	addr    string
	hostKey ssh.PublicKey

	mu   sync.Mutex
	seen []string
}

func (f *fakeTarget) note(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, s)
}

func (f *fakeTarget) saw(s string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.seen, s)
}

func newFakeTarget(t *testing.T, authorized ssh.PublicKey) *fakeTarget {
	t.Helper()
	host, _ := newSSHKey(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTarget{addr: l.Addr().String(), hostKey: host.PublicKey()}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if meta.User() != "deploy" || !bytes.Equal(key.Marshal(), authorized.Marshal()) {
				f.note("rejected:" + meta.User())
				return nil, errors.New("no")
			}
			f.note("auth:" + meta.User())
			return nil, nil
		},
	}
	cfg.AddHostKey(host)
	var conns []net.Conn
	var mu sync.Mutex
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go f.serve(c, cfg)
		}
	}()
	return f
}

func (f *fakeTarget) serve(c net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, reqs, _ := nc.Accept()
			go func() {
				for r := range reqs {
					f.note("req:" + r.Type)
					if r.WantReply {
						r.Reply(true, nil)
					}
					if r.Type != "exec" {
						continue
					}
					var m struct{ Command string }
					ssh.Unmarshal(r.Payload, &m)
					if m.Command == "sleep" {
						io.WriteString(ch, "started\n")
						continue
					}
					io.WriteString(ch, "ran: "+m.Command)
					io.WriteString(ch.Stderr(), "warn")
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{3}))
					ch.Close()
				}
			}()
		case "direct-tcpip":
			var m struct {
				Host     string
				Port     uint32
				OrigHost string
				OrigPort uint32
			}
			ssh.Unmarshal(nc.ExtraData(), &m)
			out, err := net.Dial("tcp", net.JoinHostPort(m.Host, strconv.Itoa(int(m.Port))))
			if err != nil {
				nc.Reject(ssh.ConnectionFailed, "unreachable")
				continue
			}
			ch, reqs, _ := nc.Accept()
			go ssh.DiscardRequests(reqs)
			go func() { io.Copy(out, ch); out.Close() }()
			go func() { io.Copy(ch, out); ch.Close() }()
		default:
			nc.Reject(ssh.UnknownChannelType, "no")
		}
	}
}

type sshHarness struct {
	t      *testing.T
	proxy  *SSHProxy
	addr   string
	cfg    *SSH
	store  *memStore
	audit  *recorder
	target *fakeTarget
}

func newSSHHarness(t *testing.T, mutate func(cfg *SSH, store *memStore)) *sshHarness {
	t.Helper()
	signer, key := newSSHKey(t)
	ft := newFakeTarget(t, signer.PublicKey())
	cfg := &SSH{Listen: "127.0.0.1:0", Targets: []SSHTarget{{
		Name: "web", Address: ft.addr, User: "deploy", Groups: []string{"team-a"},
		HostKeys: []string{string(ssh.MarshalAuthorizedKey(ft.hostKey))},
	}}}
	store := &memStore{m: map[string]Secret{"web": {Value: key, Hosts: []string{"127.0.0.1"}}}}
	if mutate != nil {
		mutate(cfg, store)
	}
	audit := &recorder{}
	auth := tokenAuth{
		"token-a": {ID: "agent-a", Groups: []string{"team-a"}},
		"token-b": {ID: "agent-b", Groups: []string{"team-b"}},
	}
	p, err := NewSSHProxy(cfg, store, auth, audit)
	if err != nil {
		t.Fatal(err)
	}
	p.Recheck = 20 * time.Millisecond
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go p.Serve(l)
	return &sshHarness{t: t, proxy: p, addr: l.Addr().String(), cfg: cfg, store: store, audit: audit, target: ft}
}

func (h *sshHarness) dial(user, token string) (*ssh.Client, error) {
	c, err := ssh.Dial("tcp", h.addr, &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.Password(token)},
		HostKeyCallback: ssh.FixedHostKey(h.proxy.HostKey()), Timeout: 5 * time.Second,
	})
	if err == nil {
		h.t.Cleanup(func() { c.Close() })
	}
	return c, err
}

func (h *sshHarness) mustDial(user, token string) *ssh.Client {
	h.t.Helper()
	c, err := h.dial(user, token)
	if err != nil {
		h.t.Fatalf("dial %s: %v", user, err)
	}
	return c
}

func (r *recorder) hasSSH(decision, method, part string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ev := range r.events {
		if ev.Decision == decision && ev.Method == method && strings.Contains(ev.Reason+"\x00"+ev.Path, part) {
			return true
		}
	}
	return false
}

// run executes a command and returns its output and exit status.
func run(t *testing.T, c *ssh.Client, command string) (string, string, int) {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	out, err := sess.Output(command)
	var exit *ssh.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("%s: err = %v, want an exit status", command, err)
	}
	return string(out), stderr.String(), exit.ExitStatus()
}

// hold starts a command that does not end and returns once it is running.
func hold(t *testing.T, c *ssh.Client) {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	out, _ := sess.StdoutPipe()
	if err := sess.Start("sleep"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if n, _ := out.Read(buf); string(buf[:n]) != "started\n" {
		t.Fatalf("held session printed %q", buf[:n])
	}
}

func waitClosed(t *testing.T, c *ssh.Client) {
	t.Helper()
	done := make(chan struct{})
	go func() { c.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the connection stayed open")
	}
}

func TestSSHExecGoesThroughWithTheBrokerKey(t *testing.T) {
	h := newSSHHarness(t, nil)
	c := h.mustDial("web", "token-a")
	out, stderr, status := run(t, c, "uptime")
	if out != "ran: uptime" || stderr != "warn" || status != 3 {
		t.Fatalf("out=%q stderr=%q status=%d", out, stderr, status)
	}
	if !h.target.saw("auth:deploy") {
		t.Fatalf("the target did not see the broker key: %v", h.target.seen)
	}
	if !h.audit.hasSSH("allowed", "ssh-connect", "") || !h.audit.hasSSH("allowed", "ssh-exec", "uptime") {
		t.Fatalf("audit = %+v", h.audit.events)
	}
}

func TestSSHClientsThatCannotAuthenticate(t *testing.T) {
	h := newSSHHarness(t, nil)
	for _, tc := range []struct{ name, user, token string }{
		{"wrong token", "web", "nope"},
		{"empty token", "web", ""},
		{"target of another group", "web", "token-b"},
		{"unknown target", "db", "token-a"},
	} {
		if _, err := h.dial(tc.user, tc.token); err == nil {
			t.Errorf("%s: connected", tc.name)
		}
	}
	if len(h.target.seen) != 0 {
		t.Fatalf("the target was contacted: %v", h.target.seen)
	}
}

func TestSSHTargetIsNotOpened(t *testing.T) {
	other, _ := newSSHKey(t)
	for _, tc := range []struct {
		name       string
		mutate     func(cfg *SSH, store *memStore)
		toClient   string
		inAuditLog string
	}{
		{"host key is not the configured one", func(cfg *SSH, _ *memStore) {
			cfg.Targets[0].HostKeys = []string{string(ssh.MarshalAuthorizedKey(other.PublicKey()))}
		}, "cannot open this target", "ssh: handshake failed"},
		{"secret bound to another host", func(_ *SSH, s *memStore) {
			s.m["web"] = Secret{Value: s.m["web"].Value, Hosts: []string{"other.example.com"}}
		}, "cannot open this target", "not bound to this host"},
		{"secret is not a key", func(_ *SSH, s *memStore) {
			s.m["web"] = Secret{Value: []byte("definitely not a private key"), Hosts: []string{"127.0.0.1"}}
		}, "cannot open this target", "not an SSH private key"},
		{"store is sealed", func(_ *SSH, s *memStore) { s.sealed = true }, "sealed", "sealed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSSHHarness(t, tc.mutate)
			c := h.mustDial("web", "token-a")
			_, err := c.NewSession()
			if err == nil || !strings.Contains(err.Error(), tc.toClient) {
				t.Fatalf("err = %v, want %q", err, tc.toClient)
			}
			if strings.Contains(err.Error(), "definitely") {
				t.Fatalf("the error quotes the secret: %v", err)
			}
			if !h.audit.hasSSH("denied", "ssh-connect", tc.inAuditLog) {
				t.Fatalf("audit = %+v", h.audit.events)
			}
			// The private key signs nothing for a host that was not verified.
			if len(h.target.seen) != 0 {
				t.Fatalf("the target saw an authentication: %v", h.target.seen)
			}
		})
	}
}

func TestSSHNothingIsForwardedUnlessConfigured(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	h := newSSHHarness(t, nil)
	c := h.mustDial("web", "token-a")
	if _, err := c.Dial("tcp", echo.Addr().String()); err == nil {
		t.Fatal("local forwarding worked without being configured")
	}
	if !h.audit.hasSSH("denied", "ssh-forward", echo.Addr().String()) {
		t.Fatalf("audit = %+v", h.audit.events)
	}
	if _, err := c.Listen("tcp", "127.0.0.1:0"); err == nil {
		t.Fatal("remote forwarding was accepted")
	}
	if _, _, err := c.OpenChannel("x11", nil); err == nil {
		t.Fatal("an x11 channel was accepted")
	}
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := sess.SendRequest("auth-agent-req@openssh.com", true, nil); ok {
		t.Fatal("agent forwarding was accepted")
	}
	sess.Close()
	if h.target.saw("req:auth-agent-req@openssh.com") {
		t.Fatal("agent forwarding reached the target")
	}

	h = newSSHHarness(t, func(cfg *SSH, _ *memStore) { cfg.Targets[0].Forward = []string{echo.Addr().String()} })
	c = h.mustDial("web", "token-a")
	conn, err := c.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("configured forwarding: %v", err)
	}
	io.WriteString(conn, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

func TestSSHNeedsAGrantAndEndsWithIt(t *testing.T) {
	h := newSSHHarness(t, nil)
	g := NewGrants(Approval{Durations: []Duration{Duration(time.Hour)}}, nil, h.audit)
	h.proxy.Approver = g

	c := h.mustDial("web", "token-a")
	if _, err := c.NewSession(); err == nil || !strings.Contains(err.Error(), "waiting for approval") {
		t.Fatalf("err = %v, want a waiting request", err)
	}
	if len(h.target.seen) != 0 {
		t.Fatalf("the target was contacted before the grant: %v", h.target.seen)
	}
	pending := g.Pending()
	if len(pending) != 1 || pending[0].Credential != "ssh:web" || pending[0].Principal.ID != "agent-a" {
		t.Fatalf("pending = %+v", pending)
	}
	if err := g.Decide(pending[0].ID, time.Hour, "test"); err != nil {
		t.Fatal(err)
	}

	c = h.mustDial("web", "token-a")
	if out, _, _ := run(t, c, "uptime"); out != "ran: uptime" {
		t.Fatalf("out = %q", out)
	}
	hold(t, c)
	g.Revoke("agent-a", "test")
	waitClosed(t, c)
	if !h.audit.hasSSH("denied", "ssh-connect", "grant ended") {
		t.Fatalf("audit = %+v", h.audit.events)
	}
}

func TestSSHSealClosesOpenConnections(t *testing.T) {
	h := newSSHHarness(t, nil)
	c := h.mustDial("web", "token-a")
	hold(t, c)
	h.store.mu.Lock()
	h.store.sealed = true
	h.store.mu.Unlock()
	waitClosed(t, c)
}

func TestSSHJumpTarget(t *testing.T) {
	signer, key := newSSHKey(t)
	inner := newFakeTarget(t, signer.PublicKey())
	h := newSSHHarness(t, func(cfg *SSH, store *memStore) {
		cfg.Targets = append(cfg.Targets, SSHTarget{
			Name: "inner", Address: inner.addr, User: "deploy", Groups: []string{"team-a"}, Jump: "web",
			HostKeys: []string{string(ssh.MarshalAuthorizedKey(inner.hostKey))},
		})
		store.m["inner"] = Secret{Value: key, Hosts: []string{"127.0.0.1"}}
	})
	direct := h.proxy.Dial
	h.proxy.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != h.target.addr {
			return nil, errors.New("the inner target was dialled directly")
		}
		return direct(ctx, network, addr)
	}
	c := h.mustDial("inner", "token-a")
	if out, _, _ := run(t, c, "id"); out != "ran: id" {
		t.Fatalf("out = %q", out)
	}
	if !inner.saw("auth:deploy") || !h.target.saw("auth:deploy") {
		t.Fatalf("jump = %v, inner = %v", h.target.seen, inner.seen)
	}
}

func TestSSHConfigIsValidated(t *testing.T) {
	key, _ := newSSHKey(t)
	line := string(ssh.MarshalAuthorizedKey(key.PublicKey()))
	ok := SSHTarget{Name: "web", Address: "web.example.com:22", User: "deploy", Groups: []string{"team-a"}, HostKeys: []string{line}}
	with := func(f func(*SSHTarget)) SSHTarget { t := ok; f(&t); return t }
	for name, cfg := range map[string]SSH{
		"listen on every interface": {Listen: ":8472", Targets: []SSHTarget{ok}},
		"no targets":                {Listen: "127.0.0.1:8472"},
		"no host key":               {Listen: "127.0.0.1:8472", Targets: []SSHTarget{with(func(t *SSHTarget) { t.HostKeys = nil })}},
		"address without port":      {Listen: "127.0.0.1:8472", Targets: []SSHTarget{with(func(t *SSHTarget) { t.Address = "web.example.com" })}},
		"no group":                  {Listen: "127.0.0.1:8472", Targets: []SSHTarget{with(func(t *SSHTarget) { t.Groups = nil })}},
		"jump to itself":            {Listen: "127.0.0.1:8472", Targets: []SSHTarget{with(func(t *SSHTarget) { t.Jump = "web" })}},
		"jump to nowhere":           {Listen: "127.0.0.1:8472", Targets: []SSHTarget{with(func(t *SSHTarget) { t.Jump = "gone" })}},
	} {
		if err := cfg.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := SSH{Listen: "127.0.0.1:8472", Targets: []SSHTarget{ok}}
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
}

// TestSSHWithTheOpenSSHClient runs the documented client side: the stock
// ssh command, with the token handed over by an askpass program.
func TestSSHWithTheOpenSSHClient(t *testing.T) {
	bin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh command")
	}
	h := newSSHHarness(t, nil)
	dir := t.TempDir()
	known, askpass := filepath.Join(dir, "known_hosts"), filepath.Join(dir, "askpass")
	os.WriteFile(known, h.proxy.KnownHosts(h.addr), 0o600)
	os.WriteFile(askpass, []byte("#!/bin/sh\nprintf '%s\\n' \"$BROKER_TOKEN\"\n"), 0o700)
	_, port, _ := net.SplitHostPort(h.addr)
	cmd := exec.Command(bin, "-F", "/dev/null", "-p", port,
		"-o", "UserKnownHostsFile="+known, "-o", "StrictHostKeyChecking=yes",
		"-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
		"-o", "NumberOfPasswordPrompts=1", "-o", "IdentityAgent=none",
		"web@127.0.0.1", "uptime")
	cmd.Env = []string{"BROKER_TOKEN=token-a", "SSH_ASKPASS=" + askpass, "SSH_ASKPASS_REQUIRE=force", "HOME=" + dir}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 || string(out) != "ran: uptime" {
		t.Fatalf("out=%q err=%v stderr=%q", out, err, stderr.String())
	}
}

func TestExampleConfigurationLoads(t *testing.T) {
	if _, err := LoadConfig("../examples/config.json"); err != nil {
		t.Fatal(err)
	}
}
