package broker

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

const (
	goodHost    = "example.com" // httptest certificates are valid for this name
	evilHost    = "evil.test"
	secretValue = "s3cr3t-value-0123456789"
	placeholder = "PLACEHOLDER-TOKEN"
)

type memStore struct {
	mu     sync.Mutex
	sealed bool
	m      map[string]Secret
}

func (s *memStore) Get(name string) (Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed {
		return Secret{}, ErrSealed
	}
	sec, ok := s.m[name]
	if !ok {
		return Secret{}, ErrNotFound
	}
	return sec, nil
}

type tokenAuth map[string]Principal

func (a tokenAuth) Authenticate(_ context.Context, token string) (Principal, error) {
	p, ok := a[token]
	if !ok {
		return Principal{}, errors.New("unknown token")
	}
	return p, nil
}

type seenRequest struct {
	Method, Host, URI, Authorization, Body string
}

// origin is a fake HTTPS service that records what reaches it.
type origin struct {
	*httptest.Server
	mu   sync.Mutex
	seen []seenRequest
}

func newOrigin(t *testing.T, handler http.HandlerFunc) *origin {
	o := &origin{}
	o.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		o.mu.Lock()
		o.seen = append(o.seen, seenRequest{r.Method, r.Host, r.RequestURI, r.Header.Get("Authorization"), string(body)})
		o.mu.Unlock()
		if handler != nil {
			handler(w, r)
		}
	}))
	t.Cleanup(o.Close)
	return o
}

func (o *origin) requests() []seenRequest {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]seenRequest(nil), o.seen...)
}

type recorder struct {
	mu     sync.Mutex
	events []Event
}

func (r *recorder) Record(ev Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recorder) has(decision, reasonPart string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ev := range r.events {
		if ev.Decision == decision && strings.Contains(ev.Reason, reasonPart) {
			return true
		}
	}
	return false
}

type harness struct {
	t      *testing.T
	good   *origin
	evil   *origin
	store  *memStore
	audit  *recorder
	srv    *Server
	broker *httptest.Server
}

func newHarness(t *testing.T, cred Credential, handler http.HandlerFunc) *harness {
	h := &harness{t: t, audit: &recorder{}}
	h.good = newOrigin(t, handler)
	h.evil = newOrigin(t, nil)
	h.store = &memStore{m: map[string]Secret{"svc": {Value: []byte(secretValue), Hosts: []string{goodHost}}}}
	auth := tokenAuth{
		"token-a": {ID: "agent-a", Groups: []string{"team-a"}},
		"token-b": {ID: "agent-b", Groups: []string{"team-b"}},
	}
	if cred.Name == "" {
		cred = Credential{Name: "svc", Hosts: []string{goodHost}, Groups: []string{"team-a"}, Scheme: "bearer"}
	}
	srv, err := NewServer(&Config{Credentials: []Credential{cred}}, h.store, auth, h.audit)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(h.good.Certificate())
	addrs := map[string]string{
		goodHost + ":443": h.good.Listener.Addr().String(),
		evilHost + ":443": h.evil.Listener.Addr().String(),
	}
	srv.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			target, ok := addrs[addr]
			if !ok {
				return nil, fmt.Errorf("unexpected dial to %s", addr)
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	}
	h.srv = srv
	h.broker = httptest.NewServer(srv)
	t.Cleanup(h.broker.Close)
	return h
}

func (h *harness) caPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(h.srv.CACertPEM()) {
		h.t.Fatal("bad CA certificate")
	}
	return pool
}

// client returns an HTTP client that uses the broker as its HTTPS proxy.
func (h *harness) client(token string) *http.Client {
	proxy, _ := url.Parse(h.broker.URL)
	if token != "" {
		proxy.User = url.UserPassword("agent", token)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: h.caPool()}}
	h.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

// tunnel opens a CONNECT tunnel by hand, for the attacks a well-behaved
// client would never attempt.
func (h *harness) tunnel(connectHost, token string) (net.Conn, *http.Response) {
	conn, err := net.Dial("tcp", h.broker.Listener.Addr().String())
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Authorization: Basic %s\r\n\r\n",
		connectHost, connectHost, base64.StdEncoding.EncodeToString([]byte("agent:"+token)))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		h.t.Fatal(err)
	}
	return conn, resp
}

func TestInjectsOnlyTheAuthorizationHeader(t *testing.T) {
	h := newHarness(t, Credential{}, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	body := `{"comment":"` + placeholder + `"}`
	req, _ := http.NewRequest("POST", "https://"+goodHost+"/repos/x?token="+placeholder, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+placeholder)
	resp, err := h.client("token-a").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(got) != "ok" {
		t.Fatalf("response = %d %q", resp.StatusCode, got)
	}
	seen := h.good.requests()
	if len(seen) != 1 {
		t.Fatalf("origin saw %d requests", len(seen))
	}
	if seen[0].Authorization != "Bearer "+secretValue {
		t.Errorf("Authorization = %q", seen[0].Authorization)
	}
	// The placeholder is not a sentinel: body and URL go through untouched.
	if seen[0].Body != body || seen[0].URI != "/repos/x?token="+placeholder {
		t.Errorf("body or URL was rewritten: %+v", seen[0])
	}
	if !h.audit.has("allowed", "") {
		t.Error("no audit event for the allowed request")
	}
}

func TestBasicScheme(t *testing.T) {
	cred := Credential{Name: "svc", Hosts: []string{goodHost}, Groups: []string{"team-a"}, Scheme: "basic", Username: "bot"}
	h := newHarness(t, cred, nil)
	resp, err := h.client("token-a").Get("https://" + goodHost + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("bot:"+secretValue))
	if got := h.good.requests()[0].Authorization; got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

func TestOtherHostGetsNothing(t *testing.T) {
	h := newHarness(t, Credential{}, nil)
	_, err := h.client("token-a").Get("https://" + evilHost + "/steal")
	if err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("err = %v, want a 403 from the proxy", err)
	}
	if n := len(h.evil.requests()); n != 0 {
		t.Fatalf("attacker host received %d requests", n)
	}
	if !h.audit.has("denied", "host is not configured") {
		t.Error("denial was not audited")
	}
}

func TestRedirectToAnotherHostLosesTheCredential(t *testing.T) {
	h := newHarness(t, Credential{}, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+evilHost+"/steal", http.StatusFound)
	})
	// The broker hands the redirect back instead of following it...
	noFollow := h.client("token-a")
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noFollow.Get("https://" + goodHost + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want the 302 itself", resp.StatusCode)
	}
	// ...and a client that follows it is stopped at the next CONNECT.
	if _, err := h.client("token-a").Get("https://" + goodHost + "/"); err == nil {
		t.Fatal("following the redirect should fail at the proxy")
	}
	if n := len(h.evil.requests()); n != 0 {
		t.Fatalf("attacker host received %d requests", n)
	}
}

func TestHostHeaderMustMatchTunnel(t *testing.T) {
	h := newHarness(t, Credential{}, nil)
	conn, resp := h.tunnel(goodHost, "token-a")
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT = %d", resp.StatusCode)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: goodHost, RootCAs: h.caPool()})
	fmt.Fprintf(tc, "GET /steal HTTP/1.1\r\nHost: %s\r\n\r\n", evilHost)
	inner, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	if inner.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", inner.StatusCode)
	}
	if n := len(h.good.requests()) + len(h.evil.requests()); n != 0 {
		t.Fatalf("%d requests left the broker", n)
	}
}

func TestSNIMustMatchTunnel(t *testing.T) {
	h := newHarness(t, Credential{}, nil)
	conn, resp := h.tunnel(goodHost, "token-a")
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT = %d", resp.StatusCode)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: evilHost, InsecureSkipVerify: true})
	if err := tc.Handshake(); err == nil {
		t.Fatal("handshake with another SNI should fail")
	}
	if !h.audit.has("denied", "SNI") {
		t.Error("SNI mismatch was not audited")
	}
}

func TestClientMustAuthenticate(t *testing.T) {
	h := newHarness(t, Credential{}, nil)
	for _, token := range []string{"", "wrong-token"} {
		_, err := h.client(token).Get("https://" + goodHost + "/")
		if err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
			t.Errorf("token %q: err = %v, want 407", token, err)
		}
	}
	if n := len(h.good.requests()); n != 0 {
		t.Fatalf("origin received %d requests", n)
	}
}

func TestGroupPolicy(t *testing.T) {
	h := newHarness(t, Credential{}, nil)
	_, err := h.client("token-b").Get("https://" + goodHost + "/")
	if err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("err = %v, want 403 for a client of another group", err)
	}
	if n := len(h.good.requests()); n != 0 {
		t.Fatalf("origin received %d requests", n)
	}
}

func TestRevokedTokenStopsAnOpenTunnel(t *testing.T) {
	h := newHarness(t, Credential{}, nil)
	auth := h.srv.auth.(tokenAuth)
	c := h.client("token-a")
	get := func() int {
		resp, err := c.Get("https://" + goodHost + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(); code != 200 {
		t.Fatalf("first request = %d", code)
	}
	delete(auth, "token-a") // the keep-alive tunnel is still open
	if code := get(); code != http.StatusForbidden {
		t.Fatalf("request after revocation = %d, want 403", code)
	}
	if n := len(h.good.requests()); n != 1 {
		t.Fatalf("origin received %d requests, want 1", n)
	}
}

func TestSealed(t *testing.T) {
	h := newHarness(t, Credential{}, nil)
	h.store.sealed = true
	_, err := h.client("token-a").Get("https://" + goodHost + "/")
	if err == nil || !strings.Contains(err.Error(), "Service Unavailable") {
		t.Fatalf("err = %v, want 503 while sealed", err)
	}
	resp, err := http.Get(h.broker.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.TrimSpace(string(got)) != `{"sealed":true}` {
		t.Errorf("status = %s", got)
	}
}

func TestSecretBoundToAnotherHost(t *testing.T) {
	// The configuration says the secret goes to goodHost, but the secret
	// itself was sealed for another host: the secret wins.
	h := newHarness(t, Credential{}, nil)
	h.store.m["svc"] = Secret{Value: []byte(secretValue), Hosts: []string{"other.example"}}
	_, err := h.client("token-a").Get("https://" + goodHost + "/")
	if err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("err = %v, want 403", err)
	}
	if n := len(h.good.requests()); n != 0 {
		t.Fatalf("origin received %d requests", n)
	}
}

func TestMethods(t *testing.T) {
	cred := Credential{Name: "svc", Hosts: []string{goodHost}, Groups: []string{"team-a"}, Scheme: "bearer", Methods: []string{"GET", "HEAD"}}
	h := newHarness(t, cred, nil)
	c := h.client("token-a")
	for _, method := range []string{"TRACE", "POST"} {
		req, _ := http.NewRequest(method, "https://"+goodHost+"/", nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d, want 405", method, resp.StatusCode)
		}
	}
	if n := len(h.good.requests()); n != 0 {
		t.Fatalf("origin received %d requests", n)
	}
}

func TestReflectedCredentialIsCut(t *testing.T) {
	filler := strings.Repeat("x", 100<<10)
	cases := map[string]http.HandlerFunc{
		"body": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, filler+r.Header.Get("Authorization")+filler)
		},
		"gzip body": func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				t.Error("broker did not negotiate gzip itself")
			}
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			io.WriteString(zw, filler+r.Header.Get("Authorization"))
			zw.Close()
		},
		"header": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		},
		"unreadable encoding": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "br")
			io.WriteString(w, "opaque")
		},
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, Credential{}, handler)
			req, _ := http.NewRequest("GET", "https://"+goodHost+"/echo", nil)
			req.Header.Set("Accept-Encoding", "br") // the client does not get to choose
			resp, err := h.client("token-a").Do(req)
			var got []byte
			if err == nil {
				got, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				for _, v := range resp.Header {
					got = append(got, strings.Join(v, " ")...)
				}
				if err == nil && resp.StatusCode == 200 {
					t.Errorf("response was delivered whole (%d bytes)", len(got))
				}
			}
			if strings.Contains(string(got), secretValue) {
				t.Fatal("the credential reached the client")
			}
		})
	}
}

func TestLeakGuardAcrossReads(t *testing.T) {
	needle := []byte(secretValue)
	clean := strings.Repeat("abc", 1000)
	g := newLeakGuard(io.NopCloser(iotest.OneByteReader(strings.NewReader(clean))), [][]byte{needle}, func() {})
	if got, err := io.ReadAll(g); err != nil || string(got) != clean {
		t.Fatalf("clean stream altered: err=%v len=%d", err, len(got))
	}
	leaked := false
	g = newLeakGuard(io.NopCloser(iotest.OneByteReader(strings.NewReader(clean+secretValue+clean))), [][]byte{needle}, func() { leaked = true })
	got, err := io.ReadAll(g)
	if !errors.Is(err, errLeak) || !leaked {
		t.Fatalf("err = %v, leaked = %v", err, leaked)
	}
	// Not even a prefix of the secret may have been released.
	if !strings.HasPrefix(clean, string(got)) {
		t.Fatalf("released bytes beyond the clean prefix: %q", got[len(got)-10:])
	}
}

func TestConfigValidation(t *testing.T) {
	ok := Credential{Name: "svc", Hosts: []string{"api.example.com"}, Groups: []string{"g"}, Scheme: "bearer"}
	bad := map[string]func(c *Config){
		"wildcard host":   func(c *Config) { c.Credentials[0].Hosts = []string{"*.example.com"} },
		"host with port":  func(c *Config) { c.Credentials[0].Hosts = []string{"example.com:443"} },
		"upper-case host": func(c *Config) { c.Credentials[0].Hosts = []string{"Example.com"} },
		"IP address":      func(c *Config) { c.Credentials[0].Hosts = []string{"10.0.0.1"} },
		"no group":        func(c *Config) { c.Credentials[0].Groups = nil },
		"unknown scheme":  func(c *Config) { c.Credentials[0].Scheme = "cookie" },
		"TRACE method":    func(c *Config) { c.Credentials[0].Methods = []string{"TRACE"} },
		"wildcard listen": func(c *Config) { c.Listen = ":8080" },
		"same host+group": func(c *Config) { d := ok; d.Name = "svc2"; c.Credentials = append(c.Credentials, d) },
		"no credentials":  func(c *Config) { c.Credentials = nil },
		"basic, no user":  func(c *Config) { c.Credentials[0].Scheme = "basic" },
		"bad secret name": func(c *Config) { c.Credentials[0].Secret = "../etc/passwd" },
		"duplicate names": func(c *Config) {
			d := ok
			d.Hosts = []string{"b.example.com"}
			c.Credentials = append(c.Credentials, d)
		},
		"empty group name": func(c *Config) { c.Credentials[0].Groups = []string{""} },
	}
	for name, mutate := range bad {
		c := &Config{Listen: "127.0.0.1:8471", Credentials: []Credential{ok}}
		c.Credentials[0].Hosts = append([]string(nil), ok.Hosts...)
		if err := c.Validate(); err != nil {
			t.Fatalf("base config: %v", err)
		}
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type fakeUnsealer struct{ key string }

func (f *fakeUnsealer) Unseal(key []byte) (int, error) {
	if string(key) != "right-key\n" {
		return 0, errors.New("wrong key")
	}
	f.key = string(key)
	return 3, nil
}
func (f *fakeUnsealer) Seal() { f.key = "" }

func TestControlSocket(t *testing.T) {
	path := t.TempDir() + "/control.sock"
	l, err := ListenControl(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	u := &fakeUnsealer{}
	grants := NewGrants(Approval{Durations: []Duration{Duration(time.Hour)}}, nil, nil)
	ctl := &Control{Unsealer: u, Sealed: func() bool { return u.key == "" }, Grants: grants}
	go ctl.Serve(l)

	if _, err := ControlRequest(path, "unseal", strings.NewReader("wrong\n")); err == nil {
		t.Error("wrong key accepted")
	}
	if reply, err := ControlRequest(path, "status", nil); err != nil || reply != "ok: sealed=true" {
		t.Errorf("status = %q, %v", reply, err)
	}
	if reply, err := ControlRequest(path, "unseal", strings.NewReader("right-key\n")); err != nil || !strings.Contains(reply, "3 secrets") {
		t.Errorf("unseal = %q, %v", reply, err)
	}
	if reply, err := ControlRequest(path, "seal", nil); err != nil || u.key != "" {
		t.Errorf("seal = %q, %v", reply, err)
	}

	// A request shows up in "pending" and is answered with "approve".
	p := Principal{ID: "agent-a", Name: "fix the build"}
	var pending *ApprovalError
	if err := grants.Authorize(p, "svc", []string{goodHost}); !errors.As(err, &pending) || pending.RequestID == "" {
		t.Fatalf("first use = %v, want a waiting request", err)
	}
	if reply, err := ControlRequest(path, "pending", nil); err != nil || !strings.Contains(reply, pending.RequestID) || !strings.Contains(reply, `"fix the build"`) {
		t.Errorf("pending = %q, %v", reply, err)
	}
	if _, err := ControlRequest(path, "approve "+pending.RequestID+" 0s", nil); err == nil {
		t.Error("approve with a zero duration accepted")
	}
	if reply, err := ControlRequest(path, "approve "+pending.RequestID+" 30m", nil); err != nil {
		t.Errorf("approve = %q, %v", reply, err)
	}
	if err := grants.Authorize(p, "svc", nil); err != nil {
		t.Errorf("after approve: %v", err)
	}
	if reply, err := ControlRequest(path, "grants", nil); err != nil || !strings.Contains(reply, "agent-a") {
		t.Errorf("grants = %q, %v", reply, err)
	}
	if reply, err := ControlRequest(path, "revoke all", nil); err != nil || reply != "ok: 1 grants revoked" {
		t.Errorf("revoke = %q, %v", reply, err)
	}
	if err := grants.Authorize(p, "svc", nil); err == nil {
		t.Error("grant still valid after revoke")
	}
}

// The name of a credential goes in the proxy URL with its slashes written
// "%2F"; a client may send it decoded or as it was.
func TestProxyUserMayBeAPathName(t *testing.T) {
	for _, user := range []string{"team/github/api-token/all", "team%2Fgithub%2Fapi-token%2Fall"} {
		r, _ := http.NewRequest("CONNECT", "http://example.com", nil)
		r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":token-a")))
		got, pass, ok := proxyToken(r)
		if !ok || got != "team/github/api-token/all" || pass != "token-a" {
			t.Errorf("%s: %q %q %t", user, got, pass, ok)
		}
	}
}
