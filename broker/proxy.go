package broker

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"
	"sync"
	"time"
)

// minSecretLen is the shortest secret the broker accepts. Shorter values
// would make the response scan cut legitimate responses.
const minSecretLen = 8

var errHostNotBound = errors.New("the secret is not bound to this host")

// Server is the proxy. It is an http.Handler meant to be served over plain
// HTTP on a loopback address: clients talk to it as an HTTPS proxy.
type Server struct {
	mu    sync.RWMutex // guards cfg and ca, replaced together by SetConfig
	cfg   *Config
	ca    *authorities
	store Store
	auth  Authenticator
	audit Auditor

	cacheMu    sync.Mutex // guards what is derived from secrets and reused
	awsCache   map[string]awsCredentials
	oauthCache map[string]oauthToken

	cmdMu   sync.Mutex // serialises start and stop of commands
	runMu   sync.Mutex // guards running; taken alone or inside cmdMu
	running map[string]*runningCommand

	// Approver, when set, must authorise each client for each credential.
	Approver Approver

	// Transport performs the upstream requests. It must verify TLS and must
	// not follow redirects (an http.RoundTripper never does). Replaced only
	// in tests.
	Transport http.RoundTripper
}

// NewServer validates cfg and creates the ephemeral CA.
func NewServer(cfg *Config, store Store, auth Authenticator, audit Auditor) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ca, err := (&authorities{}).extend(cfg.hosts())
	if err != nil {
		return nil, err
	}
	if audit == nil {
		audit = discard{}
	}
	return &Server{
		cfg: cfg, store: store, auth: auth, audit: audit, ca: ca,
		Transport: &http.Transport{
			Proxy:                 nil, // never chain through an environment proxy
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
			IdleConnTimeout:       90 * time.Second,
		},
	}, nil
}

// CACertPEM returns the certificate clients must trust.
func (s *Server) CACertPEM() []byte { _, ca := s.state(); return ca.pem }

func (s *Server) state() (*Config, *authorities) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg, s.ca
}

// SetConfig replaces the credentials while the server runs. Hosts that were
// already configured keep their CA, so clients that trusted it keep working;
// new hosts get one more CA, added to the certificate file. Tunnels opened
// before the change stop being served and have to be opened again.
func (s *Server) SetConfig(cfg *Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ca, err := s.ca.extend(cfg.hosts())
	if err != nil {
		return err
	}
	s.cfg, s.ca = cfg, ca
	return nil
}

// Sealed reports whether the store is still sealed.
func (s *Server) Sealed() bool {
	_, err := s.store.Get("status")
	return errors.Is(err, ErrSealed)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		s.connect(w, r)
	case r.Method == http.MethodGet && r.URL.Host == "" && r.URL.Path == "/status":
		fmt.Fprintf(w, "{\"sealed\":%t}\n", s.Sealed())
	case r.Method == http.MethodGet && r.URL.Host == "" && strings.HasPrefix(r.URL.Path, "/aws/"):
		s.aws(w, r)
	case r.URL.Host == "" && strings.HasPrefix(r.URL.Path, "/commands/"):
		s.command(w, r)
	default:
		http.Error(w, "secrets-broker: only CONNECT is supported", http.StatusMethodNotAllowed)
	}
}

// connect authenticates the client, checks that it may use a credential on
// the requested host, and only then terminates TLS and serves the tunnel.
func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	ev := Event{Time: time.Now().UTC(), Method: http.MethodConnect}
	deny := func(code int, reason string) {
		ev.Decision, ev.Reason, ev.Status = "denied", reason, code
		s.audit.Record(ev)
		http.Error(w, "secrets-broker: "+reason, code)
	}

	host, port, err := net.SplitHostPort(r.Host)
	host = normalizeHost(host)
	ev.Host = host
	if err != nil || port != "443" {
		deny(http.StatusForbidden, "only port 443 is allowed")
		return
	}
	token, ok := proxyToken(r)
	if !ok {
		w.Header().Set("Proxy-Authenticate", `Basic realm="secrets-broker"`)
		deny(http.StatusProxyAuthRequired, "proxy authentication required")
		return
	}
	p, err := s.auth.Authenticate(r.Context(), token)
	if err != nil {
		w.Header().Set("Proxy-Authenticate", `Basic realm="secrets-broker"`)
		deny(http.StatusProxyAuthRequired, "invalid token")
		return
	}
	ev.Principal, ev.Groups = p.ID, p.Groups
	cfg, ca := s.state()
	cred, reason := cfg.credentialFor(host, p.Groups)
	if cred == nil {
		deny(http.StatusForbidden, reason)
		return
	}
	ev.Credential = cred.Name
	if _, err := s.secretFor(cred, host); err != nil {
		deny(statusFor(err), err.Error())
		return
	}
	if err := s.approved(p, cred); err != nil {
		deny(http.StatusForbidden, err.Error())
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		deny(http.StatusInternalServerError, "connection cannot be hijacked")
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if brw.Reader.Buffered() > 0 {
		return // bytes sent before the tunnel was established
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}

	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if normalizeHost(hello.ServerName) != host {
				return nil, fmt.Errorf("SNI %q does not match the tunnel host", hello.ServerName)
			}
			return ca.leaf(host)
		},
	})
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		ev.Decision, ev.Reason = "denied", "TLS handshake: "+err.Error()
		s.audit.Record(ev)
		return
	}
	conn.SetDeadline(time.Time{})

	inner := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.forward(w, r, token, host, cred)
		}),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	inner.Serve(newOneConnListener(tlsConn)) // returns when the tunnel closes
}

// forward performs one request of an established tunnel against the bound
// host, with the real Authorization header. token is what the client
// presented at CONNECT.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, token, host string, cred *Credential) {
	ev := Event{Time: time.Now().UTC(), Credential: cred.Name, Host: host, Method: r.Method, Path: r.URL.Path}
	deny := func(code int, reason string) {
		ev.Decision, ev.Reason, ev.Status = "denied", reason, code
		s.audit.Record(ev)
		http.Error(w, "secrets-broker: "+reason, code)
	}

	// A tunnel can stay open for a long time. The token is checked again on
	// every request, so an expired or revoked token stops working at once.
	p, err := s.auth.Authenticate(r.Context(), token)
	if err != nil {
		deny(http.StatusForbidden, "token is no longer valid")
		return
	}
	ev.Principal, ev.Groups = p.ID, p.Groups
	cfg, _ := s.state()
	if again, _ := cfg.credentialFor(host, p.Groups); again != cred {
		deny(http.StatusForbidden, "this client may no longer use this credential")
		return
	}

	// The tunnel was authorised for one host. A request naming another host
	// inside it is refused: the credential goes to the host that was checked
	// against the SNI, or nowhere.
	if normalizeHost(strings.TrimSuffix(r.Host, ":443")) != host {
		deny(http.StatusMisdirectedRequest, "Host header does not match the tunnel host")
		return
	}
	if !cred.allows(r.Method) {
		deny(http.StatusMethodNotAllowed, "method not allowed for this credential")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/") || r.Header.Get("Upgrade") != "" {
		deny(http.StatusBadRequest, "unsupported request")
		return
	}
	secret, err := s.secretFor(cred, host)
	if err != nil {
		if errors.Is(err, ErrSealed) {
			s.forget()
		}
		deny(statusFor(err), err.Error())
		return
	}
	if err := s.approved(p, cred); err != nil {
		deny(http.StatusForbidden, err.Error())
		return
	}
	authz, needles, err := s.authorizationFor(r.Context(), cred, secret)
	if err != nil {
		deny(http.StatusBadGateway, err.Error())
		return
	}

	rp := &httputil.ReverseProxy{
		Transport: s.Transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = host
			pr.Out.Host = host
			// Without a client Accept-Encoding the transport negotiates
			// gzip itself and hands over the decoded body, which is what
			// the response scan needs.
			pr.Out.Header.Del("Accept-Encoding")
			// The only place the secret is ever written. Whatever the
			// client sent as Authorization is discarded.
			pr.Out.Header.Set("Authorization", authz)
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode == http.StatusSwitchingProtocols {
				return errors.New("protocol upgrade is not supported")
			}
			if ce := resp.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
				return fmt.Errorf("response with Content-Encoding %q cannot be inspected", ce)
			}
			for _, values := range resp.Header {
				for _, v := range values {
					if containsAny([]byte(v), needles) {
						return errLeak
					}
				}
			}
			resp.Body = newLeakGuard(resp.Body, needles, func() {
				leak := ev
				leak.Decision, leak.Reason = "denied", errLeak.Error()
				s.audit.Record(leak)
			})
			ev.Decision, ev.Status = "allowed", resp.StatusCode
			s.audit.Record(ev)
			return nil
		},
		ErrorHandler: func(_ http.ResponseWriter, _ *http.Request, err error) {
			deny(http.StatusBadGateway, "upstream: "+err.Error())
		},
	}
	rp.ServeHTTP(w, r)
}

// secretFor fetches the secret of cred and enforces the host list stored
// with the secret itself.
func (s *Server) secretFor(cred *Credential, host string) (Secret, error) {
	sec, err := s.store.Get(cred.secretName())
	if err != nil {
		return Secret{}, err
	}
	if !slices.Contains(sec.Hosts, host) {
		return Secret{}, errHostNotBound
	}
	if len(sec.Value) < minSecretLen {
		return Secret{}, errors.New("secret is too short")
	}
	return sec, nil
}

// approved asks the Approver, when there is one. A grant can end while a
// tunnel is open, so this runs on every request.
func (s *Server) approved(p Principal, cred *Credential) error {
	if s.Approver == nil {
		return nil
	}
	return s.Approver.Authorize(p, cred.Name, cred.Hosts)
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, ErrSealed):
		return http.StatusServiceUnavailable
	case errors.Is(err, errHostNotBound):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// proxyToken extracts the client token from Proxy-Authorization. With
// "http://user:token@proxy" the token is the password; with
// "http://token@proxy" it is the user name.
func proxyToken(r *http.Request) (string, bool) {
	const prefix = "Basic "
	h := r.Header.Get("Proxy-Authorization")
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(h[len(prefix):])
	if err != nil {
		return "", false
	}
	user, pass, _ := strings.Cut(string(raw), ":")
	if pass == "" {
		pass = user
	}
	return pass, pass != ""
}

type discard struct{}

func (discard) Record(Event) {}

// oneConnListener lets an http.Server serve a single, already accepted
// connection. The second Accept blocks until that connection is closed, so
// Serve returns exactly when the tunnel ends.
type oneConnListener struct {
	conn chan net.Conn
	done chan struct{}
	addr net.Addr
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{conn: make(chan net.Conn, 1), done: make(chan struct{}), addr: c.LocalAddr()}
	l.conn <- &notifyConn{Conn: c, done: l.done}
	close(l.conn)
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if c, ok := <-l.conn; ok {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.addr }

type notifyConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *notifyConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}
