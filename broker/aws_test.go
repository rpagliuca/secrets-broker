package broker

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func answer(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}

const (
	awsKeyID     = "AKIDEXAMPLE000000000"
	awsSecretKey = "long-term-secret-key-never-leaves"
	stsAnswer    = `<GetSessionTokenResponse><GetSessionTokenResult><Credentials>
<AccessKeyId>ASIATEMP</AccessKeyId><SecretAccessKey>temp-secret</SecretAccessKey>
<SessionToken>temp-token</SessionToken><Expiration>EXPIRES</Expiration>
</Credentials></GetSessionTokenResult></GetSessionTokenResponse>`
)

// awsHarness adds one AWS account and a fake STS to the HTTP harness.
func awsHarness(t *testing.T) (*harness, *[]url.Values) {
	h := newHarness(t, Credential{}, nil)
	cfg, _ := h.srv.state()
	next := *cfg
	next.AWS = []AWSAccount{{Name: "prod", Groups: []string{"team-a"}}}
	if err := h.srv.SetConfig(&next); err != nil {
		t.Fatal(err)
	}
	h.store.m["prod"] = Secret{Value: []byte(awsKeyID + ":" + awsSecretKey), Hosts: []string{"sts.us-east-1.amazonaws.com"}}
	var mu sync.Mutex
	var calls []url.Values
	origin := h.srv.Transport
	h.srv.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "sts.us-east-1.amazonaws.com" {
			return origin.RoundTrip(r)
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		// The signature must be the one this key gives for this exact request.
		signed := r.Header.Get("Authorization")
		at, _ := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
		check := r.Clone(r.Context())
		signV4(check, string(body), awsKeyID, awsSecretKey, "us-east-1", "sts", at)
		if signed != check.Header.Get("Authorization") || !strings.HasPrefix(signed, "AWS4-HMAC-SHA256 Credential="+awsKeyID+"/") {
			return answer(403, "<Error><Code>SignatureDoesNotMatch</Code></Error>"), nil
		}
		if strings.Contains(string(body)+signed, awsSecretKey) {
			t.Error("the long-term key was sent to STS")
		}
		mu.Lock()
		calls = append(calls, form)
		mu.Unlock()
		secs, _ := strconv.Atoi(form.Get("DurationSeconds"))
		exp := time.Now().Add(time.Duration(secs) * time.Second).UTC().Format(time.RFC3339)
		return answer(200, strings.Replace(stsAnswer, "EXPIRES", exp, 1)), nil
	})
	return h, &calls
}

func (h *harness) aws(name, token string) (int, string) {
	req, _ := http.NewRequest(http.MethodGet, h.broker.URL+"/aws/"+name, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestAWSTemporaryCredentials(t *testing.T) {
	h, calls := awsHarness(t)
	code, body := h.aws("prod", "token-a")
	var creds awsCredentials
	if code != 200 || json.Unmarshal([]byte(body), &creds) != nil {
		t.Fatalf("%d %s", code, body)
	}
	if creds.Version != 1 || creds.AccessKeyID != "ASIATEMP" || creds.SecretAccessKey != "temp-secret" || creds.SessionToken != "temp-token" {
		t.Fatalf("creds = %+v", creds)
	}
	if strings.Contains(body, awsSecretKey) || strings.Contains(body, awsKeyID) {
		t.Fatal("the long-term key reached the client")
	}
	if c := (*calls)[0]; c.Get("Action") != "GetSessionToken" || c.Get("DurationSeconds") != "3600" {
		t.Fatalf("STS request = %v", c)
	}
	if h.aws("prod", "token-a"); len(*calls) != 1 {
		t.Fatalf("%d STS calls, want the second request served from the first session", len(*calls))
	}
	if !h.audit.hasSSH("allowed", "aws-credentials", "") {
		t.Fatalf("audit = %+v", h.audit.events)
	}
}

func TestAWSRefusals(t *testing.T) {
	h, calls := awsHarness(t)
	for name, tc := range map[string]struct {
		account, token string
		want           int
	}{
		"no token":                 {"prod", "", 401},
		"wrong token":              {"prod", "nope", 401},
		"account of another group": {"prod", "token-b", 403},
		"unknown account":          {"dev", "token-a", 403},
	} {
		if code, _ := h.aws(tc.account, tc.token); code != tc.want {
			t.Errorf("%s: %d, want %d", name, code, tc.want)
		}
	}
	h.store.m["prod"] = Secret{Value: h.store.m["prod"].Value, Hosts: []string{"sts.eu-west-1.amazonaws.com"}}
	if code, _ := h.aws("prod", "token-a"); code == 200 {
		t.Error("a key bound to another STS host was used")
	}
	h.store.sealed = true
	if code, _ := h.aws("prod", "token-a"); code != 503 {
		t.Errorf("sealed: %d", code)
	}
	if len(*calls) != 0 {
		t.Fatalf("STS was called: %v", *calls)
	}
}

func TestAWSSessionEndsWithTheGrant(t *testing.T) {
	h, calls := awsHarness(t)
	g := NewGrants(Approval{Durations: []Duration{Duration(time.Hour)}}, nil, h.audit)
	h.srv.Approver = g
	if code, body := h.aws("prod", "token-a"); code != 403 || !strings.Contains(body, "waiting for approval") {
		t.Fatalf("%d %s", code, body)
	}
	pending := g.Pending()
	if len(pending) != 1 || pending[0].Credential != "aws:prod" {
		t.Fatalf("pending = %+v", pending)
	}
	g.Decide(pending[0].ID, 20*time.Minute, "test")
	if code, body := h.aws("prod", "token-a"); code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	secs, _ := strconv.Atoi((*calls)[0].Get("DurationSeconds"))
	if secs > 1200 || secs < 1100 {
		t.Fatalf("session of %d s for a grant of 20 min", secs)
	}
	g.Revoke("agent-a", "test")
	if code, _ := h.aws("prod", "token-a"); code != 403 {
		t.Fatalf("after the revocation: %d", code)
	}
}

func TestOAuthAccessTokenIsInjected(t *testing.T) {
	const access = "access-token-0123456789"
	cred := Credential{Name: "svc", Hosts: []string{goodHost}, Groups: []string{"team-a"}, Scheme: "oauth2", TokenURL: "https://auth.example.com/token"}
	h := newHarness(t, cred, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/echo" {
			io.WriteString(w, r.Header.Get("Authorization"))
			return
		}
		io.WriteString(w, "seen:"+strconv.FormatBool(r.Header.Get("Authorization") == "Bearer "+access))
	})
	secret := `{"client_id":"client-id","client_secret":"client-secret-value","refresh_token":"refresh-token-value"}`
	h.store.m["svc"] = Secret{Value: []byte(secret), Hosts: []string{goodHost, "auth.example.com"}}
	exchanges := 0
	origin := h.srv.Transport
	h.srv.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "auth.example.com" {
			return origin.RoundTrip(r)
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "refresh-token-value" || form.Get("client_secret") != "client-secret-value" {
			return answer(400, `{"error":"invalid_grant"}`), nil
		}
		exchanges++
		return answer(200, `{"access_token":"`+access+`","expires_in":3600}`), nil
	})
	get := func(path string) (int, string) {
		resp, err := h.client("token-a").Get("https://" + goodHost + path)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if code, body := get("/"); code != 200 || body != "seen:true" {
		t.Fatalf("%d %q", code, body)
	}
	if get("/"); exchanges != 1 {
		t.Fatalf("%d token exchanges, want the access token reused", exchanges)
	}
	if _, body := get("/echo"); strings.Contains(body, access) {
		t.Fatal("the access token came back to the client")
	}
	// A secret not bound to the token endpoint is never sent there.
	h.srv.forget()
	h.store.m["svc"] = Secret{Value: []byte(secret), Hosts: []string{goodHost}}
	if code, _ := get("/"); code == 200 || exchanges != 1 {
		t.Fatalf("code %d, %d exchanges", code, exchanges)
	}
}

func TestCommandRunsWithSecretFilesAndStopsWithTheGrant(t *testing.T) {
	h := newHarness(t, Credential{}, nil)
	base, marker := t.TempDir(), t.TempDir()+"/stopped"
	cfg, _ := h.srv.state()
	next := *cfg
	next.CommandsDir = base
	next.Commands = []Command{{
		Name: "vpn", Groups: []string{"team-a"},
		Start: []string{"/bin/sh", "-c", "echo up; cat {dir}/auth.txt; echo $WHERE"},
		Stop:  []string{"/bin/sh", "-c", "echo down > " + marker},
		Files: []CommandFile{{Secret: "vpn-auth", Name: "auth.txt"}},
		Env:   map[string]string{"WHERE": "{dir}"},
	}}
	if err := h.srv.SetConfig(&next); err != nil {
		t.Fatal(err)
	}
	h.store.m["vpn-auth"] = Secret{Value: []byte("user-and-password-value"), Hosts: []string{"command:vpn"}}
	g := NewGrants(Approval{Durations: []Duration{Duration(time.Hour)}}, nil, h.audit)
	h.srv.Approver = g
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.srv.WatchCommands(ctx, 20*time.Millisecond)

	call := func(method, path, token string) (int, string) {
		req, _ := http.NewRequest(method, h.broker.URL+"/commands/"+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if code, _ := call("POST", "vpn/start", "token-b"); code != 403 {
		t.Fatalf("another group: %d", code)
	}
	if code, body := call("POST", "vpn/start", "token-a"); code != 403 || !strings.Contains(body, "waiting for approval") {
		t.Fatalf("%d %s", code, body)
	}
	if _, err := os.Stat(base + "/vpn"); err == nil {
		t.Fatal("the secret files were written before the grant")
	}
	g.Decide(g.Pending()[0].ID, time.Hour, "test")
	code, body := call("POST", "vpn/start", "token-a")
	if code != 200 || !strings.Contains(body, "up\n[redacted]") || strings.Contains(body, "user-and-password") || !strings.Contains(body, base+"/vpn") {
		t.Fatalf("%d %q", code, body)
	}
	if data, _ := os.ReadFile(base + "/vpn/auth.txt"); string(data) != "user-and-password-value" {
		t.Fatalf("file = %q", data)
	}
	if _, body := call("GET", "vpn", "token-a"); !strings.Contains(body, `"running":true`) {
		t.Fatalf("status = %s", body)
	}
	if code, _ := call("GET", "vpn/start", "token-a"); code != 405 {
		t.Fatalf("GET start: %d", code)
	}

	g.Revoke("agent-a", "test")
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the command kept running after the grant was revoked")
	}
	if _, err := os.Stat(base + "/vpn"); err == nil {
		t.Fatal("the secret files stayed after the command stopped")
	}
	if !h.audit.hasSSH("allowed", "command-stop", "grant ended") {
		t.Fatalf("audit = %+v", h.audit.events)
	}
}

func TestCommandForwardsOnlyForTheClientThatRunsIt(t *testing.T) {
	h := newHarness(t, Credential{}, nil)
	base := t.TempDir()
	cfg, _ := h.srv.state()
	next := *cfg
	next.CommandsDir = base
	next.Commands = []Command{{
		Name: "vpn", Groups: []string{"team-a"},
		Start: []string{"/bin/true"}, Stop: []string{"/bin/true"},
		Forwards: map[string]string{"10.0.0.80:502": "plc.sock"},
	}}
	if err := h.srv.SetConfig(&next); err != nil {
		t.Fatal(err)
	}
	s := newSSHHarness(t, nil)
	s.proxy.Commands = h.srv
	post := func(action string) {
		req, _ := http.NewRequest("POST", h.broker.URL+"/commands/vpn/"+action, nil)
		req.Header.Set("Authorization", "Bearer token-a")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", action, resp, err)
		}
		resp.Body.Close()
	}
	if _, err := s.dial("vpn", "token-b"); err == nil {
		t.Fatal("a client of another group connected to the command")
	}

	post("start")
	l, err := net.Listen("unix", base+"/vpn/plc.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	c := s.mustDial("vpn", "token-a")
	conn, err := c.Dial("tcp", "10.0.0.80:502")
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	io.WriteString(conn, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	if _, err := c.Dial("tcp", "10.0.0.81:502"); err == nil {
		t.Fatal("a destination outside the configuration was reached")
	}
	if _, err := c.NewSession(); err == nil {
		t.Fatal("a command connection offered a session")
	}
	post("stop")
	waitClosed(t, c)
	c = s.mustDial("vpn", "token-a")
	if _, err := c.Dial("tcp", "10.0.0.80:502"); err == nil {
		t.Fatal("the forward still works after the command stopped")
	}
}

func TestSeveralCredentialsInOneRequest(t *testing.T) {
	h, _ := awsHarness(t)
	n := &notified{ch: make(chan Request, 10)}
	g := NewGrants(Approval{Durations: []Duration{Duration(time.Hour)}}, n, h.audit)
	h.srv.Approver = g
	call := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, h.broker.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer token-a")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(out)
	}
	if code, body := call("GET", "/grants", ""); code != 200 || !strings.Contains(body, `"available":["aws:prod","svc"]`) {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := call("POST", "/requests", `{"credentials":["svc","nope"],"duration":"4h"}`); code != 400 {
		t.Fatalf("unknown name: %d", code)
	}
	code, body := call("POST", "/requests", `{"credentials":["svc","aws:prod"],"duration":"4h"}`)
	if code != 200 || !strings.Contains(body, `"request"`) {
		t.Fatalf("%d %s", code, body)
	}
	req := <-n.ch
	if len(req.Credentials) != 2 || req.Suggested != 4*time.Hour || len(g.Pending()) != 1 {
		t.Fatalf("request = %+v", req)
	}
	// Asking again, or using one of them, does not ask the approver twice.
	call("POST", "/requests", `{"credentials":["svc","aws:prod"]}`)
	h.aws("prod", "token-a")
	if len(n.ch) != 0 || len(g.Pending()) != 1 {
		t.Fatalf("%d more notifications, %d pending", len(n.ch), len(g.Pending()))
	}
	if err := g.Decide(req.ID, 4*time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	if !g.Granted("agent-a", "svc") || !g.Granted("agent-a", "aws:prod") {
		t.Fatal("one answer must grant every credential of the request")
	}
	if code, _ := h.aws("prod", "token-a"); code != 200 {
		t.Fatalf("aws after the grant: %d", code)
	}
	if _, body := call("GET", "/grants", ""); strings.Count(body, `"until"`) != 2 {
		t.Fatalf("grants = %s", body)
	}
	// A refusal blocks every credential of the request for the cooldown.
	g.Revoke("agent-a", "test")
	call("POST", "/requests", `{"credentials":["svc","aws:prod"]}`)
	g.Decide((<-n.ch).ID, 0, "test")
	if _, body := call("POST", "/requests", `{"credentials":["svc"]}`); !strings.Contains(body, `"refused"`) || len(n.ch) != 0 {
		t.Fatalf("after a refusal: %s", body)
	}
}

func TestServiceUsesItsFixedListWithoutApproval(t *testing.T) {
	h, _ := awsHarness(t)
	cfg, _ := h.srv.state()
	next := *cfg
	sum := sha256.Sum256([]byte("service-token-0123456789"))
	next.Services = []Service{{ID: "collector", SHA256: hex.EncodeToString(sum[:]), Groups: []string{"team-a"}, Credentials: []string{"aws:prod"}}}
	if err := h.srv.SetConfig(&next); err != nil {
		t.Fatal(err)
	}
	n := &notified{ch: make(chan Request, 10)}
	g := NewGrants(Approval{Durations: []Duration{Duration(time.Hour)}}, n, h.audit)
	sv := &services{cfg: func() *Config { c, _ := h.srv.state(); return c }, auth: h.srv.auth, inner: g}
	h.srv.auth, h.srv.Approver = sv, sv

	// The service gets what is on its list at once, and nobody is asked.
	if code, body := h.aws("prod", "service-token-0123456789"); code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	// Off the list it is refused, and still nobody is asked.
	_, resp := h.tunnel(goodHost, "service-token-0123456789")
	if resp.StatusCode != 403 || len(n.ch) != 0 || len(g.Pending()) != 0 {
		t.Fatalf("off the list: %d, %d notifications, %d pending", resp.StatusCode, len(n.ch), len(g.Pending()))
	}
	req, _ := http.NewRequest("POST", h.broker.URL+"/requests", strings.NewReader(`{"credentials":["svc"]}`))
	req.Header.Set("Authorization", "Bearer service-token-0123456789")
	if r, _ := http.DefaultClient.Do(req); r.StatusCode == 200 {
		t.Fatal("a service asked for approval")
	}
	// Another client still needs the approval.
	if code, body := h.aws("prod", "token-a"); code != 403 || !strings.Contains(body, "waiting for approval") {
		t.Fatalf("%d %s", code, body)
	}
	if !h.audit.hasSSH("allowed", "aws-credentials", "") {
		t.Fatalf("audit = %+v", h.audit.events)
	}
	// A service that leaves the configuration loses everything.
	h.srv.SetConfig(cfg)
	if code, _ := h.aws("prod", "service-token-0123456789"); code == 200 {
		t.Fatal("a removed service still works")
	}
}

func TestClientNamesOneOfTwoCredentialsOfAHost(t *testing.T) {
	seen := make(chan string, 10)
	h := newHarness(t, Credential{Name: "read", Secret: "svc", Hosts: []string{goodHost}, Groups: []string{"team-a"}, Scheme: "bearer", Default: true},
		func(w http.ResponseWriter, r *http.Request) { seen <- r.Header.Get("Authorization") })
	cfg, _ := h.srv.state()
	next := *cfg
	next.Credentials = append(slices.Clone(cfg.Credentials),
		Credential{Name: "write", Hosts: []string{goodHost}, Groups: []string{"team-a"}, Scheme: "bearer"},
		Credential{Name: "elsewhere", Hosts: []string{"other.example.com"}, Groups: []string{"team-a"}, Scheme: "bearer"})
	if err := h.srv.SetConfig(&next); err != nil {
		t.Fatal(err)
	}
	h.store.m["write"] = Secret{Value: []byte("the-write-secret-value"), Hosts: []string{goodHost}}
	get := func(user string) int {
		proxy, _ := url.Parse(h.broker.URL)
		proxy.User = url.UserPassword(user, "token-a")
		c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: h.caPool()}}}
		resp, err := c.Get("https://" + goodHost + "/")
		if err != nil {
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if get("anything"); <-seen != "Bearer "+secretValue {
		t.Fatal("without a name the default credential must be used")
	}
	if get("write"); <-seen != "Bearer the-write-secret-value" {
		t.Fatal("the named credential was not used")
	}
	if code := get("elsewhere"); code != 0 || len(seen) != 0 {
		t.Fatalf("a credential of another host was accepted as a name: %d", code)
	}
	two := next
	two.Credentials = slices.Clone(next.Credentials)
	two.Credentials[0].Default = false
	if err := h.srv.SetConfig(&two); err == nil {
		t.Fatal("two credentials for one host and none default was accepted")
	}
}

func TestOpenCredentialNeedsNoApprovalButIsLogged(t *testing.T) {
	h, _ := awsHarness(t)
	cfg, _ := h.srv.state()
	next := *cfg
	next.Approval = &Approval{Durations: []Duration{Duration(time.Hour)}, Open: []string{"aws:prod"}}
	if err := h.srv.SetConfig(&next); err != nil {
		t.Fatal(err)
	}
	n := &notified{ch: make(chan Request, 10)}
	g := NewGrants(*next.Approval, n, h.audit)
	sv := &services{cfg: func() *Config { c, _ := h.srv.state(); return c }, auth: h.srv.auth, inner: g}
	h.srv.auth, h.srv.Approver = sv, sv

	if code, body := h.aws("prod", "token-a"); code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := h.aws("prod", "token-b"); code != 403 {
		t.Fatalf("open does not mean any group: %d", code)
	}
	if code, _ := h.aws("prod", "nope"); code != 401 {
		t.Fatalf("open does not mean without a token: %d", code)
	}
	// What is not open still waits for the approver, and asking for both
	// asks only for that one.
	req, _ := http.NewRequest("POST", h.broker.URL+"/requests", strings.NewReader(`{"credentials":["svc","aws:prod"]}`))
	req.Header.Set("Authorization", "Bearer token-a")
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != 200 {
		t.Fatalf("%v %v", r, err)
	}
	if asked := <-n.ch; len(asked.Credentials) != 1 || asked.Credentials[0] != "svc" {
		t.Fatalf("asked for %v", asked.Credentials)
	}
	if !h.audit.hasSSH("allowed", "aws-credentials", "") {
		t.Fatalf("the use of an open credential is not in the audit log: %+v", h.audit.events)
	}
	bad := next
	bad.Approval = &Approval{Durations: next.Approval.Durations, Open: []string{"aws:nope"}}
	if err := h.srv.SetConfig(&bad); err == nil {
		t.Fatal("an unknown open name was accepted")
	}
}

func TestExplicitOnlyNeverAsksOnUse(t *testing.T) {
	h, _ := awsHarness(t)
	cfg, _ := h.srv.state()
	next := *cfg
	next.Approval = &Approval{Durations: []Duration{Duration(time.Hour)}, ExplicitOnly: true}
	if err := h.srv.SetConfig(&next); err != nil {
		t.Fatal(err)
	}
	n := &notified{ch: make(chan Request, 10)}
	g := NewGrants(*next.Approval, n, h.audit)
	sv := &services{cfg: func() *Config { c, _ := h.srv.state(); return c }, auth: h.srv.auth, inner: g}
	h.srv.auth, h.srv.Approver = sv, sv

	// A use without a grant is refused and asks nobody.
	if code, body := h.aws("prod", "token-a"); code != 403 || !strings.Contains(body, "ask first") {
		t.Fatalf("%d %s", code, body)
	}
	if _, resp := h.tunnel(goodHost, "token-a"); resp.StatusCode != 403 {
		t.Fatalf("tunnel: %d", resp.StatusCode)
	}
	if len(n.ch) != 0 || len(g.Pending()) != 0 {
		t.Fatalf("%d notifications, %d pending", len(n.ch), len(g.Pending()))
	}
	// Asking is the only way; after the answer the use works.
	req, _ := http.NewRequest("POST", h.broker.URL+"/requests", strings.NewReader(`{"credentials":["aws:prod"],"duration":"1h"}`))
	req.Header.Set("Authorization", "Bearer token-a")
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != 200 {
		t.Fatalf("%v %v", r, err)
	}
	asked := <-n.ch
	if code, _ := h.aws("prod", "token-a"); code != 403 || len(n.ch) != 0 {
		t.Fatalf("while waiting: %d, %d more notifications", code, len(n.ch))
	}
	g.Decide(asked.ID, time.Hour, "test")
	if code, body := h.aws("prod", "token-a"); code != 200 {
		t.Fatalf("after the grant: %d %s", code, body)
	}
}

// With require_reason nothing is asked of the approver unless the client
// says why it wants each credential.
func TestRequireReasonRefusesARequestWithoutOne(t *testing.T) {
	h, _ := awsHarness(t)
	cfg, _ := h.srv.state()
	next := *cfg
	next.Approval = &Approval{Durations: []Duration{Duration(time.Hour)}, RequireReason: true}
	if err := h.srv.SetConfig(&next); err != nil {
		t.Fatal(err)
	}
	n := &notified{ch: make(chan Request, 10)}
	g := NewGrants(*next.Approval, n, h.audit)
	sv := &services{cfg: func() *Config { c, _ := h.srv.state(); return c }, auth: h.srv.auth, inner: g}
	h.srv.auth, h.srv.Approver = sv, sv
	ask := func(body string) (int, string) {
		req, _ := http.NewRequest("POST", h.broker.URL+"/requests", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer token-a")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(out)
	}

	// A use without a grant asks nobody, as with explicit_only.
	if code, body := h.aws("prod", "token-a"); code != 403 || !strings.Contains(body, "ask first") {
		t.Fatalf("%d %s", code, body)
	}
	for _, body := range []string{
		`{"credentials":["svc","aws:prod"],"duration":"1h"}`,
		`{"credentials":["svc","aws:prod"],"reasons":{"svc":"read the open pull request"}}`,
		`{"credentials":["svc","aws:prod"],"reasons":{"svc":"read the open pull request","aws:prod":"  x  "}}`,
	} {
		code, out := ask(body)
		if code != 400 || !strings.Contains(out, "missing for:") || !strings.Contains(out, "aws:prod") {
			t.Errorf("%s: %d %s", body, code, out)
		}
	}
	if len(n.ch) != 0 || len(g.Pending()) != 0 {
		t.Fatalf("%d notifications, %d pending", len(n.ch), len(g.Pending()))
	}
	code, out := ask(`{"credentials":["svc","aws:prod"],"reasons":{"svc":"read the open pull request","aws:prod":"list the buckets of the backup"}}`)
	if code != 200 || !strings.Contains(out, `"request"`) {
		t.Fatalf("%d %s", code, out)
	}
	if req := <-n.ch; len(req.Reasons) != 2 {
		t.Fatalf("reasons = %v", req.Reasons)
	}
}

// An account with an MFA device is granted only with the one-time code the
// approver types. The session is opened once, at the approval, and the
// grant ends with it.
func TestAWSAccountWithMFANeedsTheCodeOfTheApprover(t *testing.T) {
	h, calls := awsHarness(t)
	cfg, _ := h.srv.state()
	next := *cfg
	next.AWS = []AWSAccount{{Name: "audit", Groups: []string{"team-a"}, RoleARN: "arn:aws:iam::123456789012:role/read-only",
		MFASerial: "arn:aws:iam::123456789012:mfa/key-1", MaxDuration: Duration(time.Hour)}}
	next.Approval = &Approval{Durations: []Duration{Duration(4 * time.Hour)}}
	if err := h.srv.SetConfig(&next); err != nil {
		t.Fatal(err)
	}
	h.store.m["audit"] = Secret{Value: []byte(awsKeyID + ":" + awsSecretKey), Hosts: []string{"sts.us-east-1.amazonaws.com"}}
	n := &notified{ch: make(chan Request, 10)}
	g := NewGrants(*next.Approval, n, h.audit)
	g.CodeHooks(h.srv.needsCode, h.srv.unlockWithCode)
	h.srv.Approver = g

	// The use asks the approver; the request says it needs a code.
	if code, _ := h.aws("audit", "token-a"); code != 403 {
		t.Fatalf("before the grant: %d", code)
	}
	req := <-n.ch
	if len(req.NeedsCode) != 1 || req.NeedsCode[0] != "aws:audit" {
		t.Fatalf("needs code = %v", req.NeedsCode)
	}
	// Without the code, or with something that is not one, nothing is granted
	// and the request keeps waiting.
	c := &Control{Grants: g}
	for _, args := range [][]string{
		{"approve", req.ID, "4h"},
		{"approve", req.ID, "4h", "aws:audit=abc"},
		{"approve", req.ID, "4h", "other=123456"},
	} {
		if out, err := c.run(args, nil); err == nil {
			t.Fatalf("%v: %s", args, out)
		}
	}
	if err := g.Decide(req.ID, 4*time.Hour, "a button"); err == nil {
		t.Fatal("granted without a code")
	}
	if len(g.Pending()) != 1 || len(*calls) != 0 || g.Granted("agent-a", "aws:audit") {
		t.Fatalf("%d pending, %d STS calls", len(g.Pending()), len(*calls))
	}
	// With the code, the broker opens the session then and there.
	if out, err := c.run([]string{"approve", req.ID, "4h", "aws:audit=123456"}, nil); err != nil {
		t.Fatalf("%s %v", out, err)
	}
	if len(*calls) != 1 {
		t.Fatalf("%d STS calls", len(*calls))
	}
	form := (*calls)[0]
	if form.Get("Action") != "AssumeRole" || form.Get("SerialNumber") != "arn:aws:iam::123456789012:mfa/key-1" ||
		form.Get("TokenCode") != "123456" || form.Get("DurationSeconds") != "3600" {
		t.Fatalf("STS call = %v", form)
	}
	// The grant asked for was 4 h; it ends with the session, in 1 h.
	grants := g.Active()
	if len(grants) != 1 || time.Until(grants[0].Until) > time.Hour+time.Minute {
		t.Fatalf("grants = %+v", grants)
	}
	// The client gets that session, and asking again opens no other.
	for range 2 {
		code, body := h.aws("audit", "token-a")
		if code != 200 || !strings.Contains(body, "ASIATEMP") {
			t.Fatalf("%d %s", code, body)
		}
	}
	if len(*calls) != 1 {
		t.Fatalf("%d STS calls after two uses", len(*calls))
	}
	// When the session is gone the broker cannot open another on its own.
	h.srv.forget()
	if code, body := h.aws("audit", "token-a"); code != 403 || !strings.Contains(body, "ask again") {
		t.Fatalf("after the session: %d %s", code, body)
	}
	if len(*calls) != 1 {
		t.Fatalf("%d STS calls", len(*calls))
	}
}

// A name may be a path. It is then used whole in grants and requests,
// without the kind in front, and the HTTP paths take it as it is.
func TestPathNamesAreUsedWhole(t *testing.T) {
	if grantName("ssh", "web") != "ssh:web" || grantName("ssh", "team/ssh/web/shell") != "team/ssh/web/shell" || grantName("", "svc") != "svc" {
		t.Fatal("grantName")
	}
	h, calls := awsHarness(t)
	cfg, _ := h.srv.state()
	next := *cfg
	next.AWS = []AWSAccount{{Name: "team/aws/prod/read-only", Secret: "prod", Groups: []string{"team-a"}}}
	next.Approval = &Approval{Durations: []Duration{Duration(time.Hour)}}
	if err := h.srv.SetConfig(&next); err != nil {
		t.Fatal(err)
	}
	n := &notified{ch: make(chan Request, 10)}
	g := NewGrants(*next.Approval, n, h.audit)
	g.CodeHooks(h.srv.needsCode, h.srv.unlockWithCode)
	h.srv.Approver = g

	req, _ := http.NewRequest("GET", h.broker.URL+"/grants", nil)
	req.Header.Set("Authorization", "Bearer token-a")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	listing, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(listing), `"team/aws/prod/read-only"`) || strings.Contains(string(listing), "aws:team") {
		t.Fatalf("catalog = %s", listing)
	}
	if code, _ := h.aws("team/aws/prod/read-only", "token-a"); code != 403 {
		t.Fatalf("before the grant: %d", code)
	}
	asked := <-n.ch
	if asked.Credential != "team/aws/prod/read-only" {
		t.Fatalf("asked for %q", asked.Credential)
	}
	g.Decide(asked.ID, time.Hour, "test")
	if code, body := h.aws("team/aws/prod/read-only", "token-a"); code != 200 || len(*calls) != 1 {
		t.Fatalf("after the grant: %d %s, %d STS calls", code, body, len(*calls))
	}
	if !cfg.known("svc") || !next.known("team/aws/prod/read-only") || next.known("aws:team/aws/prod/read-only") {
		t.Error("known")
	}

	// A path needs its secret named, and no two things share a name.
	bad := next
	bad.AWS = []AWSAccount{{Name: "team/aws/prod/read-only", Groups: []string{"team-a"}}}
	if err := h.srv.SetConfig(&bad); err == nil || !strings.Contains(err.Error(), "needs \"secret\"") {
		t.Errorf("path without secret: %v", err)
	}
	twice := next
	twice.Commands = []Command{{Name: "team/aws/prod/read-only", Groups: []string{"team-a"}, Start: []string{"/bin/true"}, Stop: []string{"/bin/true"}}}
	twice.CommandsDir = t.TempDir()
	if err := h.srv.SetConfig(&twice); err == nil || !strings.Contains(err.Error(), "more than one thing") {
		t.Errorf("same name twice: %v", err)
	}
}

// The explanation STS gives with a refusal reaches the approver: it tells a
// wrong one-time code from a wrong device serial.
func TestSTSErrorCarriesTheMessage(t *testing.T) {
	rt := rtFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			"<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>MultiFactorAuthentication failed,\n unable to validate MFA code.  Please verify your MFA serial number is valid &amp; associated with this user.</Message></Error></ErrorResponse>"))}, nil
	})
	acct := &AWSAccount{Name: "audit", MFASerial: "arn:aws:iam::123456789012:mfa/key-1"}
	_, err := stsSession(context.Background(), rt, acct, awsKeyID, awsSecretKey, time.Hour, "agent-a", "123456", time.Now())
	want := "STS answered 403 (AccessDenied: MultiFactorAuthentication failed, unable to validate MFA code. Please verify your MFA serial number is valid & associated with this user.)"
	if err == nil || err.Error() != want {
		t.Fatalf("%v", err)
	}
	if got := stsErrorMessage([]byte("<Error><Code>Throttling</Code></Error>")); got != "" {
		t.Fatalf("%q", got)
	}
}
