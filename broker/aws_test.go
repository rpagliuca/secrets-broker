package broker

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
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
