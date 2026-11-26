package broker

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"crypto"
)

func githubAppHarness(t *testing.T) (*harness, *rsa.PrivateKey, *[]map[string]any) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cred := Credential{
		Name: "team/github/{repo}/write", Secret: "app", Hosts: []string{goodHost}, Groups: []string{"team-a"}, Scheme: "github_app",
		GitHubApp: &GitHubApp{AppID: "12345", InstallationID: 678, Permissions: map[string]string{"contents": "write"}, APIHost: goodHost},
	}
	var asked []map[string]any
	n := 0
	var h *harness
	h = newHarness(t, cred, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/678/access_tokens" {
			if r.Method != http.MethodPost || !validJWT(r.Header.Get("Authorization"), &key.PublicKey) {
				w.WriteHeader(401)
				io.WriteString(w, `{"message":"bad JWT"}`)
				return
			}
			var in map[string]any
			seen := h.good.requests()
			json.Unmarshal([]byte(seen[len(seen)-1].Body), &in)
			asked = append(asked, in)
			n++
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"token": "ghs_installation-token-" + strings.Repeat("x", n), "expires_at": time.Now().Add(time.Hour)})
			return
		}
		if r.URL.Path == "/echo" {
			io.WriteString(w, r.Header.Get("Authorization"))
			return
		}
		io.WriteString(w, "ok")
	})
	h.store.m["app"] = Secret{Value: keyPEM, Hosts: []string{goodHost}}
	return h, key, &asked
}

func validJWT(authz string, pub *rsa.PublicKey) bool {
	jwt, ok := strings.CutPrefix(authz, "Bearer ")
	parts := strings.Split(jwt, ".")
	if !ok || len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
		return false
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Iss      string
		Iat, Exp int64
	}
	return json.Unmarshal(raw, &c) == nil && c.Iss == "12345" && c.Exp-c.Iat <= 600 && c.Exp > time.Now().Unix()
}

func (h *harness) namedGet(name, token, path string) (int, string) {
	h.t.Helper()
	proxy, _ := url.Parse(h.broker.URL)
	proxy.User = url.UserPassword(name, token)
	tr := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: h.caPool()}}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr}
	resp, err := c.Get("https://" + goodHost + path)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestGitHubAppTokenForTheNamedRepository(t *testing.T) {
	h, _, asked := githubAppHarness(t)
	lastAuthz := func() string { r := h.good.requests(); return r[len(r)-1].Authorization }
	code, body := h.namedGet("team/github/broker/write", "token-a", "/repos/o/broker")
	if code != 200 || lastAuthz() != "Bearer ghs_installation-token-x" {
		t.Fatalf("%d %q %q", code, body, lastAuthz())
	}
	if len(*asked) != 1 {
		t.Fatalf("%d token requests", len(*asked))
	}
	got, _ := json.Marshal((*asked)[0])
	if string(got) != `{"permissions":{"contents":"write"},"repositories":["broker"]}` {
		t.Fatalf("token asked for %s", got)
	}
	// Reused while valid, per repository.
	h.namedGet("team/github/broker/write", "token-a", "/")
	if len(*asked) != 1 {
		t.Fatalf("%d token requests, want the token reused", len(*asked))
	}
	if code, body := h.namedGet("team/github/other/write", "token-a", "/"); code != 200 || lastAuthz() != "Bearer ghs_installation-token-xx" {
		t.Fatalf("other repository: %d %q", code, body)
	}
	// The audit log names the repository.
	if !h.audit.hasCredential("team/github/other/write") {
		t.Fatal("audit log without the resolved name")
	}
}

func TestGitHubAppNamesAndGroups(t *testing.T) {
	h, _, asked := githubAppHarness(t)
	for _, name := range []string{"team/github/{repo}/write", "team/github/a/b/write", "team/github/Broker/write", "team/github/x.git/write", "team/github//write"} {
		before := len(*asked)
		if code, _ := h.namedGet(name, "token-a", "/"); code == 200 || len(*asked) != before {
			t.Errorf("%q served", name)
		}
	}
	if code, _ := h.namedGet("team/github/broker/write", "token-b", "/"); code == 200 {
		t.Error("served to another group")
	}
	// Without a name the template serves nobody.
	if code, _ := h.namedGet("agent", "token-a", "/"); code == 200 {
		t.Error("served without a name")
	}
	if len(*asked) != 0 {
		t.Fatalf("%d token requests", len(*asked))
	}
}

func TestGitHubAppTokenNeverReachesTheClient(t *testing.T) {
	h, _, _ := githubAppHarness(t)
	h.good.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/access_tokens") {
			w.WriteHeader(201)
			io.WriteString(w, `{"token":"ghs_installation-token-x","expires_at":"2099-01-01T00:00:00Z"}`)
			return
		}
		io.WriteString(w, "echo "+r.Header.Get("Authorization"))
	})
	if code, body := h.namedGet("team/github/broker/write", "token-a", "/"); strings.Contains(body, "ghs_") || code == 200 {
		t.Fatalf("%d %q", code, body)
	}
}

func TestGitHubAppOnTheGitHost(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cred := &Credential{Name: "r", GitHubApp: &GitHubApp{AppID: "1", InstallationID: 2, Permissions: map[string]string{"contents": "read"}}}
	s := &Server{oauthCache: map[string]oauthToken{}}
	s.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://api.github.com/app/installations/2/access_tokens" {
			t.Errorf("asked %s", r.URL)
		}
		return answer(201, `{"token":"ghs_0123456789abcdef","expires_at":"2099-01-01T00:00:00Z"}`), nil
	})
	sec := Secret{Value: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), Hosts: []string{"api.github.com", "github.com"}}
	authz, needles, err := s.githubAppAuthorization(t.Context(), cred, sec, "github.com")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_0123456789abcdef"))
	if err != nil || authz != want || !containsAny([]byte(want), needles) {
		t.Fatalf("%q %v", authz, err)
	}
	// A key not bound to the API host is never used.
	sec.Hosts = []string{"github.com"}
	if _, _, err := s.githubAppAuthorization(t.Context(), &Credential{Name: "other", GitHubApp: cred.GitHubApp}, sec, "github.com"); err == nil {
		t.Fatal("key used without its API host")
	}
}

func TestGitHubAppConfigValidation(t *testing.T) {
	app := func() *GitHubApp {
		return &GitHubApp{AppID: "1", InstallationID: 2, Permissions: map[string]string{"contents": "read"}}
	}
	ok := Credential{Name: "g/{repo}/read", Secret: "app", Hosts: []string{"api.github.com", "github.com"}, Groups: []string{"a"}, Scheme: "github_app", GitHubApp: app()}
	if err := (&Config{Credentials: []Credential{ok}}).Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(c *Credential){
		"no app":             func(c *Credential) { c.GitHubApp = nil },
		"no permissions":     func(c *Credential) { c.GitHubApp.Permissions = nil },
		"bad permission":     func(c *Credential) { c.GitHubApp.Permissions = map[string]string{"contents": "all"} },
		"api host not bound": func(c *Credential) { c.Hosts = []string{"github.com"} },
		"placeholder inside": func(c *Credential) { c.Name = "g/x{repo}/read" },
		"two placeholders":   func(c *Credential) { c.Name = "g/{repo}/{repo}" },
		"list and template":  func(c *Credential) { c.GitHubApp.Repositories = []string{"a"} },
		"no secret":          func(c *Credential) { c.Secret = "" },
		"template not app":   func(c *Credential) { c.Scheme, c.GitHubApp = "bearer", nil },
		"default":            func(c *Credential) { c.Default = true },
	}
	for what, change := range bad {
		c := ok
		c.GitHubApp = app()
		change(&c)
		if err := (&Config{Credentials: []Credential{c}}).Validate(); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
	// Names that meet are refused.
	concrete := Credential{Name: "g/x/read", Secret: "s", Hosts: []string{"example.com"}, Groups: []string{"a"}, Scheme: "bearer"}
	if err := (&Config{Credentials: []Credential{ok, concrete}}).Validate(); err == nil {
		t.Error("a template name that is another credential's name was accepted")
	}
	other := ok
	other.Name, other.GitHubApp = "g/{repo}", app()
	if err := (&Config{Credentials: []Credential{ok, other}}).Validate(); err == nil {
		t.Error("overlapping templates accepted")
	}
	write := ok
	write.Name, write.GitHubApp = "g/{repo}/write", app()
	if err := (&Config{Credentials: []Credential{ok, write}}).Validate(); err != nil {
		t.Errorf("read and write templates: %v", err)
	}
}

func (r *recorder) hasCredential(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ev := range r.events {
		if ev.Credential == name && ev.Decision == "allowed" {
			return true
		}
	}
	return false
}

func TestGitHubAppNamesAreAskedForAndGranted(t *testing.T) {
	h, _, _ := githubAppHarness(t)
	n := &notified{ch: make(chan Request, 10)}
	g := NewGrants(Approval{Durations: []Duration{Duration(time.Hour)}, ExplicitOnly: true}, n, h.audit)
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
	if _, body := call("GET", "/grants", ""); !strings.Contains(body, `"team/github/{repo}/write"`) {
		t.Fatalf("catalog: %s", body)
	}
	if code, _ := call("POST", "/requests", `{"credentials":["team/github/a/b/write"]}`); code != 400 {
		t.Fatalf("invalid repository name: %d", code)
	}
	if code, body := call("POST", "/requests", `{"credentials":["team/github/broker/write"],"duration":"1h"}`); code != 200 || !strings.Contains(body, `"request"`) {
		t.Fatalf("%d %s", code, body)
	}
	req := <-n.ch
	if req.Credential != "team/github/broker/write" {
		t.Fatalf("request = %+v", req)
	}
	if code, _ := h.namedGet("team/github/broker/write", "token-a", "/"); code == 200 {
		t.Fatalf("before the grant: %d", code)
	}
	g.Decide(req.ID, time.Hour, "test")
	if code, _ := h.namedGet("team/github/broker/write", "token-a", "/"); code != 200 {
		t.Fatalf("after the grant: %d", code)
	}
	// The grant is for that repository only.
	if code, _ := h.namedGet("team/github/other/write", "token-a", "/"); code == 200 {
		t.Fatalf("another repository: %d", code)
	}
}
