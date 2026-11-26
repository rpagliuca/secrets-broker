package broker

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func scopedCredential() Credential {
	return Credential{
		Name: "svc", Hosts: []string{goodHost}, Groups: []string{"team-a"}, Scheme: "bearer",
		Scopes: []Scope{
			{Name: "team/repo/{repo}/read-and-comment", Rules: []ScopeRule{
				{Methods: []string{"GET", "HEAD"}, Paths: []string{"/repos/team/{repo}/**"}},
				{Methods: []string{"POST"}, Paths: []string{"/repos/team/{repo}/pulls/*/comments"}},
			}},
			{Name: "team/tracker/{project}/read", Rules: []ScopeRule{
				{Methods: []string{"GET"}, Paths: []string{"/issue/{project}-*", "/project/{project}"}},
			}},
		},
	}
}

// grant gives agent-a the names, as the approver would.
func grant(t *testing.T, g *Grants, names ...string) {
	t.Helper()
	id, err := g.Request(Principal{ID: "agent-a", Groups: []string{"team-a"}}, names, []string{goodHost}, 0, nil)
	if err != nil || id == "" {
		t.Fatalf("request: %q %v", id, err)
	}
	if err := g.Decide(id, time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
}

// raw sends one request line through a tunnel, untouched by any client
// library, and returns the status.
func raw(t *testing.T, h *harness, method, uri string) int {
	t.Helper()
	conn, resp := h.tunnel(goodHost, "token-a")
	if resp.StatusCode != 200 {
		return resp.StatusCode
	}
	tc := tls.Client(conn, &tls.Config{ServerName: goodHost, RootCAs: h.caPool()})
	fmt.Fprintf(tc, "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", method, uri, goodHost)
	inner, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, inner.Body)
	inner.Body.Close()
	return inner.StatusCode
}

func TestScopeAllowsOnlyItsPaths(t *testing.T) {
	h := newHarness(t, scopedCredential(), func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	g, c, _, _ := newTestGrants()
	h.srv.Approver = g

	if code := raw(t, h, "GET", "/repos/team/web/src"); code != http.StatusForbidden {
		t.Fatalf("without a grant: %d, want 403", code)
	}
	grant(t, g, "team/repo/web/read-and-comment", "team/tracker/ops/read")

	cases := []struct {
		method, uri string
		want        int
	}{
		{"GET", "/repos/team/web", 200},
		{"GET", "/repos/team/web/src/main/README.md?at=x", 200},
		{"GET", "/repos/team/WEB/pulls", 200}, // parameters ignore case
		{"HEAD", "/repos/team/web/src", 200},
		{"POST", "/repos/team/web/pulls/7/comments", 200},
		{"GET", "/issue/OPS-12", 200},
		{"GET", "/project/ops", 200},

		{"GET", "/repos/team/other/src", 403},
		{"GET", "/repos/team/web-other/src", 403},
		{"GET", "/repos/team", 403},
		{"GET", "/repos/team/", 403},
		{"POST", "/repos/team/web/pulls/7/merge", 403},
		{"POST", "/repos/team/web/pulls/7/comments/extra", 403},
		{"DELETE", "/repos/team/web/src", 403},
		{"PUT", "/repos/team/web", 403},
		{"GET", "/issue/OTHER-1", 403},
		{"GET", "/issue/OPSX-1", 403},
		{"GET", "/search?jql=project%3DOPS", 403},

		// Forms the service might read otherwise than the broker.
		{"GET", "/repos/team/web/../other/src", 403},
		{"GET", "/repos/team/web/./src", 403},
		{"GET", "/repos/team/web%2F..%2Fother/src", 403},
		{"GET", "/repos/team/web/%2e%2e/other", 403},
		{"GET", "/repos/team/web/..;/other", 403},
		{"GET", "/repos/team/web;x=1/src", 403},
		{"GET", "/repos/team/web//src", 403},
		{"GET", "/repos/team/web/%252e%252e/other", 403},
		{"GET", `/repos/team/web/..\other`, 403},
	}
	for _, tc := range cases {
		if code := raw(t, h, tc.method, tc.uri); code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.uri, code, tc.want)
		}
	}
	for _, r := range h.good.requests() {
		if strings.Contains(r.URI, "other") || strings.Contains(r.URI, "..") || r.Method == "DELETE" {
			t.Errorf("reached the service: %s %s", r.Method, r.URI)
		}
	}
	allowed := 0
	for _, ev := range h.audit.events {
		if ev.Decision == "allowed" {
			allowed++
			if ev.Scope == "" {
				t.Errorf("allowed event without its scope: %+v", ev)
			}
		}
	}
	if allowed != 7 {
		t.Errorf("%d allowed events, want 7", allowed)
	}

	// The grant ends: nothing more, inside or outside the scope.
	c.advance(time.Hour)
	if code := raw(t, h, "GET", "/repos/team/web/src"); code != http.StatusForbidden {
		t.Errorf("after the grant ended: %d, want 403", code)
	}
}

func TestGrantOfTheCredentialStillAllowsEverything(t *testing.T) {
	h := newHarness(t, scopedCredential(), nil)
	g, _, _, _ := newTestGrants()
	h.srv.Approver = g
	grant(t, g, "svc")
	for _, uri := range []string{"/repos/team/other/src", "/search?jql=x", "/a//b"} {
		if code := raw(t, h, "DELETE", uri); code != 200 {
			t.Errorf("DELETE %s = %d, want 200", uri, code)
		}
	}
}

func TestProxyUserMayNameAScope(t *testing.T) {
	cfg := &Config{Credentials: []Credential{scopedCredential()}}
	if cr, reason := cfg.credentialFor(goodHost, []string{"team-a"}, "team/repo/web/read-and-comment"); cr == nil {
		t.Fatalf("scope name as proxy user: %s", reason)
	}
	if cr, _ := cfg.credentialFor(goodHost, []string{"team-b"}, "team/repo/web/read-and-comment"); cr != nil {
		t.Fatal("a scope of another group was chosen")
	}
}

func TestScopeNamesInRequests(t *testing.T) {
	cfg := &Config{Credentials: []Credential{scopedCredential()}}
	groups := []string{"team-a"}
	for name, want := range map[string]bool{
		"svc":                               true,
		"team/repo/web/read-and-comment":    true,
		"team/repo/{repo}/read-and-comment": false, // the pattern is not a name
		"team/repo/Web/read-and-comment":    false,
		"team/repo/../read-and-comment":     false,
		"team/repo/a/b/read-and-comment":    false,
		"team/repo/web/write":               false,
	} {
		if _, ok := cfg.lookup(groups, name); ok != want {
			t.Errorf("lookup(%q) = %t, want %t", name, ok, want)
		}
	}
	if _, ok := cfg.lookup([]string{"team-b"}, "team/repo/web/read-and-comment"); ok {
		t.Error("a scope of another group may be asked for")
	}
	if !slices.Contains(cfg.catalog(groups)["team/repo/{repo}/read-and-comment"], goodHost) {
		t.Error("the catalog does not list the scope pattern")
	}
}

func TestScopeValidation(t *testing.T) {
	rule := []ScopeRule{{Methods: []string{"GET"}, Paths: []string{"/r/{repo}/**"}}}
	bad := map[string]func(cr *Credential){
		"no rules": func(cr *Credential) { cr.Scopes = []Scope{{Name: "t/{repo}"}} },
		"rule without paths": func(cr *Credential) {
			cr.Scopes = []Scope{{Name: "t/x", Rules: []ScopeRule{{Methods: []string{"GET"}}}}}
		},
		"TRACE": func(cr *Credential) {
			cr.Scopes = []Scope{{Name: "t/x", Rules: []ScopeRule{{Methods: []string{"TRACE"}, Paths: []string{"/"}}}}}
		},
		"unused parameter":  func(cr *Credential) { cr.Scopes = []Scope{{Name: "t/{repo}/{other}", Rules: rule}} },
		"undeclared param":  func(cr *Credential) { cr.Scopes = []Scope{{Name: "t/x", Rules: rule}} },
		"parameter twice":   func(cr *Credential) { cr.Scopes = []Scope{{Name: "t/{repo}/{repo}", Rules: rule}} },
		"part of a segment": func(cr *Credential) { cr.Scopes = []Scope{{Name: "t/r-{repo}", Rules: rule}} },
		"relative path": func(cr *Credential) {
			cr.Scopes = []Scope{{Name: "t/{repo}", Rules: []ScopeRule{{Methods: []string{"GET"}, Paths: []string{"r/{repo}"}}}}}
		},
		"** in the middle": func(cr *Credential) {
			cr.Scopes = []Scope{{Name: "t/{repo}", Rules: []ScopeRule{{Methods: []string{"GET"}, Paths: []string{"/**/{repo}"}}}}}
		},
		"empty segment": func(cr *Credential) {
			cr.Scopes = []Scope{{Name: "t/{repo}", Rules: []ScopeRule{{Methods: []string{"GET"}, Paths: []string{"/r//{repo}"}}}}}
		},
		"method of the cred": func(cr *Credential) {
			cr.Methods = []string{"GET"}
			cr.Scopes = []Scope{{Name: "t/{repo}", Rules: []ScopeRule{{Methods: []string{"POST"}, Paths: []string{"/r/{repo}"}}}}}
		},
		"same as credential": func(cr *Credential) { cr.Scopes = []Scope{{Name: "{repo}", Rules: rule}} },
		"overlapping scopes": func(cr *Credential) {
			cr.Scopes = []Scope{{Name: "t/{repo}", Rules: rule}, {Name: "t/web", Rules: []ScopeRule{{Methods: []string{"GET"}, Paths: []string{"/"}}}}}
		},
		"upper-case segment":  func(cr *Credential) { cr.Scopes = []Scope{{Name: "T/{repo}", Rules: rule}} },
		"trailing slash name": func(cr *Credential) { cr.Scopes = []Scope{{Name: "t/{repo}/", Rules: rule}} },
	}
	for name, mutate := range bad {
		cr := Credential{Name: "svc", Hosts: []string{"api.example.com"}, Groups: []string{"g"}, Scheme: "bearer"}
		mutate(&cr)
		if err := (&Config{Credentials: []Credential{cr}}).Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := scopedCredential()
	if err := (&Config{Credentials: []Credential{good}}).Validate(); err != nil {
		t.Fatalf("scoped credential: %v", err)
	}
	// A scope must not answer to the name of something else.
	other := Credential{Name: "team/repo/web/read-and-comment", Secret: "other", Hosts: []string{"b.example.com"}, Groups: []string{"g"}, Scheme: "bearer"}
	clash := &Config{Credentials: []Credential{good, other}}
	if err := clash.Validate(); err == nil {
		t.Error("a scope that answers to the name of another credential was accepted")
	}
}
