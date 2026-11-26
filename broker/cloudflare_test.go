package broker

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	cfMaster  = "cf-master-token-value"
	cfAccount = "0123456789abcdef0123456789abcdef"
	cfGroup   = "4755a26eedb94da69e1066d98aa820be"
	cfZone    = "fedcba9876543210fedcba9876543210"
)

// fakeCloudflare is the token API of Cloudflare: it issues and deletes
// tokens for the master token, and answers other calls with the bearer it
// received.
type fakeCloudflare struct {
	mu      sync.Mutex
	created []map[string]any
	live    map[string]string // id -> value
	deleted []string
	n       int
}

func cfHarness(t *testing.T, mutate func(*Credential)) (*harness, *fakeCloudflare) {
	t.Helper()
	cred := Credential{
		Name: "team/cloudflare/zone/dns-edit", Secret: "cf", Hosts: []string{goodHost}, Groups: []string{"team-a"},
		Scheme: "cloudflare_token",
		Cloudflare: &CloudflareToken{
			AccountID: cfAccount, APIHost: goodHost,
			Policies: []json.RawMessage{json.RawMessage(`{"effect":"allow","resources":{"com.cloudflare.api.account.zone.` + cfZone + `":"*"},"permission_groups":[{"id":"` + cfGroup + `"}]}`)},
		},
	}
	if mutate != nil {
		mutate(&cred)
	}
	f := &fakeCloudflare{live: map[string]string{}}
	var h *harness
	tokens := "/client/v4/accounts/" + cfAccount + "/tokens"
	h = newHarness(t, cred, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		authz := r.Header.Get("Authorization")
		switch {
		case r.URL.Path == tokens && r.Method == http.MethodPost:
			if authz != "Bearer "+cfMaster {
				w.WriteHeader(403)
				io.WriteString(w, `{"success":false,"errors":[{"code":9109,"message":"Unauthorized"}]}`)
				return
			}
			// The origin has read the body already, to record it.
			var in map[string]any
			seen := h.good.requests()
			json.Unmarshal([]byte(seen[len(seen)-1].Body), &in)
			f.created = append(f.created, in)
			f.n++
			id := fmt.Sprintf("%032x", f.n)
			f.live[id] = fmt.Sprintf("issued-token-%d-%s", f.n, strings.Repeat("v", 20))
			json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": map[string]any{"id": id, "value": f.live[id]}})
		case strings.HasPrefix(r.URL.Path, tokens+"/") && r.Method == http.MethodDelete:
			id := strings.TrimPrefix(r.URL.Path, tokens+"/")
			if authz != "Bearer "+cfMaster || f.live[id] == "" {
				w.WriteHeader(404)
				io.WriteString(w, `{"success":false,"errors":[{"code":1003,"message":"not found"}]}`)
				return
			}
			delete(f.live, id)
			f.deleted = append(f.deleted, id)
			io.WriteString(w, `{"success":true,"errors":[],"result":{"id":"`+id+`"}}`)
		case r.URL.Path == "/echo":
			io.WriteString(w, authz)
		default:
			io.WriteString(w, `{"success":true,"result":{"bearer":"`+strings.TrimPrefix(authz, "Bearer ")[:6]+`"}}`)
		}
	})
	h.store.m["cf"] = Secret{Value: []byte(cfMaster + "\n"), Hosts: []string{goodHost}}
	return h, f
}

func (f *fakeCloudflare) counts() (created, live, deleted int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.created), len(f.live), len(f.deleted)
}

func TestCloudflareIssuesOneTokenPerClient(t *testing.T) {
	h, f := cfHarness(t, func(c *Credential) { c.Groups = []string{"team-a", "team-b"} })
	last := func() string { r := h.good.requests(); return r[len(r)-1].Authorization }
	code, body := h.namedGet("agent", "token-a", "/client/v4/zones")
	if code != 200 || last() != "Bearer issued-token-1-"+strings.Repeat("v", 20) {
		t.Fatalf("%d %q %q", code, body, last())
	}
	h.namedGet("agent", "token-a", "/client/v4/zones")
	if c, _, _ := f.counts(); c != 1 {
		t.Fatalf("%d tokens created, want the first reused", c)
	}
	h.namedGet("agent", "token-b", "/client/v4/zones")
	if c, _, _ := f.counts(); c != 2 || !strings.HasPrefix(last(), "Bearer issued-token-2-") {
		t.Fatalf("another client: %d tokens, %q", c, last())
	}
	// What was asked for: the policies of the credential, an expiry, a name
	// that says who it is for.
	in := f.created[0]
	pol, _ := json.Marshal(in["policies"])
	if !strings.Contains(string(pol), cfZone) || !strings.Contains(string(pol), cfGroup) {
		t.Fatalf("policies %s", pol)
	}
	end, err := time.Parse(time.RFC3339, in["expires_on"].(string))
	if err != nil || time.Until(end) > time.Hour || time.Until(end) < 50*time.Minute {
		t.Fatalf("expires_on %v", in["expires_on"])
	}
	if name, _ := in["name"].(string); !strings.Contains(name, "team/cloudflare/zone/dns-edit") || !strings.Contains(name, "agent-a") {
		t.Fatalf("name %q", name)
	}
	if !h.audit.has("allowed", "issued ") {
		t.Fatal("no audit event for the creation")
	}
}

func TestCloudflareMasterNeverReachesTheClient(t *testing.T) {
	h, _ := cfHarness(t, nil)
	h.namedGet("agent", "token-a", "/client/v4/zones")
	for _, r := range h.good.requests() {
		if r.URI != "/client/v4/accounts/"+cfAccount+"/tokens" && strings.Contains(r.Authorization, cfMaster) {
			t.Fatalf("master token sent on a client request: %+v", r)
		}
	}
	// A response that echoes the issued token is cut.
	if code, body := h.namedGet("agent", "token-a", "/echo"); code == 200 || strings.Contains(body, "issued-token") {
		t.Fatalf("%d %q", code, body)
	}
}

func TestCloudflareTokenEndsWithTheGrant(t *testing.T) {
	h, f := cfHarness(t, nil)
	g := NewGrants(Approval{Durations: []Duration{Duration(10 * time.Minute)}, ExplicitOnly: true}, &notified{ch: make(chan Request, 10)}, h.audit)
	h.srv.Approver = g
	id, err := g.Request(Principal{ID: "agent-a", Groups: []string{"team-a"}}, []string{"team/cloudflare/zone/dns-edit"}, []string{goodHost}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	g.Decide(id, 10*time.Minute, "test")
	if code, body := h.namedGet("agent", "token-a", "/client/v4/zones"); code != 200 {
		t.Fatalf("%d %q", code, body)
	}
	end, _ := time.Parse(time.RFC3339, f.created[0]["expires_on"].(string))
	if until := g.Until("agent-a", "team/cloudflare/zone/dns-edit"); end.After(until) || until.Sub(end) > time.Second {
		t.Fatalf("token ends %v, grant %v", end, until)
	}
	// While the grant lasts, the sweep keeps it.
	h.srv.SweepIssued(t.Context(), false)
	if _, live, _ := f.counts(); live != 1 {
		t.Fatalf("%d live tokens", live)
	}
	g.Revoke("agent-a", "test")
	h.srv.SweepIssued(t.Context(), false)
	if _, live, deleted := f.counts(); live != 0 || deleted != 1 {
		t.Fatalf("after revoke: %d live, %d deleted", live, deleted)
	}
	if !h.audit.has("allowed", "grant ended: deleted") {
		t.Fatal("no audit event for the deletion")
	}
	if code, _ := h.namedGet("agent", "token-a", "/client/v4/zones"); code == 200 {
		t.Fatal("served after the revoke")
	}
}

func TestCloudflareRenewsAndDeletesTheOld(t *testing.T) {
	h, f := cfHarness(t, nil)
	h.namedGet("agent", "token-a", "/client/v4/zones")
	// Two minutes before its end, the token is due for renewal.
	h.srv.cacheMu.Lock()
	for k, tok := range h.srv.cfCache {
		tok.expires = time.Now().Add(2 * time.Minute)
		h.srv.cfCache[k] = tok
	}
	h.srv.cacheMu.Unlock()
	h.namedGet("agent", "token-a", "/client/v4/zones")
	if c, live, deleted := f.counts(); c != 2 || live != 1 || deleted != 1 {
		t.Fatalf("created %d, live %d, deleted %d", c, live, deleted)
	}
}

func TestCloudflareShortGrantIsNotRenewedOnEveryRequest(t *testing.T) {
	h, f := cfHarness(t, nil)
	g := NewGrants(Approval{Durations: []Duration{Duration(4 * time.Minute)}, ExplicitOnly: true}, &notified{ch: make(chan Request, 10)}, h.audit)
	h.srv.Approver = g
	id, _ := g.Request(Principal{ID: "agent-a", Groups: []string{"team-a"}}, []string{"team/cloudflare/zone/dns-edit"}, []string{goodHost}, 0, nil)
	g.Decide(id, 4*time.Minute, "test")
	for range 3 {
		if code, body := h.namedGet("agent", "token-a", "/client/v4/zones"); code != 200 {
			t.Fatalf("%d %q", code, body)
		}
	}
	if c, _, _ := f.counts(); c != 1 {
		t.Fatalf("%d tokens created for a grant shorter than the renewal margin", c)
	}
}

func TestCloudflareReloadAndStopDeleteTokens(t *testing.T) {
	h, f := cfHarness(t, nil)
	h.namedGet("agent", "token-a", "/client/v4/zones")
	cfg, _ := h.srv.state()
	changed := *cfg
	changed.Credentials = append([]Credential(nil), cfg.Credentials...)
	cf := *changed.Credentials[0].Cloudflare
	cf.RequestIP = []string{"192.0.2.0/24"}
	changed.Credentials[0].Cloudflare = &cf
	if err := h.srv.SetConfig(&changed); err != nil {
		t.Fatal(err)
	}
	h.srv.SweepIssued(t.Context(), false)
	if _, live, deleted := f.counts(); live != 0 || deleted != 1 {
		t.Fatalf("after a change: %d live, %d deleted", live, deleted)
	}
	h.namedGet("agent", "token-a", "/client/v4/zones")
	if cond, _ := json.Marshal(f.created[1]["condition"]); string(cond) != `{"request_ip":{"in":["192.0.2.0/24"]}}` {
		t.Fatalf("condition %s", cond)
	}
	h.srv.SweepIssued(t.Context(), true)
	if _, live, _ := f.counts(); live != 0 {
		t.Fatalf("%d live after stopping", live)
	}
}

func TestCloudflareCreationRefused(t *testing.T) {
	h, f := cfHarness(t, nil)
	h.store.m["cf"] = Secret{Value: []byte("a-wrong-master-token"), Hosts: []string{goodHost}}
	code, body := h.namedGet("agent", "token-a", "/client/v4/zones")
	if code != http.StatusBadGateway || !strings.Contains(body, "9109") || strings.Contains(body, "wrong-master") {
		t.Fatalf("%d %q", code, body)
	}
	if c, _, _ := f.counts(); c != 0 {
		t.Fatal("token created")
	}
}

func TestCloudflareValidation(t *testing.T) {
	ok := func() Credential {
		return Credential{Name: "c", Secret: "cf", Hosts: []string{"api.cloudflare.com"}, Groups: []string{"a"}, Scheme: "cloudflare_token",
			Cloudflare: &CloudflareToken{Policies: []json.RawMessage{json.RawMessage(`{"effect":"allow","resources":{"com.cloudflare.api.account.` + cfAccount + `":{"com.cloudflare.api.account.zone.*":"*"}},"permission_groups":[{"id":"` + cfGroup + `"}]}`)}}}
	}
	if err := (&Config{Credentials: []Credential{ok()}}).Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	bad := map[string]func(*Credential){
		"no policies":  func(c *Credential) { c.Cloudflare.Policies = nil },
		"no block":     func(c *Credential) { c.Cloudflare = nil },
		"another host": func(c *Credential) { c.Hosts = []string{"api.cloudflare.com", "example.com"} },
		"username":     func(c *Credential) { c.Username = "u" },
		"bad account":  func(c *Credential) { c.Cloudflare.AccountID = "ABC" },
		"bad ip":       func(c *Credential) { c.Cloudflare.RequestIP = []string{"1.2.3.4"} },
		"long life":    func(c *Credential) { c.Cloudflare.MaxDuration = "48h" },
		"short life":   func(c *Credential) { c.Cloudflare.MaxDuration = "1m" },
		"bad effect": func(c *Credential) {
			c.Cloudflare.Policies[0] = json.RawMessage(`{"effect":"maybe","resources":{"com.cloudflare.api.account.*":"*"},"permission_groups":[{"id":"` + cfGroup + `"}]}`)
		},
		"no groups": func(c *Credential) {
			c.Cloudflare.Policies[0] = json.RawMessage(`{"effect":"allow","resources":{"com.cloudflare.api.account.*":"*"},"permission_groups":[]}`)
		},
		"bad resource": func(c *Credential) {
			c.Cloudflare.Policies[0] = json.RawMessage(`{"effect":"allow","resources":{"com.evil":"*"},"permission_groups":[{"id":"` + cfGroup + `"}]}`)
		},
		"unknown field": func(c *Credential) {
			c.Cloudflare.Policies[0] = json.RawMessage(`{"effect":"allow","extra":1,"resources":{"com.cloudflare.api.account.*":"*"},"permission_groups":[{"id":"` + cfGroup + `"}]}`)
		},
		"zone with a value": func(c *Credential) {
			c.Cloudflare.Policies[0] = json.RawMessage(`{"effect":"allow","resources":{"com.cloudflare.api.account.zone.*":{"x":"*"}},"permission_groups":[{"id":"` + cfGroup + `"}]}`)
		},
		"block on bearer": func(c *Credential) { c.Scheme = "bearer" },
	}
	for name, mutate := range bad {
		c := ok()
		cf := *c.Cloudflare
		cf.Policies = append([]json.RawMessage(nil), cf.Policies...)
		c.Cloudflare = &cf
		mutate(&c)
		if err := (&Config{Credentials: []Credential{c}}).Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
