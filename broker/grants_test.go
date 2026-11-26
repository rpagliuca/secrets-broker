package broker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a time source the tests move by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// notified collects the requests sent to the approver.
type notified struct{ ch chan Request }

func (n *notified) Notify(_ context.Context, _ *Grants, req Request) { n.ch <- req }

func newTestGrants() (*Grants, *clock, *notified, *recorder) {
	c := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	n := &notified{ch: make(chan Request, 100)}
	audit := &recorder{}
	g := NewGrants(Approval{Durations: []Duration{Duration(time.Hour)}}, n, audit)
	g.now = c.now
	return g, c, n, audit
}

func requestID(t *testing.T, err error) string {
	t.Helper()
	var ae *ApprovalError
	if !errors.As(err, &ae) || ae.RequestID == "" {
		t.Fatalf("err = %v, want a waiting request", err)
	}
	return ae.RequestID
}

func TestGrantLifecycle(t *testing.T) {
	g, c, n, audit := newTestGrants()
	a := Principal{ID: "agent-a", Groups: []string{"team-a"}}
	b := Principal{ID: "agent-b", Groups: []string{"team-a"}}

	id := requestID(t, g.Authorize(a, "svc", []string{goodHost}))
	if req := <-n.ch; req.ID != id || req.Principal.ID != "agent-a" || req.Credential != "svc" {
		t.Fatalf("notified %+v", req)
	}
	// Asking again while waiting does not create or notify a second request.
	again := requestID(t, g.Authorize(a, "svc", nil))
	time.Sleep(50 * time.Millisecond) // a second notification would arrive by now
	if again != id || len(n.ch) != 0 {
		t.Fatalf("second request %s, %d notifications", again, len(n.ch))
	}
	if err := g.Decide(id, time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	if err := g.Authorize(a, "svc", nil); err != nil {
		t.Fatalf("after grant: %v", err)
	}
	// The grant is for that client and that credential only.
	if err := g.Authorize(b, "svc", nil); err == nil {
		t.Fatal("grant leaked to another client")
	}
	if err := g.Authorize(a, "other", nil); err == nil {
		t.Fatal("grant leaked to another credential")
	}
	if err := g.Decide(id, time.Hour, "test"); err == nil {
		t.Fatal("a request was answered twice")
	}

	c.advance(time.Hour)
	if err := g.Authorize(a, "svc", nil); err == nil {
		t.Fatal("grant outlived its duration")
	}
	if !audit.has("granted", "for 1h0m0s, by test") {
		t.Error("grant was not audited")
	}
}

func TestRefusalStartsACooldownAndSilenceDoesNot(t *testing.T) {
	g, c, n, audit := newTestGrants()
	a := Principal{ID: "agent-a"}

	id := requestID(t, g.Authorize(a, "svc", nil))
	if err := g.Decide(id, 0, "test"); err != nil {
		t.Fatal(err)
	}
	var ae *ApprovalError
	if err := g.Authorize(a, "svc", nil); !errors.As(err, &ae) || ae.RequestID != "" || ae.Until.IsZero() {
		t.Fatalf("after refusal: %v, want a cooldown", err)
	}
	c.advance(10 * time.Minute)
	id = requestID(t, g.Authorize(a, "svc", nil)) // may ask again

	// Nobody answers: the request expires. That is not a refusal, so the
	// client may ask again at once, and the approver is asked again.
	c.advance(10 * time.Minute)
	if err := g.Decide(id, time.Hour, "test"); err == nil {
		t.Fatal("an expired request was granted")
	}
	if !audit.has("expired", "no answer in 10m0s") {
		t.Error("the expiry was not audited")
	}
	if again := requestID(t, g.Authorize(a, "svc", nil)); again == id {
		t.Fatal("the expired request is still the one waiting")
	}
	time.Sleep(50 * time.Millisecond) // let the notifier goroutines run
	if len(n.ch) != 3 {
		t.Fatalf("%d notifications, want 3", len(n.ch))
	}
}

func TestPendingRequestsAreCapped(t *testing.T) {
	g, _, n, _ := newTestGrants()
	for i := 0; i < maxPending+5; i++ {
		g.Authorize(Principal{ID: "agent-" + strings.Repeat("x", i+1)}, "svc", nil)
	}
	if got := len(g.Pending()); got != maxPending {
		t.Fatalf("%d waiting requests, want %d", got, maxPending)
	}
	time.Sleep(50 * time.Millisecond) // let the notifier goroutines run
	if len(n.ch) != maxPending {
		t.Fatalf("%d notifications, want %d", len(n.ch), maxPending)
	}
}

func TestProxyNeedsAGrant(t *testing.T) {
	h := newHarness(t, Credential{}, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	g, c, n, _ := newTestGrants()
	h.srv.Approver = g
	client := h.client("token-a")

	_, err := client.Get("https://" + goodHost + "/")
	if err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("without a grant: %v, want 403", err)
	}
	req := <-n.ch
	if req.Principal.ID != "agent-a" || req.Credential != "svc" || len(req.Hosts) != 1 {
		t.Fatalf("request %+v", req)
	}
	if n := len(h.good.requests()); n != 0 {
		t.Fatalf("origin received %d requests before the grant", n)
	}

	if err := g.Decide(req.ID, time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	get := func() int {
		resp, err := client.Get("https://" + goodHost + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(); code != 200 {
		t.Fatalf("with a grant: %d", code)
	}
	// The grant ends while the keep-alive tunnel is still open.
	c.advance(time.Hour)
	if code := get(); code != http.StatusForbidden {
		t.Fatalf("after the grant expired: %d, want 403", code)
	}
	if n := len(h.good.requests()); n != 1 {
		t.Fatalf("origin received %d requests, want 1", n)
	}
}

func TestApprovalConfig(t *testing.T) {
	base := func() *Config {
		return &Config{
			Approval:    &Approval{Durations: []Duration{Duration(time.Hour)}},
			Credentials: []Credential{{Name: "svc", Hosts: []string{goodHost}, Groups: []string{"g"}, Scheme: "bearer"}},
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Approval){
		"no duration":   func(a *Approval) { a.Durations = nil },
		"zero duration": func(a *Approval) { a.Durations = []Duration{0} },
		"too long":      func(a *Approval) { a.Durations = []Duration{Duration(48 * time.Hour)} },
	} {
		c := base()
		mutate(c.Approval)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var d Duration
	if err := d.UnmarshalJSON([]byte(`"90m"`)); err != nil || time.Duration(d) != 90*time.Minute {
		t.Errorf("duration = %v, %v", time.Duration(d), err)
	}
	if err := d.UnmarshalJSON([]byte(`3600`)); err == nil {
		t.Error("a bare number was accepted as a duration")
	}
}

// The log of an approval says who the principal was, not only its id.
func TestApprovalEventsCarryTheName(t *testing.T) {
	g, _, _, audit := newTestGrants()
	p := Principal{ID: "agent-a", Name: "fix the build", Groups: []string{"team-a"}}
	id := requestID(t, g.Authorize(p, "svc", []string{goodHost}))
	if err := g.Decide(id, time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	seen := map[string]bool{}
	for _, ev := range audit.events {
		if ev.Name != "fix the build" {
			t.Errorf("%s event has name %q", ev.Decision, ev.Name)
		}
		seen[ev.Decision] = true
	}
	if !seen["requested"] || !seen["granted"] {
		t.Fatalf("events = %+v", audit.events)
	}
}

// The approver may end a cooldown, so that the client asks again at once.
func TestUnblockEndsACooldown(t *testing.T) {
	g, _, n, audit := newTestGrants()
	a := Principal{ID: "agent-a"}
	b := Principal{ID: "agent-b"}
	for _, p := range []Principal{a, b} {
		if err := g.Decide(requestID(t, g.Authorize(p, "svc", nil)), 0, "test"); err != nil {
			t.Fatal(err)
		}
	}
	blocked := g.Blocked()
	if len(blocked) != 2 || blocked[0].Principal != "agent-a" || blocked[0].Credential != "svc" || blocked[0].Until.IsZero() {
		t.Fatalf("blocked = %+v", blocked)
	}
	if got := g.Unblock("agent-a", "test"); got != 1 {
		t.Fatalf("unblocked %d, want 1", got)
	}
	if !audit.has("unblocked", "by test") {
		t.Error("the unblock was not audited")
	}
	requestID(t, g.Authorize(a, "svc", nil)) // asks again at once
	var ae *ApprovalError
	if err := g.Authorize(b, "svc", nil); !errors.As(err, &ae) || ae.Until.IsZero() {
		t.Fatalf("agent-b after unblocking agent-a: %v, want a cooldown", err)
	}
	if left := g.Blocked(); len(left) != 1 || left[0].Principal != "agent-b" {
		t.Fatalf("blocked = %+v", left)
	}
	if got := g.Unblock("all", "test"); got != 1 {
		t.Fatalf("unblocked %d, want 1", got)
	}
	// Unblocking grants nothing.
	if g.Granted("agent-b", "svc") || len(g.Active()) != 0 {
		t.Error("unblocking granted access")
	}
	time.Sleep(50 * time.Millisecond)
	if len(n.ch) != 3 {
		t.Fatalf("%d notifications, want 3", len(n.ch))
	}
}
