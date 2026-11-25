package pushward

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rpagliuca/secrets-broker/broker"
)

type store map[string]broker.Secret

func (s store) Get(name string) (broker.Secret, error) {
	sec, ok := s[name]
	if !ok {
		return broker.Secret{}, broker.ErrNotFound
	}
	return sec, nil
}

// fake is a PushWard API that answers with the action chosen by the test.
type fake struct {
	*httptest.Server
	mu        sync.Mutex
	sent      map[string]any
	auth      string
	polls     int
	answer    string // action id to answer with, after the first poll
	retracted string
}

func newFake(t *testing.T) *fake {
	f := &fake{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.auth = r.Header.Get("Authorization")
		switch {
		case r.Method == "POST" && r.URL.Path == "/notifications":
			json.NewDecoder(r.Body).Decode(&f.sent)
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"id":1234,"answerable":true,"answer_cursor":"57","pushed":true}`)
		case r.Method == "GET" && r.URL.Path == "/notifications/answers/1234":
			f.polls++
			if f.polls == 1 || f.answer == "" {
				io.WriteString(w, `{"notification_id":1234,"status":"pending"}`)
				return
			}
			io.WriteString(w, `{"notification_id":1234,"status":"answered","action_id":"`+f.answer+`"}`)
		case r.Method == "POST" && r.URL.Path == "/notifications/retract":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			f.retracted = body["collapse_id"]
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"devices":1}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fake) notifier() *Notifier {
	u, _ := url.Parse(f.URL)
	return &Notifier{
		Store:   store{"pushward": {Value: []byte("hlk_test_key"), Hosts: []string{u.Hostname()}}},
		Secret:  "pushward",
		BaseURL: f.URL,
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func approval() broker.Approval {
	return broker.Approval{Durations: []broker.Duration{broker.Duration(time.Hour), broker.Duration(4 * time.Hour)}}
}

func TestApproveFromThePhone(t *testing.T) {
	f := newFake(t)
	f.answer = "allow-14400"
	g := broker.NewGrants(approval(), f.notifier(), nil)
	p := broker.Principal{ID: "S-1", Name: "fix the build", Groups: []string{"team-a"}}

	if err := g.Authorize(p, "svc", []string{"api.example.com"}); err == nil {
		t.Fatal("authorised before any answer")
	}
	waitFor(t, "the grant", func() bool { return g.Authorize(p, "svc", nil) == nil })

	grants := g.Active()
	if len(grants) != 1 || time.Until(grants[0].Until) < 3*time.Hour {
		t.Fatalf("grants = %+v, want one of 4 h", grants)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auth != "Bearer hlk_test_key" {
		t.Errorf("Authorization = %q", f.auth)
	}
	if f.sent["level"] != "time-sensitive" || f.sent["body"] != "fix the build asks for svc (S-1)" {
		t.Errorf("notification = %v", f.sent)
	}
	actions := f.sent["actions"].([]any)
	if len(actions) != 3 {
		t.Fatalf("%d buttons, want deny + 2 durations", len(actions))
	}
	for _, a := range actions {
		if a.(map[string]any)["authentication_required"] != true {
			t.Errorf("button %v does not require unlocking the phone", a)
		}
	}
	if first := actions[0].(map[string]any); first["id"] != "deny" || first["destructive"] != true {
		t.Errorf("first button = %v", first)
	}
	if actions[2].(map[string]any)["title"] != "4 h" {
		t.Errorf("last button = %v", actions[2])
	}
	if raw, _ := json.Marshal(f.sent); strings.Contains(string(raw), "hlk_") {
		t.Error("the integration key is in the notification")
	}
}

func TestDenyFromThePhone(t *testing.T) {
	f := newFake(t)
	f.answer = "deny"
	g := broker.NewGrants(approval(), f.notifier(), nil)
	p := broker.Principal{ID: "S-1"}
	g.Authorize(p, "svc", nil)
	waitFor(t, "the refusal", func() bool { return len(g.Pending()) == 0 })
	if err := g.Authorize(p, "svc", nil); err == nil {
		t.Fatal("authorised after a refusal")
	}
	waitFor(t, "the retraction", func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.retracted != "" })
}

func TestUnknownAnswerGrantsNothing(t *testing.T) {
	f := newFake(t)
	f.answer = "allow-999999"
	g := broker.NewGrants(approval(), f.notifier(), nil)
	p := broker.Principal{ID: "S-1"}
	g.Authorize(p, "svc", nil)
	waitFor(t, "the retraction", func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.retracted != "" })
	if len(g.Active()) != 0 {
		t.Fatal("an answer that was never offered created a grant")
	}
}

func TestKeyMustBeBoundToTheAPIHost(t *testing.T) {
	f := newFake(t)
	n := f.notifier()
	n.Store = store{"pushward": {Value: []byte("hlk_test_key"), Hosts: []string{"other.example"}}}
	if _, err := n.key(); err == nil {
		t.Fatal("a key bound to another host was used")
	}
}

func TestShort(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Hour: "1 h", 12 * time.Hour: "12 h", 30 * time.Minute: "30 min", 90 * time.Minute: "1 h 30 min",
	} {
		if got := Short(d); got != want {
			t.Errorf("Short(%s) = %q, want %q", d, got, want)
		}
	}
}
