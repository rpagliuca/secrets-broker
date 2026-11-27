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
	lose      int // replies to "send" to drop after receiving the notification
	sends     int
}

func newFake(t *testing.T) *fake {
	f := &fake{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.auth = r.Header.Get("Authorization")
		switch {
		case r.Method == "POST" && r.URL.Path == "/notifications":
			f.sent = nil
			json.NewDecoder(r.Body).Decode(&f.sent)
			f.sends++
			if f.lose > 0 {
				// The notification was taken, but the reply never arrives.
				f.lose--
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					conn.Close()
				}
				return
			}
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

// The notification reaches the phone but the reply with its id is lost: the
// broker must send again, or the answer on the phone is never read.
func TestSendsAgainWhenTheReplyIsLost(t *testing.T) {
	old := retryDelay
	retryDelay = 10 * time.Millisecond
	t.Cleanup(func() { retryDelay = old })

	f := newFake(t)
	f.lose = 1
	f.answer = "allow-3600"
	g := broker.NewGrants(approval(), f.notifier(), nil)
	p := broker.Principal{ID: "S-1", Name: "fix the build", Groups: []string{"team-a"}}

	if err := g.Authorize(p, "svc", []string{"api.example.com"}); err == nil {
		t.Fatal("authorised before any answer")
	}
	waitFor(t, "the grant", func() bool { return g.Authorize(p, "svc", nil) == nil })
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sends != 2 {
		t.Errorf("%d sends, want 2", f.sends)
	}
}

// A request nobody answered leaves a note on the phone in place of the
// question, instead of buttons that no longer count.
func TestExpiredRequestLeavesANote(t *testing.T) {
	f := newFake(t) // never answers
	cfg := approval()
	cfg.RequestTTL = broker.Duration(150 * time.Millisecond)
	g := broker.NewGrants(cfg, f.notifier(), nil)
	p := broker.Principal{ID: "S-1", Name: "fix the build", Groups: []string{"team-a"}}

	if err := g.Authorize(p, "svc", []string{"api.example.com"}); err == nil {
		t.Fatal("authorised before any answer")
	}
	waitFor(t, "the note", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.sends == 2
	})
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sent["title"] != "Expired: Credential request" || f.sent["level"] != "passive" || f.sent["actions"] != nil {
		t.Errorf("note = %v", f.sent)
	}
	if f.sent["collapse_id"] == "" || f.sent["collapse_id"] == nil {
		t.Errorf("the note does not replace the question: %v", f.sent)
	}
	if f.retracted != "" {
		t.Error("the note was retracted")
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

// A request that needs a one-time code cannot be granted from a button.
func TestRequestThatNeedsACodeOnlyHasTheDenyButton(t *testing.T) {
	f := newFake(t)
	g := broker.NewGrants(approval(), f.notifier(), nil)
	g.CodeHooks(func(c string) bool { return c == "aws:audit" },
		func(broker.Principal, string, string, time.Duration) (time.Time, error) { return time.Time{}, nil })
	p := broker.Principal{ID: "S-1", Name: "fix the build", Groups: []string{"team-a"}}
	if err := g.Authorize(p, "aws:audit", []string{"sts.example.com"}); err == nil {
		t.Fatal("authorised before any answer")
	}
	waitFor(t, "the notification", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.sends == 1
	})
	f.mu.Lock()
	defer f.mu.Unlock()
	actions := f.sent["actions"].([]any)
	if len(actions) != 1 || actions[0].(map[string]any)["id"] != "deny" {
		t.Fatalf("buttons = %v", actions)
	}
	if body, _ := f.sent["body"].(string); !strings.Contains(body, "one-time code") {
		t.Errorf("body = %q", body)
	}
}

// The buttons never change places: whatever the client suggested, the
// durations come in the configured order.
func TestButtonsKeepTheirOrder(t *testing.T) {
	f := newFake(t)
	g := broker.NewGrants(approval(), f.notifier(), nil) // 1 h and 4 h
	p := broker.Principal{ID: "S-1", Name: "fix the build", Groups: []string{"team-a"}}
	if _, err := g.Request(p, []string{"svc"}, []string{"api.example.com"}, 4*time.Hour, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the notification", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.sends == 1
	})
	f.mu.Lock()
	defer f.mu.Unlock()
	var titles []string
	for _, a := range f.sent["actions"].([]any) {
		titles = append(titles, a.(map[string]any)["title"].(string))
	}
	if got := strings.Join(titles, ","); got != "Deny,1 h,4 h" {
		t.Fatalf("buttons = %s", got)
	}
}

func TestCloseTakesTheQuestionOffThePhone(t *testing.T) {
	f := newFake(t) // never answers
	g := broker.NewGrants(approval(), f.notifier(), nil)
	g.Authorize(broker.Principal{ID: "S-1"}, "svc", nil)
	waitFor(t, "the notification", func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.sends == 1 })
	g.Close(3 * time.Second)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.retracted == "" {
		t.Fatal("the question was left on the phone after Close")
	}
	if len(g.Pending()) != 0 {
		t.Fatal("a request survived Close")
	}
}

// sealable is a store that answers ErrSealed until it is opened.
type sealable struct {
	mu     sync.Mutex
	open   bool
	inside store
}

func (s *sealable) Get(name string) (broker.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open {
		return broker.Secret{}, broker.ErrSealed
	}
	return s.inside.Get(name)
}

func TestRequestMadeWhileSealedIsSentAfterTheUnseal(t *testing.T) {
	defer func(d time.Duration) { sealedRetry = d }(sealedRetry)
	sealedRetry = 10 * time.Millisecond
	f := newFake(t)
	n := f.notifier()
	s := &sealable{inside: n.Store.(store)}
	n.Store = s
	g := broker.NewGrants(approval(), n, nil)
	g.Authorize(broker.Principal{ID: "S-1"}, "svc", nil)
	time.Sleep(50 * time.Millisecond)
	f.mu.Lock()
	sends := f.sends
	f.mu.Unlock()
	if sends != 0 {
		t.Fatal("sent while sealed")
	}
	s.mu.Lock()
	s.open = true
	s.mu.Unlock()
	waitFor(t, "the notification after the unseal", func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.sends == 1 })
	g.Close(time.Second)
}
