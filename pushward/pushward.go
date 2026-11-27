// Package pushward delivers approval requests to a phone through PushWard
// (https://pushward.app) and brings the answer back.
//
// The broker sends a notification with one button per choice and then reads
// the answer from the PushWard API. Nothing calls the broker: it only needs
// outbound HTTPS. The integration key comes from the broker's own store, so
// clients of the broker never hold it and cannot forge an answer.
package pushward

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rpagliuca/secrets-broker/broker"
)

// DefaultBaseURL is the PushWard API.
const DefaultBaseURL = "https://api.pushward.app"

// Notifier implements broker.Notifier.
type Notifier struct {
	// Store and Secret locate the PushWard integration key. The secret must
	// be bound to the API host, like any other.
	Store  broker.Store
	Secret string
	// BaseURL defaults to DefaultBaseURL.
	BaseURL string
	// Source is the name the PushWard app shows for these notifications and
	// groups them under. Defaults to "secrets-broker"; without a source the
	// app files them as "Unknown".
	Source string
	// Level is the interruption level of the notification. Defaults to
	// "time-sensitive", which gets through a Focus.
	Level string
	// NoUnlock drops the requirement to unlock the phone (Face ID, Touch ID
	// or passcode) before a button counts.
	NoUnlock bool
	// Text writes the notification. The default is in English.
	Text func(req broker.Request) (title, body string)
	// Expired rewrites the notification of a request that expired without
	// an answer: it takes the place of the question on the phone, so that
	// whoever looks later sees why the buttons no longer count. The default
	// is in English.
	Expired func(req broker.Request) (title, body string)
	// Deny and Allow label the buttons. The defaults are "Deny" and the
	// duration, such as "4 h".
	Deny  string
	Allow func(d time.Duration) string
	// Client defaults to a client that ignores proxy settings.
	Client *http.Client
}

// Notify implements broker.Notifier: it asks, waits for the answer and
// reports it to g. It returns when ctx ends, which is when the request was
// answered or expired.
func (n *Notifier) Notify(ctx context.Context, g *broker.Grants, req broker.Request) {
	if err := n.ask(ctx, g, req); err != nil && ctx.Err() == nil {
		log.Printf("pushward: request %s: %v", req.ID, err)
	}
}

func (n *Notifier) ask(ctx context.Context, g *broker.Grants, req broker.Request) error {
	// A request made while the store is sealed waits for the unseal, and
	// then the approver is asked: otherwise it would wait unseen.
	key, err := n.key()
	for errors.Is(err, broker.ErrSealed) {
		select {
		case <-ctx.Done():
			return err
		case <-time.After(sealedRetry):
		}
		key, err = n.key()
	}
	if err != nil {
		return err
	}
	choices := map[string]time.Duration{"deny": 0}
	actions := []action{{ID: "deny", Title: n.denyLabel(), Destructive: true, Unlock: !n.NoUnlock}}
	// Every configured choice, always in the configured order: the buttons
	// must not change places from one request to the next, whatever the
	// client suggested (the suggestion is in the text). PushWard accepts ten
	// buttons, one of which is the refusal.
	durations := g.Durations()
	if len(durations) > 9 {
		durations = durations[:9]
	}
	if len(req.NeedsCode) > 0 {
		// A button cannot carry the one-time code the request needs: from
		// here it can only be refused. It is granted where the code can be
		// typed.
		durations = nil
	}
	for _, d := range durations {
		id := "allow-" + strconv.FormatInt(int64(d/time.Second), 10)
		choices[id] = d
		actions = append(actions, action{ID: id, Title: n.allowLabel(d), Unlock: !n.NoUnlock})
	}
	title, body := n.text(req)
	source := n.Source
	if source == "" {
		source = "secrets-broker"
	}
	level := n.Level
	if level == "" {
		level = "time-sensitive"
	}
	// Whatever happens, the question must not sit on the phone looking
	// answerable. An answered request is taken off; one that expired is
	// replaced by a note saying so.
	defer func() {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			n.expired(key, req, source)
			return
		}
		n.retract(key, req.ID)
	}()
	var sent struct {
		ID         json.Number `json:"id"`
		Answerable bool        `json:"answerable"`
	}

	// A notification can reach the phone although the reply to this call is
	// lost, and without its id the answer cannot be read. So a failed send
	// is repeated while the request is alive: the collapse id is the same,
	// and the notification the broker ends up listening to takes the place
	// of the one it lost.
	for {
		sendCtx, cancel := context.WithTimeout(ctx, sendTimeout)
		err = n.call(sendCtx, key, http.MethodPost, "/notifications", notification{
			Title: title, Body: body, Level: level, CollapseID: req.ID, Actions: actions,
			Source: "secrets-broker", SourceName: source,
		}, &sent)
		cancel()
		if err == nil {
			break
		}
		if !transient(err) || ctx.Err() != nil {
			return err
		}
		log.Printf("pushward: request %s: sending again: %v", req.ID, err)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(retryDelay):
		}
	}
	if sent.ID == "" || !sent.Answerable {
		return errors.New("the notification was accepted but its answer will not be recorded")
	}

	for ctx.Err() == nil {
		var ans struct {
			Status   string `json:"status"`
			ActionID string `json:"action_id"`
		}
		err := n.call(ctx, key, http.MethodGet, "/notifications/answers/"+url.PathEscape(sent.ID.String())+"?wait=25", nil, &ans)
		if err != nil {
			if !transient(err) {
				return err
			}
			select { // try again while the request is alive
			case <-ctx.Done():
			case <-time.After(retryDelay):
			}
			continue
		}
		if ans.Status != "answered" {
			continue
		}
		d, ok := choices[ans.ActionID]
		if !ok {
			return fmt.Errorf("unexpected answer %q", ans.ActionID)
		}
		return g.Decide(req.ID, d, "pushward")
	}
	return ctx.Err()
}

type notification struct {
	Title      string   `json:"title"`
	Body       string   `json:"body"`
	Level      string   `json:"level"`
	CollapseID string   `json:"collapse_id"`
	Actions    []action `json:"actions,omitempty"`
	Source     string   `json:"source"`
	SourceName string   `json:"source_display_name"`
}

type action struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Destructive bool   `json:"destructive,omitempty"`
	Unlock      bool   `json:"authentication_required,omitempty"`
}

type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string { return fmt.Sprintf("PushWard answered %d: %s", e.code, e.body) }

// transient reports whether a call is worth repeating: the network failed,
// the reply did not come in time, or PushWard said to try later.
func transient(err error) bool {
	var se *statusError
	if errors.As(err, &se) {
		return se.code == http.StatusTooManyRequests || se.code >= 500
	}
	return true
}

// How long one attempt to send may take, and the pause before the next
// attempt after a transient failure. Variables so that tests can shorten them.
var (
	sendTimeout = 15 * time.Second
	// sealedRetry is how often a request made while sealed checks for the unseal.
	sealedRetry = 15 * time.Second
	retryDelay  = 5 * time.Second
)

func (n *Notifier) call(ctx context.Context, key, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, n.baseURL()+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := n.Client
	if client == nil {
		client = defaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &statusError{resp.StatusCode, string(bytes.TrimSpace(raw))}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// expired replaces the question by a quiet note without buttons, under the
// same collapse id. If that fails, the question is retracted. Best effort.
func (n *Notifier) expired(key string, req broker.Request, source string) {
	title, body := n.text(req)
	if n.Expired != nil {
		title, body = n.Expired(req)
	} else {
		title = "Expired: " + title
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := n.call(ctx, key, http.MethodPost, "/notifications", notification{
		Title: title, Body: body, Level: "passive", CollapseID: req.ID,
		Source: "secrets-broker", SourceName: source,
	}, nil)
	if err != nil {
		log.Printf("pushward: request %s: expired note: %v", req.ID, err)
		n.retract(key, req.ID)
	}
}

// retract removes the notification from the devices. Best effort.
func (n *Notifier) retract(key, collapseID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out struct {
		Devices *int `json:"devices"`
	}
	if err := n.call(ctx, key, http.MethodPost, "/notifications/retract", map[string]string{"collapse_id": collapseID}, &out); err != nil {
		log.Printf("pushward: request %s: retract: %v", collapseID, err)
		return
	}
	// PushWard says how many devices it could reach; 0 means the
	// notification stays on the phone.
	switch {
	case out.Devices == nil:
		log.Printf("pushward: request %s: retract accepted, devices not reported", collapseID)
	case *out.Devices == 0:
		log.Printf("pushward: request %s: retract reached no device", collapseID)
	default:
		log.Printf("pushward: request %s: retract sent to %d devices", collapseID, *out.Devices)
	}
}

// key fetches the integration key and enforces its host binding.
func (n *Notifier) key() (string, error) {
	u, err := url.Parse(n.baseURL())
	if err != nil {
		return "", err
	}
	sec, err := n.Store.Get(n.Secret)
	if err != nil {
		return "", err
	}
	if !slices.Contains(sec.Hosts, u.Hostname()) {
		return "", fmt.Errorf("secret %s is not bound to %s", n.Secret, u.Hostname())
	}
	return string(sec.Value), nil
}

func (n *Notifier) baseURL() string {
	if n.BaseURL != "" {
		return n.BaseURL
	}
	return DefaultBaseURL
}

func (n *Notifier) text(req broker.Request) (string, string) {
	if n.Text != nil {
		return n.Text(req)
	}
	who := req.Principal.Name
	if who == "" {
		who = req.Principal.ID
	}
	what := strings.Join(req.Credentials, ", ")
	if req.Suggested > 0 {
		what += " for " + Short(req.Suggested)
	}
	if len(req.NeedsCode) > 0 {
		what += "; needs a one-time code, so approve it on the broker"
	}
	return "Credential request", fmt.Sprintf("%s asks for %s (%s)", who, what, req.Principal.ID)
}

func (n *Notifier) denyLabel() string {
	if n.Deny != "" {
		return n.Deny
	}
	return "Deny"
}

func (n *Notifier) allowLabel(d time.Duration) string {
	if n.Allow != nil {
		return n.Allow(d)
	}
	return Short(d)
}

// Short formats a duration for a button: "4 h", "30 min", "1 h 30 min".
func Short(d time.Duration) string {
	h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)
	switch {
	case m == 0:
		return fmt.Sprintf("%d h", h)
	case h == 0:
		return fmt.Sprintf("%d min", m)
	}
	return fmt.Sprintf("%d h %d min", h, m)
}

var defaultClient = &http.Client{
	Timeout:   40 * time.Second, // above the 25 s long poll
	Transport: &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, IdleConnTimeout: 90 * time.Second},
}
