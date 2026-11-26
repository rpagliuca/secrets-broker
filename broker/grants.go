package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Approver decides whether a client may use a credential right now.
type Approver interface {
	// Authorize returns nil when p holds a grant for the credential. Any
	// other result is an *ApprovalError.
	Authorize(p Principal, credential string, hosts []string) error
	// Granted reports whether a grant is in force, without creating a
	// request. Long-lived connections use it to notice the end of a grant.
	Granted(principal, credential string) bool
}

// Notifier tells the person who approves that a request is waiting, and
// brings the answer back by calling Grants.Decide. Notify runs in its own
// goroutine; ctx ends when the request is answered (context.Canceled) or
// expires without an answer (context.DeadlineExceeded).
type Notifier interface {
	Notify(ctx context.Context, g *Grants, req Request)
}

// Request is a client asking to use a credential. It carries nothing written
// by the client: what the approver reads comes from the authenticator and
// from the configuration.
type Request struct {
	ID        string    `json:"id"`
	Principal Principal `json:"principal"`
	// Credential is the first of Credentials, which has everything asked
	// for: one name when the request came from a use, several when the
	// client asked ahead for what a task needs.
	Credential  string    `json:"credential"`
	Credentials []string  `json:"credentials"`
	Hosts       []string  `json:"hosts"`
	Created     time.Time `json:"created"`
	// Suggested is how long the client says it needs, or zero. It is a
	// suggestion to the approver, who chooses.
	Suggested time.Duration `json:"suggested,omitempty"`
	// Reasons is why the client says it wants each credential, by name. It
	// is the only text in a request written by the client: whatever shows
	// it must mark it as the client's own, unverified words.
	Reasons map[string]string `json:"reasons,omitempty"`
}

// maxReason is how long a reason may be, in characters; minReason is how
// short, when the configuration requires one.
const (
	maxReason = 200
	minReason = 10
)

// cleanReason makes a reason safe to show on one line: no control
// characters, single spaces, at most maxReason characters.
func cleanReason(s string) string {
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}), " ")
	if r := []rune(s); len(r) > maxReason {
		s = string(r[:maxReason])
	}
	return s
}

// Grant is an approved request.
type Grant struct {
	Principal  string    `json:"principal"`
	Credential string    `json:"credential"`
	Until      time.Time `json:"until"`
}

// ApprovalError is why a client without a grant was refused.
type ApprovalError struct {
	RequestID string    // set while a request is waiting for an answer
	Until     time.Time // set while new requests are not accepted
}

func (e *ApprovalError) Error() string {
	if e.RequestID != "" {
		return "waiting for approval (request " + e.RequestID + "); retry after it is approved"
	}
	if !e.Until.IsZero() {
		return "not approved; a new request is accepted after " + e.Until.UTC().Format(time.RFC3339)
	}
	return "not approved; too many requests are waiting"
}

// Approval is the configuration of the approval step.
type Approval struct {
	// Durations are the choices offered to the approver, such as "1h".
	Durations []Duration `json:"durations"`
	// RequestTTL is how long a request waits for an answer. Default 10m.
	RequestTTL Duration `json:"request_ttl,omitempty"`
	// Cooldown is how long a client waits before asking again for the same
	// credential after a refusal. A request that expires without an answer
	// is not a refusal: the client may ask again at once. Default 10m.
	Cooldown Duration `json:"cooldown,omitempty"`
	// Open lists what needs no approval, by the name used in grants
	// ("name", "ssh:<target>", "aws:<account>", "command:<name>"). Every
	// authenticated client of the right group uses these at once. They
	// still go through the broker: the secret stays in it and each use is
	// in the audit log.
	Open []string `json:"open,omitempty"`
	// ExplicitOnly stops a use without a grant from asking the approver:
	// it is refused and nobody is notified. Requests then only come from
	// the client asking (POST /requests). Background tools that touch a
	// service on their own, such as a status poller or a server listing
	// its resources at start-up, no longer cause requests nobody made.
	ExplicitOnly bool `json:"explicit_only,omitempty"`
	// RequireReason refuses a request that does not say why the client
	// wants each credential (at least minReason characters each). It
	// implies ExplicitOnly: a request born from a use has no reason.
	RequireReason bool `json:"require_reason,omitempty"`
}

// Duration is a time.Duration written as a string ("90m") in JSON.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`a duration must be a string such as "1h"`)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

const (
	maxGrant      = 24 * time.Hour
	maxPending    = 20
	maxPerRequest = 30
)

func (a *Approval) validate() error {
	if len(a.Durations) == 0 {
		return errors.New("approval: at least one duration is required")
	}
	for _, d := range a.Durations {
		if d <= 0 || time.Duration(d) > maxGrant {
			return fmt.Errorf("approval: duration %s must be between 0 and %s", time.Duration(d), maxGrant)
		}
	}
	if a.RequestTTL < 0 || a.Cooldown < 0 {
		return errors.New("approval: request_ttl and cooldown cannot be negative")
	}
	return nil
}

// Grants is the Approver of the broker: every use of a credential needs a
// grant given to that client, for that credential, for a limited time.
// Grants live in memory only; a restart forgets them all.
type Grants struct {
	durations []time.Duration
	ttl       time.Duration
	cooldown  time.Duration
	notifier  Notifier
	audit     Auditor
	now       func() time.Time

	mu      sync.Mutex
	entries map[grantKey]*grantEntry
	pending map[string]*pendingRequest
}

type grantKey struct{ principal, credential string }

type grantEntry struct {
	until        time.Time // the grant, when in the future
	blockedUntil time.Time // no new request before this
	pending      string    // id of the waiting request
}

type pendingRequest struct {
	Request
	expires time.Time
	cancel  context.CancelFunc
}

// NewGrants creates the grant table. notifier may be nil: requests are then
// answered only through the control socket.
func NewGrants(cfg Approval, notifier Notifier, audit Auditor) *Grants {
	if audit == nil {
		audit = discard{}
	}
	g := &Grants{
		ttl: time.Duration(cfg.RequestTTL), cooldown: time.Duration(cfg.Cooldown),
		notifier: notifier, audit: audit, now: time.Now,
		entries: map[grantKey]*grantEntry{}, pending: map[string]*pendingRequest{},
	}
	for _, d := range cfg.Durations {
		g.durations = append(g.durations, time.Duration(d))
	}
	if g.ttl == 0 {
		g.ttl = 10 * time.Minute
	}
	if g.cooldown == 0 {
		g.cooldown = 10 * time.Minute
	}
	return g
}

// Durations returns the choices to offer to the approver.
func (g *Grants) Durations() []time.Duration { return g.durations }

// Authorize implements Approver. The first call without a grant creates a
// request and notifies the approver; the client is refused until an answer
// arrives.
func (g *Grants) Authorize(p Principal, credential string, hosts []string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.expire(now)
	key := grantKey{p.ID, credential}
	e := g.entries[key]
	if e == nil {
		e = &grantEntry{}
		g.entries[key] = e
	}
	switch {
	case now.Before(e.until):
		return nil
	case e.pending != "":
		return &ApprovalError{RequestID: e.pending}
	case now.Before(e.blockedUntil):
		return &ApprovalError{Until: e.blockedUntil}
	case len(g.pending) >= maxPending:
		return &ApprovalError{}
	}
	return &ApprovalError{RequestID: g.ask(now, p, []string{credential}, hosts, 0, nil)}
}

// ask creates one waiting request for credentials and notifies the
// approver. The caller holds the lock and has checked each credential.
func (g *Grants) ask(now time.Time, p Principal, credentials, hosts []string, suggested time.Duration, reasons map[string]string) string {
	raw := make([]byte, 4)
	rand.Read(raw)
	req := Request{ID: hex.EncodeToString(raw), Principal: p, Credential: credentials[0], Credentials: credentials,
		Hosts: hosts, Created: now.UTC(), Suggested: suggested}
	for _, c := range credentials {
		if why := cleanReason(reasons[c]); why != "" {
			if req.Reasons == nil {
				req.Reasons = map[string]string{}
			}
			req.Reasons[c] = why
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), g.ttl)
	g.pending[req.ID] = &pendingRequest{Request: req, expires: now.Add(g.ttl), cancel: cancel}
	for _, c := range credentials {
		key := grantKey{p.ID, c}
		if g.entries[key] == nil {
			g.entries[key] = &grantEntry{}
		}
		g.entries[key].pending = req.ID
	}
	g.record(req, "requested", "request "+req.ID)
	if g.notifier != nil {
		go g.notifier.Notify(ctx, g, req)
	}
	return req.ID
}

// Request asks for several credentials in one question to the approver,
// with the duration the client suggests. Credentials already granted, or
// already waiting in another request, are left out. It returns the id of
// the request that was created, or "" when there was nothing left to ask.
func (g *Grants) Request(p Principal, credentials, hosts []string, suggested time.Duration, reasons map[string]string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.expire(now)
	if len(credentials) > maxPerRequest {
		return "", fmt.Errorf("at most %d credentials per request", maxPerRequest)
	}
	if suggested < 0 || suggested > maxGrant {
		suggested = 0
	}
	var ask []string
	var blocked time.Time
	for _, c := range credentials {
		e := g.entries[grantKey{p.ID, c}]
		switch {
		case slices.Contains(ask, c) || e != nil && (now.Before(e.until) || e.pending != ""):
		case e != nil && now.Before(e.blockedUntil):
			blocked = e.blockedUntil
		default:
			ask = append(ask, c)
		}
	}
	switch {
	case len(ask) == 0 && !blocked.IsZero():
		return "", &ApprovalError{Until: blocked}
	case len(ask) == 0:
		return "", nil
	case len(g.pending) >= maxPending:
		return "", &ApprovalError{}
	}
	return g.ask(now, p, ask, hosts, suggested, reasons), nil
}

// Granted implements Approver.
func (g *Grants) Granted(principal, credential string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entries[grantKey{principal, credential}]
	return e != nil && g.now().Before(e.until)
}

// Until returns when the grant ends, or the zero time without a grant.
func (g *Grants) Until(principal, credential string) time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e := g.entries[grantKey{principal, credential}]; e != nil {
		return e.until
	}
	return time.Time{}
}

// Decide answers a waiting request: a positive duration grants it for that
// long, zero refuses it. by says who answered, for the audit log.
func (g *Grants) Decide(id string, d time.Duration, by string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.expire(now)
	req := g.pending[id]
	if req == nil {
		return fmt.Errorf("no waiting request %q (answered or expired)", id)
	}
	if d < 0 || d > maxGrant {
		return fmt.Errorf("duration must be between 0 and %s", maxGrant)
	}
	g.drop(req)
	for _, c := range req.Credentials {
		e := g.entries[grantKey{req.Principal.ID, c}]
		if d == 0 {
			e.blockedUntil = now.Add(g.cooldown)
		} else {
			e.until = now.Add(d)
		}
	}
	if d == 0 {
		g.record(req.Request, "refused", "by "+by)
		return nil
	}
	g.record(req.Request, "granted", fmt.Sprintf("for %s, by %s", d, by))
	return nil
}

// Revoke ends the grants and waiting requests of a client, or of every
// client when principal is "all". It returns how many grants were ended.
func (g *Grants) Revoke(principal, by string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	n := 0
	for key, e := range g.entries {
		if principal != "all" && key.principal != principal {
			continue
		}
		if req := g.pending[e.pending]; req != nil {
			g.drop(req)
		}
		if now.Before(e.until) {
			n++
			g.audit.Record(Event{Time: now.UTC(), Decision: "revoked", Reason: "by " + by, Principal: key.principal, Credential: key.credential})
		}
		e.until = time.Time{}
	}
	return n
}

// Block is a client kept from asking again for a credential, after a refusal.
type Block struct {
	Principal  string    `json:"principal"`
	Credential string    `json:"credential"`
	Until      time.Time `json:"until"`
}

// Blocked lists the cooldowns in force, soonest to end first.
func (g *Grants) Blocked() []Block {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.expire(now)
	var out []Block
	for key, e := range g.entries {
		if now.Before(e.blockedUntil) {
			out = append(out, Block{Principal: key.principal, Credential: key.credential, Until: e.blockedUntil})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Until.Equal(out[j].Until) {
			return out[i].Until.Before(out[j].Until)
		}
		return out[i].Principal+"\x00"+out[i].Credential < out[j].Principal+"\x00"+out[j].Credential
	})
	return out
}

// Unblock ends the cooldowns of a client, or of every client when principal
// is "all", so that it may ask again at once. It grants nothing. It returns
// how many cooldowns were ended.
func (g *Grants) Unblock(principal, by string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	n := 0
	for key, e := range g.entries {
		if (principal != "all" && key.principal != principal) || !now.Before(e.blockedUntil) {
			continue
		}
		e.blockedUntil = time.Time{}
		n++
		g.audit.Record(Event{Time: now.UTC(), Decision: "unblocked", Reason: "by " + by, Principal: key.principal, Credential: key.credential})
	}
	return n
}

// Pending lists the waiting requests, oldest first.
func (g *Grants) Pending() []Request {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.expire(g.now())
	out := make([]Request, 0, len(g.pending))
	for _, req := range g.pending {
		out = append(out, req.Request)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// Active lists the grants still valid, soonest to expire first.
func (g *Grants) Active() []Grant {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	var out []Grant
	for key, e := range g.entries {
		if now.Before(e.until) {
			out = append(out, Grant{key.principal, key.credential, e.until.UTC()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Until.Before(out[j].Until) })
	return out
}

// expire drops unanswered requests and forgets entries with nothing left.
// Nobody refused an unanswered request, so it starts no cooldown: the
// approver may simply not have seen it, and the client can ask again.
func (g *Grants) expire(now time.Time) {
	for _, req := range g.pending {
		if !now.Before(req.expires) {
			g.drop(req)
			g.record(req.Request, "expired", "no answer in "+g.ttl.String())
		}
	}
	for key, e := range g.entries {
		if e.pending == "" && !now.Before(e.until) && !now.Before(e.blockedUntil) {
			delete(g.entries, key)
		}
	}
}

func (g *Grants) drop(req *pendingRequest) {
	req.cancel()
	delete(g.pending, req.ID)
	for _, c := range req.Credentials {
		if e := g.entries[grantKey{req.Principal.ID, c}]; e != nil && e.pending == req.ID {
			e.pending = ""
		}
	}
}

// record writes one event per credential of the request.
func (g *Grants) record(req Request, decision, reason string) {
	for _, c := range req.Credentials {
		g.audit.Record(Event{
			Time: g.now().UTC(), Decision: decision, Reason: reason,
			Principal: req.Principal.ID, Name: req.Principal.Name, Groups: req.Principal.Groups, Credential: c,
		})
	}
}
