package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
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
// goroutine; ctx ends when the request is answered or expires.
type Notifier interface {
	Notify(ctx context.Context, g *Grants, req Request)
}

// Request is a client asking to use a credential. It carries nothing written
// by the client: what the approver reads comes from the authenticator and
// from the configuration.
type Request struct {
	ID         string    `json:"id"`
	Principal  Principal `json:"principal"`
	Credential string    `json:"credential"`
	Hosts      []string  `json:"hosts"`
	Created    time.Time `json:"created"`
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
	// credential after a refusal or an unanswered request. Default 10m.
	Cooldown Duration `json:"cooldown,omitempty"`
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
	maxGrant   = 24 * time.Hour
	maxPending = 20
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
	raw := make([]byte, 4)
	rand.Read(raw)
	req := Request{ID: hex.EncodeToString(raw), Principal: p, Credential: credential, Hosts: hosts, Created: now.UTC()}
	ctx, cancel := context.WithTimeout(context.Background(), g.ttl)
	g.pending[req.ID] = &pendingRequest{Request: req, expires: now.Add(g.ttl), cancel: cancel}
	e.pending = req.ID
	g.record(req, "requested", "request "+req.ID)
	if g.notifier != nil {
		go g.notifier.Notify(ctx, g, req)
	}
	return &ApprovalError{RequestID: req.ID}
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
	e := g.entries[grantKey{req.Principal.ID, req.Credential}]
	if d == 0 {
		e.blockedUntil = now.Add(g.cooldown)
		g.record(req.Request, "refused", "by "+by)
		return nil
	}
	e.until = now.Add(d)
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
// An unanswered request counts as a refusal for the cooldown, so a client
// cannot keep the approver's phone buzzing.
func (g *Grants) expire(now time.Time) {
	for _, req := range g.pending {
		if !now.Before(req.expires) {
			g.drop(req)
			g.entries[grantKey{req.Principal.ID, req.Credential}].blockedUntil = now.Add(g.cooldown)
			g.record(req.Request, "refused", "request expired without an answer")
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
	if e := g.entries[grantKey{req.Principal.ID, req.Credential}]; e != nil {
		e.pending = ""
	}
}

func (g *Grants) record(req Request, decision, reason string) {
	g.audit.Record(Event{
		Time: g.now().UTC(), Decision: decision, Reason: reason,
		Principal: req.Principal.ID, Groups: req.Principal.Groups, Credential: req.Credential,
	})
}
