// Package web is the phone panel of the broker: grants in force, requests to
// answer (with a passkey), what happened, the vault (open with a passkey,
// close, rotation). It sits behind a Google login and listens on loopback
// only; a tunnel publishes it. It talks to the broker through the control
// socket and reads the audit log; it sees no secret, except the vault key
// on its way to the broker when the vault is opened with a passkey.
package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rpagliuca/secrets-broker/broker"
)

//go:embed pages/*.html static/*
var files embed.FS

// SessionNames gives a client a name and a state when the broker did not:
// for instance, the task system the clients are sessions of. Optional.
type SessionNames interface {
	// Name of the client, or "".
	Name(id string) string
	// State of the client ("active", "ended"), or "".
	State(id string) string
}

type noNames struct{}

func (noNames) Name(string) string  { return "" }
func (noNames) State(string) string { return "" }

// Server is the screens and actions of the panel. It is always behind the
// login.
type Server struct {
	broker   Broker
	passkeys *Passkeys
	names    SessionNames
	// risks classify the credentials; one not listed shows as high.
	risks map[string]Risk
	// rotation, brokerConfig and vaultPublicKey serve the vault page.
	rotation       *Rotation
	brokerConfig   string
	vaultPublicKey string
	durations      []time.Duration
	origin         string // public origin, checked on every action
	zone           *time.Location
	now            func() time.Time
	tr             *Translator
	pages          *template.Template
	// mfaDevices maps a key name in the risks ("yk1") to its serial, and
	// mfaCommand is the command that copies a code (see Config).
	mfaDevices map[string]string
	mfaCommand string
	// storeKeyCommand is shown on the vault page: how to store the vault
	// key for the enabled passkeys, from where that key is kept.
	storeKeyCommand string
}

// Routes returns the panel without the login; the caller puts it behind
// Login.Protect.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /passkey", s.passkeyPage)
	mux.HandleFunc("GET /usage", s.usage)
	mux.HandleFunc("GET /request/{id}", s.requestPage)
	mux.HandleFunc("GET /vault", s.vaultPage)
	mux.HandleFunc("POST /vault/prf/begin", s.prfBegin)
	mux.HandleFunc("POST /vault/prf/finish", s.prfFinish)
	mux.HandleFunc("POST /vault/open/begin", s.openBegin)
	mux.HandleFunc("POST /vault/open/finish", s.openFinish)
	mux.HandleFunc("POST /vault/close", s.closeVault)
	mux.HandleFunc("GET /live", s.live)
	static, _ := fs.Sub(files, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("POST /revoke", s.revoke)
	mux.HandleFunc("POST /deny", s.deny)
	mux.HandleFunc("POST /unblock", s.unblock)
	mux.HandleFunc("POST /approve/begin", s.approveBegin)
	mux.HandleFunc("POST /approve/finish", s.approveFinish)
	mux.HandleFunc("POST /passkey/register/begin", s.registerBegin)
	mux.HandleFunc("POST /passkey/register/finish", s.registerFinish)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		// same-origin, not no-referrer: with no-referrer the browser sends
		// "Origin: null" on form posts, and the check below refuses it.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		// Every action must come from a page of this panel.
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.sameOrigin(r) {
			replyError(w, http.StatusForbidden, s.tr.T("err.other_origin"))
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// Risk is how risky a credential is and why, from the risks file. MFA says
// where the one-time code of a credential that needs one is: "yk1 ·
// Issuer (account)", the key and the account as the authenticator app
// shows it. MFAEnforced says the provider itself refuses the key without
// the code, so that a leaked key is worth nothing.
type Risk struct {
	Risk        string `json:"risk"`
	Why         string `json:"why"`
	MFA         string `json:"mfa,omitempty"`
	MFAEnforced bool   `json:"mfa_enforced_by_provider,omitempty"`
}

var riskOrder = map[string]int{"high": 0, "medium": 1, "low": 2}

// LoadRisks reads the classification, by name as the broker grants it.
func LoadRisks(path string) (map[string]Risk, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var risks map[string]Risk
	if err := json.Unmarshal(raw, &risks); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for name, r := range risks {
		if _, ok := riskOrder[r.Risk]; !ok {
			return nil, fmt.Errorf("%s: %s has risk %q; use high, medium or low", path, name, r.Risk)
		}
	}
	return risks, nil
}

// patternRisk finds the risk of a name that is an instance of a scope with
// parameters: "org/git/repo/app/read" uses "org/git/repo/{repo}/read".
func patternRisk(risks map[string]Risk, name string) (Risk, bool) {
	parts := strings.Split(name, "/")
	for pattern, r := range risks {
		p := strings.Split(pattern, "/")
		if len(p) != len(parts) || !strings.Contains(pattern, "{") {
			continue
		}
		match := true
		for i := range p {
			if !(strings.HasPrefix(p[i], "{") && strings.HasSuffix(p[i], "}")) && p[i] != parts[i] {
				match = false
				break
			}
		}
		if match {
			return r, true
		}
	}
	return Risk{}, false
}

// badge is a credential with its risk, ready for a page. One without a
// classification shows as high risk: better too much attention.
func (s *Server) badge(name string) badgeView {
	r, ok := s.risks[name]
	if !ok {
		r, ok = patternRisk(s.risks, name)
	}
	if !ok {
		r = Risk{Risk: "high", Why: s.tr.T("risk.unclassified")}
	}
	b := badgeView{Name: name, Risk: r.Risk, Label: s.tr.T("risk." + r.Risk), Why: r.Why, MFA: r.MFA}
	if key, account, ok := strings.Cut(r.MFA, " · "); ok {
		b.MFAKey, b.MFAAccount = key, account
	} else {
		b.MFAAccount = r.MFA
	}
	b.MFACommand = s.codeCommand(b.MFAKey, b.MFAAccount)
	return b
}

// codeCommand fills the configured command that copies the code of an
// authenticator account: {serial} is the key's serial and {account} the
// account as the CLI looks it up ("Issuer:account"), quoted for a shell.
func (s *Server) codeCommand(key, account string) string {
	serial := s.mfaDevices[key]
	if s.mfaCommand == "" || serial == "" || account == "" {
		return ""
	}
	if issuer, rest, ok := strings.Cut(account, " ("); ok && strings.HasSuffix(rest, ")") {
		account = issuer + ":" + strings.TrimSuffix(rest, ")")
	}
	return strings.NewReplacer("{serial}", serial, "{account}", strconv.Quote(account)).Replace(s.mfaCommand)
}

type view struct {
	Email       string
	Sealed      bool
	BrokerError string
	Notice      string
	// Renew lists the secrets past 70% of their validity, or expired.
	Renew      []string
	Period     string
	BySecret   bool
	HasPasskey bool
	Requests   []requestView
	Open       []sessionView
	Cooldowns  []cooldownView
	Sessions   []sessionView
	Secrets    []secretView
	Unused     []badgeView
	Passkeys   []passkeyView
	Vault      *vaultView
	// Request is the request opened alone, full screen (/request/<id>).
	Request *requestView
}

type badgeView struct {
	Name, Risk, Label, Why, MFA string
	// MFAKey and MFAAccount split MFA: the key ("yk1") and the account to
	// look up in the authenticator app. MFACommand copies its code.
	MFAKey, MFAAccount, MFACommand string
}

type requestView struct {
	ID, Session, Name, Ago string
	High                   bool
	// For the summary card of the home page: how many of each risk, and
	// whether one needs a one-time code.
	Highs, Mediums, Lows int
	NeedsCode            bool
	// Suggested is the duration the client asked for, for the page.
	Suggested   string
	Credentials []credentialView
	Durations   []durationView
}

// credentialView is a credential in a request, with the client's reason.
type credentialView struct {
	Badge  badgeView
	Reason string
	// NeedsCode: granted only with the one-time code typed with it.
	NeedsCode bool
	// Query is the SQL the client wants to run once, and Timeout the most
	// it asked for; empty for what is not a database.
	Query, Timeout string
	QueryLines     int
	// Parts is the name split on slashes, shown with the same weight.
	Parts []string
}

type durationView struct {
	Label     string
	Seconds   int64
	Suggested bool
}

type cooldownView struct {
	Session, Name, Until, Left string
	Credentials                []badgeView
}

// itemView is what a client did with a credential in the period.
type itemView struct {
	Badge                           badgeView
	Session, Name, State            string
	Open                            bool
	Until, Left, Window             string
	LastUse                         string // "3 min ago" or "none yet", for the grant in force
	Reason                          string // the client's, for the grant in force
	Requests, Grants, Uses, Denials int
	Lines                           []lineView
}

type sessionView struct {
	Session, Name, State, Last string
	Open, High                 bool
	Items                      []itemView
}

type secretView struct {
	Badge               badgeView
	Open, Uses, Denials int
	Items               []itemView
}

type lineView struct {
	When, Method, Target, Reason string
	Status                       int
	Denied                       bool
}

type passkeyView struct{ Name, Created string }

// maxLines is how many recent uses each client and credential pair shows.
const maxLines = 5

// home is the entry page: only what is alive now (waiting requests, grants
// in force, cooldowns). It does not read the log.
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	v := view{Email: emailOf(r), Notice: r.URL.Query().Get("notice")}
	if s.rotation != nil {
		v.Renew = s.rotation.toRenew(s.now().In(s.zone), s.tr)
	}
	if err := s.alive(&v); err != nil {
		v.BrokerError = err.Error()
	}
	s.show(w, "home.html", v)
}

// live returns only the part of the home page that changes by itself; the
// page fetches it every few seconds. A sealed vault and a broker that does
// not answer go in it too, so the page never looks merely empty.
func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	var v view
	if err := s.alive(&v); err != nil {
		v.BrokerError = err.Error()
	}
	s.show(w, "live", v)
}

// alive fills the waiting requests, the grants in force and the cooldowns,
// from the broker's state only.
func (s *Server) alive(v *view) error {
	sealed, err := s.broker.Sealed()
	if err != nil {
		return err
	}
	v.Sealed = sealed
	requests, err := s.broker.Pending()
	if err != nil {
		return err
	}
	grants, err := s.broker.Grants()
	if err != nil {
		return err
	}
	blocked, err := s.broker.Blocked()
	if err != nil {
		return err
	}
	v.HasPasskey = len(s.passkeys.List()) > 0
	now := s.now()
	names := map[string]string{}
	for _, p := range requests {
		rv := s.requestView(p, now)
		names[p.Principal.ID] = rv.Name
		v.Requests = append(v.Requests, rv)
	}
	name := func(id string) string {
		if n, ok := names[id]; ok && n != "" {
			return n
		}
		return s.names.Name(id)
	}
	v.Open = s.openGrants(grants, name, now)
	v.Cooldowns = s.cooldowns(blocked, name, now)
	return nil
}

// requestPage shows one request alone, full screen: where each reason is
// read and the decision made. The home page only summarizes.
func (s *Server) requestPage(w http.ResponseWriter, r *http.Request) {
	v := view{Email: emailOf(r), HasPasskey: len(s.passkeys.List()) > 0}
	if p, ok := s.request(r.PathValue("id")); ok {
		rv := s.requestView(p, s.now())
		v.Request = &rv
	}
	s.show(w, "request.html", v)
}

// usage is the page of what happened, from the log: by client or by
// credential, in the last 24 hours or 7 days.
func (s *Server) usage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	v := view{Email: emailOf(r), Period: "24h", BySecret: q.Get("view") == "secrets"}
	window := 24 * time.Hour
	if q.Get("period") == "7d" {
		v.Period, window = "7d", 7*24*time.Hour
	}
	now := s.now()
	fail := func(err error) {
		if err != nil && v.BrokerError == "" {
			v.BrokerError = err.Error()
		}
	}
	grants, err := s.broker.Grants()
	fail(err)
	events, err := s.broker.Events(now.Add(-window))
	fail(err)

	names := map[string]string{}
	for _, ev := range events {
		if ev.Name != "" {
			names[ev.Principal] = ev.Name
		}
	}
	for _, g := range grants {
		if g.Name != "" {
			names[g.Principal] = g.Name
		}
	}
	name := func(id string) string {
		if n, ok := names[id]; ok {
			return n
		}
		n := s.names.Name(id) // what the log did not name
		names[id] = n
		return n
	}
	counts := s.count(events, grants)
	v.Sessions, v.Secrets = s.summary(counts, name, now)
	if v.BySecret {
		used := map[string]bool{}
		for k := range counts {
			used[k.secret] = true
		}
		for secret := range s.risks {
			if !used[secret] {
				v.Unused = append(v.Unused, s.badge(secret))
			}
		}
		sort.Slice(v.Unused, func(i, j int) bool {
			a, b := v.Unused[i], v.Unused[j]
			if a.Risk != b.Risk {
				return riskOrder[a.Risk] < riskOrder[b.Risk]
			}
			return a.Name < b.Name
		})
	}
	s.show(w, "usage.html", v)
}

// openGrants groups the grants in force by client: those with high risk
// open first.
func (s *Server) openGrants(grants []broker.Grant, name func(string) string, now time.Time) []sessionView {
	bySession := map[string]*sessionView{}
	for _, g := range grants {
		sv := bySession[g.Principal]
		if sv == nil {
			sv = &sessionView{Session: g.Principal, Name: g.Name, Open: true}
			if sv.Name == "" {
				sv.Name = name(g.Principal)
			}
			bySession[g.Principal] = sv
		}
		item := itemView{Badge: s.badge(g.Credential), Open: true, Until: s.clock(g.Until, now), Left: Short(g.Until.Sub(now)),
			Reason: g.Reason, LastUse: s.tr.T("grant.no_use_yet")}
		if g.LastUse != nil {
			item.LastUse = s.tr.T("grant.ago", Short(now.Sub(*g.LastUse)))
		}
		sv.High = sv.High || item.Badge.Risk == "high"
		sv.Items = append(sv.Items, item)
	}
	sessions := make([]sessionView, 0, len(bySession))
	for _, sv := range bySession {
		sort.Slice(sv.Items, func(i, j int) bool {
			a, b := sv.Items[i].Badge, sv.Items[j].Badge
			if a.Risk != b.Risk {
				return riskOrder[a.Risk] < riskOrder[b.Risk]
			}
			return a.Name < b.Name
		})
		sessions = append(sessions, *sv)
	}
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].High != sessions[j].High {
			return sessions[i].High
		}
		return sessions[i].Session < sessions[j].Session
	})
	return sessions
}

func (s *Server) requestView(p broker.Request, now time.Time) requestView {
	name := p.Principal.Name
	if name == "" {
		name = s.names.Name(p.Principal.ID)
	}
	rv := requestView{ID: p.ID, Session: p.Principal.ID, Name: name, Ago: Short(now.Sub(p.Created)), Durations: s.durationViews(p.Suggested)}
	if p.Suggested > 0 {
		rv.Suggested = Short(p.Suggested)
	}
	for _, c := range p.Credentials {
		b := s.badge(c)
		rv.High = rv.High || b.Risk == "high"
		switch b.Risk {
		case "high":
			rv.Highs++
		case "medium":
			rv.Mediums++
		default:
			rv.Lows++
		}
		needs := slices.Contains(p.NeedsCode, c)
		rv.NeedsCode = rv.NeedsCode || needs
		cv := credentialView{Badge: b, Reason: p.Reasons[c], NeedsCode: needs, Parts: strings.Split(c, "/")}
		if q, ok := p.Queries[c]; ok {
			cv.Query, cv.QueryLines = q.SQL, strings.Count(strings.TrimSpace(q.SQL), "\n")+1
			if q.Timeout > 0 {
				cv.Timeout = Short(time.Duration(q.Timeout))
			}
		}
		rv.Credentials = append(rv.Credentials, cv)
	}
	return rv
}

func (s *Server) passkeyPage(w http.ResponseWriter, r *http.Request) {
	v := view{Email: emailOf(r), Notice: r.URL.Query().Get("notice")}
	for _, k := range s.passkeys.List() {
		v.Passkeys = append(v.Passkeys, passkeyView{Name: k.Name, Created: k.Created.In(s.zone).Format(s.tr.T("time.date"))})
	}
	s.show(w, "passkey.html", v)
}

func (s *Server) show(w http.ResponseWriter, page string, v view) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.pages.ExecuteTemplate(w, page, v); err != nil {
		log.Printf("web: %s: %v", page, err)
	}
}

// durationViews returns the durations always in the configured order, so
// the buttons never move. The client's suggestion comes marked; when it is
// not one of them, the first that covers it (or the largest) is marked.
func (s *Server) durationViews(suggested time.Duration) []durationView {
	marked := time.Duration(0)
	if suggested > 0 && len(s.durations) > 0 {
		marked = slices.Max(s.durations)
		for _, d := range s.durations {
			if d >= suggested && d < marked {
				marked = d
			}
		}
	}
	var out []durationView
	for _, d := range s.durations {
		out = append(out, durationView{Label: Short(d), Seconds: int64(d / time.Second), Suggested: d == marked})
	}
	return out
}

// pair is a client using a credential; tally, what it did in the period.
type pair struct{ session, secret string }

type tally struct {
	requests, grants, uses, denials int
	first, last                     time.Time // window of the uses allowed
	activity                        time.Time // last event of any kind
	until                           time.Time // grant in force
	lines                           []broker.Event
}

// count adds up, by client and credential, the requests, grants and uses.
func (s *Server) count(events []broker.Event, grants []broker.Grant) map[pair]*tally {
	tallies := map[pair]*tally{}
	of := func(session, secret string) *tally {
		k := pair{session, secret}
		if tallies[k] == nil {
			tallies[k] = &tally{}
		}
		return tallies[k]
	}
	for _, ev := range events {
		if ev.Principal == "" || ev.Credential == "" {
			continue
		}
		switch {
		case ev.Decision == "requested":
			of(ev.Principal, ev.Credential).requests++
		case ev.Decision == "granted":
			of(ev.Principal, ev.Credential).grants++
		case (ev.Decision == "allowed" || ev.Decision == "denied") && ev.Method != "request":
			t := of(ev.Principal, ev.Credential)
			if ev.Decision == "allowed" {
				t.uses++
				if t.first.IsZero() {
					t.first = ev.Time
				}
				t.last = ev.Time
			} else {
				t.denials++
			}
			t.lines = append(t.lines, ev)
			if len(t.lines) > maxLines {
				t.lines = t.lines[1:]
			}
		default:
			continue
		}
		t := of(ev.Principal, ev.Credential)
		if ev.Time.After(t.activity) {
			t.activity = ev.Time
		}
	}
	for _, g := range grants {
		of(g.Principal, g.Credential).until = g.Until
	}
	return tallies
}

// summary builds the two views of the period: by client and by credential.
func (s *Server) summary(tallies map[pair]*tally, name func(string) string, now time.Time) ([]sessionView, []secretView) {
	states := map[string]string{}
	state := func(id string) string {
		if e, ok := states[id]; ok {
			return e
		}
		e := s.names.State(id)
		if strings.HasPrefix(id, "service:") {
			e = s.tr.T("state.service")
		}
		states[id] = e
		return e
	}
	bySession := map[string]*sessionView{}
	bySecret := map[string]*secretView{}
	last := map[string]time.Time{}
	for k, t := range tallies {
		item := itemView{
			Badge: s.badge(k.secret), Session: k.session, Name: name(k.session), State: state(k.session),
			Requests: t.requests, Grants: t.grants, Uses: t.uses, Denials: t.denials,
		}
		if now.Before(t.until) {
			item.Open, item.Until, item.Left = true, s.clock(t.until, now), Short(t.until.Sub(now))
		}
		if !t.first.IsZero() {
			item.Window = s.clock(t.first, now)
			if end := s.clock(t.last, now); end != item.Window {
				item.Window = s.tr.T("usage.window", item.Window, end)
			}
		}
		for i := len(t.lines) - 1; i >= 0; i-- {
			ev := t.lines[i]
			target := ev.Host
			if ev.Path != "" && !strings.HasPrefix(ev.Path, "/") {
				target += " "
			}
			target += ev.Path
			if len(target) > 90 {
				target = target[:90] + "…"
			}
			item.Lines = append(item.Lines, lineView{When: s.clock(ev.Time, now), Method: ev.Method, Target: target,
				Status: ev.Status, Denied: ev.Decision == "denied", Reason: ev.Reason})
		}

		sv := bySession[k.session]
		if sv == nil {
			sv = &sessionView{Session: k.session, Name: item.Name, State: item.State}
			bySession[k.session] = sv
		}
		sv.Items = append(sv.Items, item)
		sv.Open = sv.Open || item.Open
		sv.High = sv.High || (item.Open && item.Badge.Risk == "high")
		if t.activity.After(last[k.session]) {
			last[k.session] = t.activity
		}

		gv := bySecret[k.secret]
		if gv == nil {
			gv = &secretView{Badge: item.Badge}
			bySecret[k.secret] = gv
		}
		gv.Items = append(gv.Items, item)
		gv.Uses += t.uses
		gv.Denials += t.denials
		if item.Open {
			gv.Open++
		}
	}

	// Items: open first, then the riskiest, then the most used.
	order := func(items []itemView) {
		sort.Slice(items, func(i, j int) bool {
			a, b := items[i], items[j]
			switch {
			case a.Open != b.Open:
				return a.Open
			case a.Badge.Risk != b.Badge.Risk:
				return riskOrder[a.Badge.Risk] < riskOrder[b.Badge.Risk]
			case a.Uses != b.Uses:
				return a.Uses > b.Uses
			case a.Badge.Name != b.Badge.Name:
				return a.Badge.Name < b.Badge.Name
			}
			return a.Session < b.Session
		})
	}
	sessions := make([]sessionView, 0, len(bySession))
	for id, sv := range bySession {
		order(sv.Items)
		if t := last[id]; !t.IsZero() {
			sv.Last = s.clock(t, now)
		}
		sessions = append(sessions, *sv)
	}
	// Clients: high risk open, then something open, then the latest activity.
	sort.Slice(sessions, func(i, j int) bool {
		a, b := sessions[i], sessions[j]
		switch {
		case a.High != b.High:
			return a.High
		case a.Open != b.Open:
			return a.Open
		case !last[a.Session].Equal(last[b.Session]):
			return last[a.Session].After(last[b.Session])
		}
		return a.Session < b.Session
	})

	secrets := make([]secretView, 0, len(bySecret))
	for _, gv := range bySecret {
		order(gv.Items)
		secrets = append(secrets, *gv)
	}
	// Credentials: the riskiest, then what is open, then the most used.
	sort.Slice(secrets, func(i, j int) bool {
		a, b := secrets[i], secrets[j]
		switch {
		case a.Badge.Risk != b.Badge.Risk:
			return riskOrder[a.Badge.Risk] < riskOrder[b.Badge.Risk]
		case a.Open != b.Open:
			return a.Open > b.Open
		case a.Uses != b.Uses:
			return a.Uses > b.Uses
		}
		return a.Badge.Name < b.Badge.Name
	})
	return sessions, secrets
}

// cooldowns groups the blocks by client: who had a request refused and
// cannot ask again yet.
func (s *Server) cooldowns(blocked []broker.Block, name func(string) string, now time.Time) []cooldownView {
	bySession := map[string]*cooldownView{}
	end := map[string]time.Time{}
	var order []string
	for _, b := range blocked {
		cv := bySession[b.Principal]
		if cv == nil {
			cv = &cooldownView{Session: b.Principal, Name: name(b.Principal)}
			bySession[b.Principal] = cv
			order = append(order, b.Principal)
		}
		cv.Credentials = append(cv.Credentials, s.badge(b.Credential))
		if b.Until.After(end[b.Principal]) {
			end[b.Principal] = b.Until
		}
	}
	sort.Strings(order)
	var out []cooldownView
	for _, id := range order {
		cv := bySession[id]
		cv.Until, cv.Left = s.clock(end[id], now), Short(end[id].Sub(now))
		out = append(out, *cv)
	}
	return out
}

// clock shows only the time for today, and day and time for other days.
func (s *Server) clock(t, now time.Time) string {
	t, now = t.In(s.zone), now.In(s.zone)
	if t.YearDay() == now.YearDay() && t.Year() == now.Year() {
		return t.Format(s.tr.T("time.today"))
	}
	return t.Format(s.tr.T("time.other_day"))
}

// noticeContext says, in a notice, whose request it was and what it took:
// ": client name (id), a, b". Empty without a known request.
func noticeContext(p broker.Request, credentials []string) string {
	who := p.Principal.Name
	if p.Principal.ID != "" {
		who = strings.TrimSpace(who + " (" + p.Principal.ID + ")")
	}
	parts := []string{}
	if who != "" {
		parts = append(parts, who)
	}
	parts = append(parts, credentials...)
	if len(parts) == 0 {
		return ""
	}
	return ": " + strings.Join(parts, ", ")
}

// Short writes a duration for a page: "5 min", "4 h", "1 h 30 min".
func Short(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%d s", int(d/time.Second))
	}
	h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)
	switch {
	case m == 0:
		return fmt.Sprintf("%d h", h)
	case h == 0:
		return fmt.Sprintf("%d min", m)
	}
	return fmt.Sprintf("%d h %d min", h, m)
}

// The actions.

func back(w http.ResponseWriter, r *http.Request, path, notice string) {
	http.Redirect(w, r, path+"?notice="+url.QueryEscape(notice), http.StatusSeeOther)
}

// closeVault seals the vault. It only reduces access, like deny and revoke:
// no passkey, only the confirmation on the page.
func (s *Server) closeVault(w http.ResponseWriter, r *http.Request) {
	if _, err := s.broker.Seal(); err != nil {
		back(w, r, "/vault", s.tr.T("vault.close_failed", err.Error()))
		return
	}
	log.Printf("web: %s closed the vault", emailOf(r))
	back(w, r, "/vault", s.tr.T("vault.closed"))
}

// revoke ends the grants of a client, or of all. It only reduces access:
// the login is enough.
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	who := r.FormValue("who")
	if who != "all" {
		grants, err := s.broker.Grants()
		if err != nil {
			back(w, r, "/", s.tr.T("err.broker", err.Error()))
			return
		}
		if !slices.ContainsFunc(grants, func(g broker.Grant) bool { return g.Principal == who }) {
			back(w, r, "/", s.tr.T("revoke.none"))
			return
		}
	}
	n, err := s.broker.Revoke(who)
	if err != nil {
		back(w, r, "/", s.tr.T("revoke.failed", err.Error()))
		return
	}
	log.Printf("web: %s revoked %s (%d grants)", emailOf(r), who, n)
	back(w, r, "/", s.tr.T("revoke.done", n))
}

// unblock ends the cooldown of a client, or of all: it may ask again at
// once. It grants nothing, so the login is enough.
func (s *Server) unblock(w http.ResponseWriter, r *http.Request) {
	who := r.FormValue("who")
	if who != "all" {
		blocked, err := s.broker.Blocked()
		if err != nil {
			back(w, r, "/", s.tr.T("err.broker", err.Error()))
			return
		}
		if !slices.ContainsFunc(blocked, func(b broker.Block) bool { return b.Principal == who }) {
			back(w, r, "/", s.tr.T("unblock.none"))
			return
		}
	}
	n, err := s.broker.Unblock(who)
	if err != nil {
		back(w, r, "/", s.tr.T("unblock.failed", err.Error()))
		return
	}
	log.Printf("web: %s ended the cooldown of %s (%d)", emailOf(r), who, n)
	back(w, r, "/", s.tr.T("unblock.done"))
}

// deny refuses a request. It only reduces access too.
func (s *Server) deny(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	p, ok := s.request(id)
	if !ok {
		back(w, r, "/", s.tr.T("request.gone"))
		return
	}
	if err := s.broker.Deny(id, r.FormValue("why")); err != nil {
		back(w, r, "/", s.tr.T("deny.failed", err.Error()))
		return
	}
	log.Printf("web: %s denied request %s", emailOf(r), id)
	back(w, r, "/", s.tr.T("deny.done")+noticeContext(p, p.Credentials)+".")
}

func (s *Server) request(id string) (broker.Request, bool) {
	requests, err := s.broker.Pending()
	if err != nil {
		return broker.Request{}, false
	}
	for _, p := range requests {
		if p.ID == id {
			return p, true
		}
	}
	return broker.Request{}, false
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

// approveBegin returns the passkey challenge to grant a request for a
// duration. The request and the duration are kept here with the challenge.
func (s *Server) approveBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Request string            `json:"request"`
		Seconds int64             `json:"seconds"`
		Codes   map[string]string `json:"codes"`
		// Only lists the credentials granted, when not all.
		Only []string `json:"only"`
		// Why is what the client reads about those left out.
		Why string `json:"why"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil {
		replyError(w, http.StatusBadRequest, s.tr.T("err.malformed"))
		return
	}
	d := time.Duration(in.Seconds) * time.Second
	if !slices.Contains(s.durations, d) {
		replyError(w, http.StatusBadRequest, s.tr.T("approve.bad_duration"))
		return
	}
	p, ok := s.request(in.Request)
	if !ok {
		replyError(w, http.StatusConflict, s.tr.T("request.gone"))
		return
	}
	// Partial grant: the names marked must be of the request, once each.
	// All marked is the whole request.
	var only []string
	for _, c := range in.Only {
		if !slices.Contains(p.Credentials, c) || slices.Contains(only, c) {
			replyError(w, http.StatusBadRequest, s.tr.T("approve.not_in_request", c))
			return
		}
		only = append(only, c)
	}
	if len(only) == len(p.Credentials) {
		only = nil
	}
	// Only the codes of the granted credentials that need one go on, and
	// all of them.
	codes := map[string]string{}
	for _, c := range p.NeedsCode {
		if len(only) > 0 && !slices.Contains(only, c) {
			continue
		}
		code := strings.TrimSpace(in.Codes[c])
		if !oneTimeCode.MatchString(code) {
			replyError(w, http.StatusBadRequest, s.tr.T("approve.need_code", c))
			return
		}
		codes[c] = code
	}
	token, options, err := s.passkeys.BeginApproval(emailOf(r), action{Request: in.Request, Duration: d, Codes: codes, Only: only, Why: in.Why})
	if err != nil {
		replyError(w, http.StatusConflict, err.Error())
		return
	}
	reply(w, map[string]any{"token": token, "options": options})
}

// approveFinish checks the passkey signature and grants the request.
func (s *Server) approveFinish(w http.ResponseWriter, r *http.Request) {
	a, err := s.passkeys.FinishApproval(emailOf(r), r.URL.Query().Get("token"), r)
	if err != nil {
		replyError(w, http.StatusForbidden, err.Error())
		return
	}
	p, _ := s.request(a.Request)
	if err := s.broker.Approve(a.Request, a.Duration, a.Codes, a.Only, a.Why); err != nil {
		replyError(w, http.StatusConflict, s.tr.T("approve.broker_refused", err.Error()))
		return
	}
	log.Printf("web: %s granted request %s for %s, with a passkey", emailOf(r), a.Request, a.Duration)
	granted := p.Credentials
	if len(a.Only) > 0 {
		granted = a.Only
	}
	reply(w, map[string]string{"notice": s.tr.T("approve.done", Short(a.Duration)) + noticeContext(p, granted) + "."})
}

func (s *Server) registerBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil {
		replyError(w, http.StatusBadRequest, s.tr.T("err.malformed"))
		return
	}
	token, options, err := s.passkeys.BeginRegistration(emailOf(r), in.Code)
	if err != nil {
		log.Printf("web: passkey registration refused for %s: %v", emailOf(r), err)
		replyError(w, http.StatusForbidden, err.Error())
		return
	}
	reply(w, map[string]any{"token": token, "options": options})
}

func (s *Server) registerFinish(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if err := s.passkeys.FinishRegistration(emailOf(r), q.Get("token"), q.Get("name"), r); err != nil {
		replyError(w, http.StatusForbidden, err.Error())
		return
	}
	log.Printf("web: %s registered a passkey", emailOf(r))
	reply(w, map[string]string{"notice": s.tr.T("passkey.registered")})
}

// sameOrigin says whether a request came from a page of this panel: the
// Origin of the panel; or, for a form posted with "Origin: null" or none,
// the Sec-Fetch-Site the browser fills and page script cannot forge.
func (s *Server) sameOrigin(r *http.Request) bool {
	switch origin := r.Header.Get("Origin"); origin {
	case s.origin:
		return true
	case "", "null":
		return r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	return false
}
