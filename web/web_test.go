package web

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/descope/virtualwebauthn"
	"github.com/rpagliuca/secrets-broker/broker"
)

const (
	testOrigin = "https://sb.example.test"
	testEmail  = "owner@example.test"
)

// fake is a fake broker that records what the panel told it to do.
type fake struct {
	mu        sync.Mutex
	requests  []broker.Request
	grants    []broker.Grant
	events    []broker.Event
	approved  []string
	denied    []string
	revoked   []string
	blocked   []broker.Block
	unblocked []string
	unsealed  [][]byte
	sealed    bool
	sealCalls int
}

func (f *fake) Sealed() (bool, error) { return f.sealed, nil }
func (f *fake) Pending() ([]broker.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]broker.Request(nil), f.requests...), nil
}
func (f *fake) Grants() ([]broker.Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]broker.Grant(nil), f.grants...), nil
}
func (f *fake) Approve(id string, d time.Duration, codes map[string]string, only []string, why string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec := id + " " + d.String()
	if len(only) > 0 {
		rec += " only=" + strings.Join(only, "+")
	}
	for n, c := range codes {
		rec += " " + n + "=" + c
	}
	f.approved = append(f.approved, rec)
	return nil
}
func (f *fake) Deny(id, why string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denied = append(f.denied, id)
	return nil
}
func (f *fake) Revoke(who string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, who)
	return 2, nil
}
func (f *fake) Events(time.Time) ([]broker.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]broker.Event(nil), f.events...), nil
}
func (f *fake) Blocked() ([]broker.Block, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]broker.Block(nil), f.blocked...), nil
}
func (f *fake) Unblock(who string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unblocked = append(f.unblocked, who)
	return 1, nil
}
func (f *fake) Unseal(key []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unsealed = append(f.unsealed, append([]byte(nil), key...))
	return "ok: unsealed", nil
}
func (f *fake) Seal() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sealCalls++
	return "ok: sealed", nil
}

// env is the whole panel, behind the login, with a fake broker.
type env struct {
	t        *testing.T
	fake     *fake
	login    *Login
	passkeys *Passkeys
	server   *Server
	routes   http.Handler
	cookie   *http.Cookie
	vaultKey []byte
}

func newEnv(t *testing.T, lang string) *env {
	t.Helper()
	tr, err := NewTranslator(lang)
	if err != nil {
		t.Fatal(err)
	}
	login, err := NewLogin(testOrigin, "", "client", "secret", strings.Repeat("k", 32), []string{testEmail}, tr)
	if err != nil {
		t.Fatal(err)
	}
	passkeys, err := OpenPasskeys(filepath.Join(t.TempDir(), "passkeys.json"), testOrigin, tr)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 1, 15, 0, 0, 0, time.UTC)
	f := &fake{
		requests: []broker.Request{{ID: "abc123", Principal: broker.Principal{ID: "S-1", Name: "fix the build"},
			Credentials: []string{"git-org", "ssh:git"}, Reasons: map[string]string{"git-org": "open the PR <b>of</b> the fix"},
			Created: now.Add(-2 * time.Minute), Suggested: 4 * time.Hour}},
		grants: []broker.Grant{
			{Principal: "S-2", Credential: "github", Until: now.Add(30 * time.Minute), Reason: "merge the site PR"},
			{Principal: "S-3", Credential: "aws:root", Until: now.Add(time.Hour)},
		},
	}
	pages, err := parsePages(tr)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		broker: f, passkeys: passkeys, names: noNames{}, origin: testOrigin, zone: time.UTC, tr: tr, pages: pages,
		risks: map[string]Risk{
			"github":     {Risk: "medium", Why: "writes to the repositories"},
			"ssh:github": {Risk: "medium", Why: "push to the repositories"},
			"git-org":    {Risk: "low", Why: "read"},
			"aws:root":   {Risk: "high", Why: "root key", MFA: "yk1 · Issuer (root)"},
		},
		durations:  []time.Duration{5 * time.Minute, time.Hour, 4 * time.Hour},
		now:        func() time.Time { return now },
		mfaDevices: map[string]string{"yk1": "123456"},
		mfaCommand: "ykman --device {serial} oath accounts code -s {account}",
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	s.vaultPublicKey = filepath.Join(t.TempDir(), "vault.pub")
	os.WriteFile(s.vaultPublicKey, []byte(id.Recipient().String()+"\n"), 0o644)
	e := &env{t: t, fake: f, login: login, passkeys: passkeys, server: s, routes: login.Protect(s.Routes()),
		vaultKey: []byte("# test\n" + id.String() + "\n")}
	rec := httptest.NewRecorder()
	login.setCookie(rec, cookieSession, testEmail, "/", time.Hour)
	e.cookie = rec.Result().Cookies()[0]
	return e
}

// do makes a logged-in call from the right origin.
func (e *env) do(method, path, body string, adjust ...func(*http.Request)) *httptest.ResponseRecorder {
	e.t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.AddCookie(e.cookie)
	if method != http.MethodGet {
		r.Header.Set("Origin", testOrigin)
		r.Header.Set("Content-Type", "application/json")
	}
	for _, a := range adjust {
		a(r)
	}
	rec := httptest.NewRecorder()
	e.routes.ServeHTTP(rec, r)
	return rec
}

func form(v url.Values) (string, func(*http.Request)) {
	return v.Encode(), func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }
}

func TestNothingPassesWithoutLogin(t *testing.T) {
	e := newEnv(t, "")
	noCookie := func(r *http.Request) { r.Header.Del("Cookie") }
	rec := e.do("GET", "/", "", noCookie, func(r *http.Request) { r.Header.Set("Accept", "text/html") })
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != pathSignIn {
		t.Errorf("page without login: %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	body, kind := form(url.Values{"who": {"all"}})
	if rec := e.do("POST", "/revoke", body, kind, noCookie); rec.Code != http.StatusUnauthorized {
		t.Errorf("revoke without login: %d", rec.Code)
	}
	if rec := e.do("POST", "/approve/begin", `{"request":"abc123","seconds":3600}`, noCookie); rec.Code != http.StatusUnauthorized {
		t.Errorf("approve without login: %d", rec.Code)
	}
	if len(e.fake.revoked) != 0 {
		t.Errorf("revoked without login: %v", e.fake.revoked)
	}
}

func TestActionFromAnotherOriginIsRefused(t *testing.T) {
	e := newEnv(t, "")
	body, kind := form(url.Values{"who": {"all"}})
	for _, origin := range []string{"https://other.example.test", ""} {
		rec := e.do("POST", "/revoke", body, kind, func(r *http.Request) {
			r.Header.Del("Origin")
			if origin != "" {
				r.Header.Set("Origin", origin)
			}
		})
		if rec.Code != http.StatusForbidden {
			t.Errorf("origin %q: %d", origin, rec.Code)
		}
	}
	// A form posted with "Origin: null" counts when the browser says it is
	// from the same site.
	rec := e.do("POST", "/revoke", body, kind, func(r *http.Request) {
		r.Header.Set("Origin", "null")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	})
	if rec.Code != http.StatusSeeOther || len(e.fake.revoked) != 1 {
		t.Errorf("same-site form with Origin null: %d %v", rec.Code, e.fake.revoked)
	}
}

func TestRevokeDenyUnblockOnlyWhatExists(t *testing.T) {
	e := newEnv(t, "")
	for _, who := range []string{"S-2", "all", "S-9 all"} {
		body, kind := form(url.Values{"who": {who}})
		e.do("POST", "/revoke", body, kind)
	}
	if got := strings.Join(e.fake.revoked, ","); got != "S-2,all" {
		t.Errorf("revoked = %q", got)
	}
	for _, id := range []string{"abc123", "other"} {
		body, kind := form(url.Values{"id": {id}})
		e.do("POST", "/deny", body, kind)
	}
	if got := strings.Join(e.fake.denied, ","); got != "abc123" {
		t.Errorf("denied = %q", got)
	}
	body, kind := form(url.Values{"who": {"S-5"}})
	e.do("POST", "/unblock", body, kind)
	if len(e.fake.unblocked) != 0 {
		t.Errorf("unblocked a client without cooldown: %v", e.fake.unblocked)
	}
}

// device is a fake authenticator, like a phone's.
type device struct {
	rp   virtualwebauthn.RelyingParty
	auth virtualwebauthn.Authenticator
	cred virtualwebauthn.Credential
}

func newDevice(verifies bool) *device {
	return &device{
		rp: virtualwebauthn.RelyingParty{Name: "secrets-broker", ID: "sb.example.test", Origin: testOrigin},
		auth: virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
			UserHandle: []byte(testEmail), UserNotVerified: !verifies,
		}),
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
}

type begin struct {
	Token   string          `json:"token"`
	Options json.RawMessage `json:"options"`
}

func readBegin(t *testing.T, rec *httptest.ResponseRecorder) begin {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("begin: %d %s", rec.Code, rec.Body)
	}
	var b begin
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil || b.Token == "" {
		t.Fatalf("begin: %v in %s", err, rec.Body)
	}
	return b
}

func (e *env) register(d *device, code string) int {
	e.t.Helper()
	rec := e.do("POST", "/passkey/register/begin", fmt.Sprintf(`{"code":%q}`, code))
	if rec.Code != http.StatusOK {
		return rec.Code
	}
	b := readBegin(e.t, rec)
	opts, err := virtualwebauthn.ParseAttestationOptions(string(b.Options))
	if err != nil {
		e.t.Fatal(err)
	}
	answer := virtualwebauthn.CreateAttestationResponse(d.rp, d.auth, d.cred, *opts)
	rec = e.do("POST", "/passkey/register/finish?name=Phone&token="+url.QueryEscape(b.Token), answer)
	if rec.Code == http.StatusOK {
		d.auth.AddCredential(d.cred)
	}
	return rec.Code
}

func (e *env) registered(d *device) {
	e.t.Helper()
	code, err := NewRegistrationCode(e.passkeys.path, time.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	if status := e.register(d, code); status != http.StatusOK {
		e.t.Fatalf("registration: %d", status)
	}
}

func (e *env) signApproval(d *device, body string) (string, string) {
	e.t.Helper()
	b := readBegin(e.t, e.do("POST", "/approve/begin", body))
	opts, err := virtualwebauthn.ParseAssertionOptions(string(b.Options))
	if err != nil {
		e.t.Fatal(err)
	}
	return b.Token, virtualwebauthn.CreateAssertionResponse(d.rp, d.auth, d.cred, *opts)
}

func TestApprovingNeedsAPasskey(t *testing.T) {
	e := newEnv(t, "")
	d := newDevice(true)
	if rec := e.do("POST", "/approve/begin", `{"request":"abc123","seconds":3600}`); rec.Code != http.StatusConflict {
		t.Fatalf("approve without a passkey: %d %s", rec.Code, rec.Body)
	}
	if code := e.register(d, "wrong"); code != http.StatusForbidden {
		t.Fatalf("registration with a wrong code: %d", code)
	}
	code, _ := NewRegistrationCode(e.passkeys.path, time.Now())
	if status := e.register(d, code); status != http.StatusOK {
		t.Fatalf("registration: %d", status)
	}
	if status := e.register(newDevice(true), code); status != http.StatusForbidden {
		t.Fatalf("code used twice: %d", status)
	}
	again, err := OpenPasskeys(e.passkeys.path, testOrigin, e.server.tr)
	if err != nil || len(again.List()) != 1 || again.List()[0].Name != "Phone" {
		t.Fatalf("stored passkeys = %+v, %v", again.List(), err)
	}
	if rec := e.do("POST", "/approve/begin", `{"request":"abc123","seconds":86400}`); rec.Code != http.StatusBadRequest {
		t.Errorf("duration not in the list: %d", rec.Code)
	}
	if rec := e.do("POST", "/approve/begin", `{"request":"other","seconds":3600}`); rec.Code != http.StatusConflict {
		t.Errorf("request not waiting: %d", rec.Code)
	}
	token, sig := e.signApproval(d, `{"request":"abc123","seconds":3600}`)
	if rec := e.do("POST", "/approve/finish?token="+url.QueryEscape(token), sig); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	if got := strings.Join(e.fake.approved, ","); got != "abc123 1h0m0s" {
		t.Fatalf("approved = %q", got)
	}
	if rec := e.do("POST", "/approve/finish?token="+url.QueryEscape(token), sig); rec.Code != http.StatusForbidden {
		t.Errorf("signature replayed: %d", rec.Code)
	}
	other, _ := e.signApproval(d, `{"request":"abc123","seconds":300}`)
	if rec := e.do("POST", "/approve/finish?token="+url.QueryEscape(other), sig); rec.Code != http.StatusForbidden {
		t.Errorf("signature of another challenge: %d", rec.Code)
	}
}

func TestPasskeyWithoutUserVerificationDoesNotCount(t *testing.T) {
	e := newEnv(t, "")
	code, _ := NewRegistrationCode(e.passkeys.path, time.Now())
	if status := e.register(newDevice(false), code); status != http.StatusForbidden {
		t.Fatalf("registration without user verification: %d", status)
	}
}

func TestRegistrationCodeExpires(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passkeys.json")
	now := time.Now()
	code, err := NewRegistrationCode(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if !codeMatches(path, code, now.Add(9*time.Minute)) || codeMatches(path, code, now.Add(11*time.Minute)) {
		t.Error("the code must be valid for 10 minutes")
	}
}

// Passkeys files written by earlier versions still load.
func TestOldPasskeysFileLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passkeys.json")
	os.WriteFile(path, []byte(`{"passkeys":[{"nome":"iPhone","criada":"2026-11-01T10:00:00Z","credencial":{"id":"AQID"}}]}`), 0o600)
	tr, _ := NewTranslator("")
	p, err := OpenPasskeys(path, testOrigin, tr)
	if err != nil || len(p.List()) != 1 || p.List()[0].Name != "iPhone" || len(p.List()[0].Credential.ID) != 3 {
		t.Fatalf("%+v %v", p.List(), err)
	}
}

func TestStrangeArgumentsNeverReachTheSocket(t *testing.T) {
	c := &SocketBroker{Socket: filepath.Join(t.TempDir(), "none.sock")}
	for _, who := range []string{"S-1\nseal", "a b", ""} {
		if _, err := c.Revoke(who); err == nil || !strings.Contains(err.Error(), "invalid argument") {
			t.Errorf("revoke %q: %v", who, err)
		}
	}
	if err := c.Approve("abc", time.Hour, map[string]string{"aws:x": "12a456"}, nil, ""); err == nil || !strings.Contains(err.Error(), "one-time code") {
		t.Errorf("bad code: %v", err)
	}
	if got := cleanWhy("line one\nline\ttwo\x00"); got != "line one line two" {
		t.Errorf("cleanWhy = %q", got)
	}
}

func TestCatalogsHaveTheSameKeys(t *testing.T) {
	read := func(l string) map[string]string {
		raw, err := catalogs.ReadFile("i18n/" + l + ".json")
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	en := read("en")
	verbs := regexp.MustCompile(`%[sd]`)
	for _, l := range Languages[1:] {
		other := read(l)
		for k, v := range en {
			o, ok := other[k]
			if !ok {
				t.Errorf("%s: missing %s", l, k)
				continue
			}
			if a, b := verbs.FindAllString(v, -1), verbs.FindAllString(o, -1); strings.Join(a, "") != strings.Join(b, "") {
				t.Errorf("%s: %s has %v, English %v", l, k, b, a)
			}
		}
		for k := range other {
			if _, ok := en[k]; !ok {
				t.Errorf("%s: %s is not in English", l, k)
			}
		}
	}
	// Every key the pages and the code use is in the catalog.
	srcs, _ := filepath.Glob("*.go")
	pages, _ := filepath.Glob("pages/*.html")
	use := regexp.MustCompile(`(?:tr\.T\(|\{\{t )"([a-z0-9_.]*[a-z0-9_])"`)
	for _, f := range append(srcs, pages...) {
		raw, _ := os.ReadFile(f)
		for _, m := range use.FindAllStringSubmatch(string(raw), -1) {
			if _, ok := en[m[1]]; !ok {
				t.Errorf("%s uses %s, not in the catalog", f, m[1])
			}
		}
	}
}

// Every page renders in every language, without a formatting slip.
func TestPagesRenderInEveryLanguage(t *testing.T) {
	for _, lang := range Languages {
		e := newEnv(t, lang)
		e.fake.sealed = true
		e.fake.blocked = []broker.Block{{Principal: "S-4", Credential: "github", Until: e.server.now().Add(5 * time.Minute)}}
		for _, path := range []string{"/", "/live", "/request/abc123", "/request/gone", "/usage", "/usage?view=secrets&period=7d", "/vault", "/passkey"} {
			rec := e.do("GET", path, "")
			body := rec.Body.String()
			if rec.Code != http.StatusOK || strings.Contains(body, "%!") || strings.Contains(body, "<no value>") {
				t.Errorf("%s %s: %d %s", lang, path, rec.Code, body)
			}
		}
		home := e.do("GET", "/", "").Body.String()
		if !strings.Contains(home, `<html lang="`+lang+`">`) || !strings.Contains(home, "<title>(1) secrets-broker</title>") {
			t.Errorf("%s: home head: %.400s", lang, home)
		}
		// The client's text is escaped.
		if req := e.do("GET", "/request/abc123", "").Body.String(); strings.Contains(req, "<b>of</b>") {
			t.Errorf("%s: the reason was not escaped", lang)
		}
	}
}

func TestLiveShowsTheSealedVault(t *testing.T) {
	e := newEnv(t, "")
	e.fake.sealed = true
	if body := e.do("GET", "/live", "").Body.String(); !strings.Contains(body, "notice-sealed") {
		t.Fatalf("%s", body)
	}
}

func TestMFAPathAndCommand(t *testing.T) {
	e := newEnv(t, "")
	b := e.server.badge("aws:root")
	if b.MFAKey != "yk1" || b.MFAAccount != "Issuer (root)" || b.MFACommand != `ykman --device 123456 oath accounts code -s "Issuer:root"` {
		t.Fatalf("%+v", b)
	}
	if b := e.server.badge("github"); b.MFACommand != "" {
		t.Fatalf("%+v", b)
	}
}

func TestCloseTheVault(t *testing.T) {
	e := newEnv(t, "")
	if rec := e.do("POST", "/vault/close", ""); rec.Code != http.StatusSeeOther || e.fake.sealCalls != 1 {
		t.Fatalf("%d %d", rec.Code, e.fake.sealCalls)
	}
}

func jsonBody(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// signBegin signs, on the fake device, the challenge of a "begin" answer.
func (e *env) signBegin(d *device, body []byte) (string, json.RawMessage, map[string]json.RawMessage) {
	e.t.Helper()
	var rest map[string]json.RawMessage
	if err := json.Unmarshal(body, &rest); err != nil {
		e.t.Fatalf("%v in %s", err, body)
	}
	var token string
	json.Unmarshal(rest["token"], &token)
	opts, err := virtualwebauthn.ParseAssertionOptions(string(rest["options"]))
	if err != nil {
		e.t.Fatal(err)
	}
	return token, json.RawMessage(virtualwebauthn.CreateAssertionResponse(d.rp, d.auth, d.cred, *opts)), rest
}

func TestOpenTheVaultWithAPasskey(t *testing.T) {
	e := newEnv(t, "")
	d := newDevice(true)
	e.registered(d)
	if _, err := StoreVaultKey(e.passkeys.path, e.server.vaultPublicKey, bytes.NewReader(e.vaultKey), time.Now()); err == nil {
		t.Fatal("stored the key without an enabled passkey")
	}
	// 1. Enable: the "browser" derives the key from the PRF secret and sends
	// only the public key, with a signature.
	prf := bytes.Repeat([]byte{7}, 32)
	pk, _ := passkeyKey(prf)
	rec := e.do("POST", "/vault/prf/begin", "{}")
	token, sig, _ := e.signBegin(d, rec.Body.Bytes())
	pub := base64.StdEncoding.EncodeToString(pk.PublicKey().Bytes())
	if rec := e.do("POST", "/vault/prf/finish?token="+url.QueryEscape(token), jsonBody(t, map[string]any{"signature": sig, "public": pub})); rec.Code != http.StatusOK {
		t.Fatalf("prf/finish: %d %s", rec.Code, rec.Body)
	}
	// 2. Store: only this vault's key, never in clear.
	other, _ := age.GenerateX25519Identity()
	if _, err := StoreVaultKey(e.passkeys.path, e.server.vaultPublicKey, strings.NewReader(other.String()), time.Now()); err == nil {
		t.Fatal("stored another vault's key")
	}
	if n, err := StoreVaultKey(e.passkeys.path, e.server.vaultPublicKey, bytes.NewReader(e.vaultKey), time.Now()); err != nil || n != 1 {
		t.Fatalf("stored for %d: %v", n, err)
	}
	if raw, _ := os.ReadFile(storedKeysFile(e.passkeys.path)); bytes.Contains(raw, []byte("AGE-SECRET-KEY")) {
		t.Fatal("the stored file has the key in clear")
	}
	// 3. Open.
	rec = e.do("POST", "/vault/open/begin", "{}")
	token, sig, rest := e.signBegin(d, rec.Body.Bytes())
	var envelopes map[string]wrapped
	var replyTo string
	json.Unmarshal(rest["envelopes"], &envelopes)
	json.Unmarshal(rest["reply_to"], &replyTo)
	var signed struct {
		RawID string `json:"rawId"`
	}
	json.Unmarshal(sig, &signed)
	plain, err := unwrap(pk, envelopes[signed.RawID])
	if err != nil || !bytes.Equal(plain, e.vaultKey) {
		t.Fatalf("the envelope does not give the vault key: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(replyTo)
	to, _ := ecdh.X25519().NewPublicKey(raw)
	answer, _ := wrap(to, plain)
	if rec := e.do("POST", "/vault/open/finish?token="+url.QueryEscape(token), jsonBody(t, map[string]any{"signature": sig, "key": answer})); rec.Code != http.StatusOK {
		t.Fatalf("open/finish: %d %s", rec.Code, rec.Body)
	}
	if len(e.fake.unsealed) != 1 || !bytes.Equal(e.fake.unsealed[0], e.vaultKey) {
		t.Fatalf("the broker got %d keys", len(e.fake.unsealed))
	}
}

// Files written by earlier versions of the vault page still work.
func TestOldVaultFilesLoad(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "prf.json"), []byte(`[{"credencial":"AQID","publica":"cHVi","criada":"2026-11-01T10:00:00Z"}]`), 0o600)
	os.WriteFile(filepath.Join(dir, "cofre.json"), []byte(`[{"efemera":"ZQ==","nonce":"bg==","cifrado":"Yw==","publica":"cHVi"}]`), 0o600)
	pks, err := readList[vaultPasskey](filepath.Join(dir, "prf.json"))
	if err != nil || len(pks) != 1 || pks[0].Credential != "AQID" || pks[0].Public != "cHVi" || pks[0].Created.IsZero() {
		t.Fatalf("%+v %v", pks, err)
	}
	keys, err := readList[storedKey](filepath.Join(dir, "cofre.json"))
	if err != nil || len(keys) != 1 || keys[0].Ephemeral != "ZQ==" || keys[0].Ciphertext != "Yw==" || keys[0].Public != "cHVi" {
		t.Fatalf("%+v %v", keys, err)
	}
}

// The browser's JavaScript (static/vault.js) and the server do the same
// math: what one encrypts, the other opens. Runs the file in node, which
// has the browser's WebCrypto.
func TestVaultInTheBrowserAndOnTheServerAgree(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if found, _ := filepath.Glob(os.Getenv("HOME") + "/.nvm/versions/node/*/bin/node"); len(found) > 0 {
			node = found[len(found)-1]
		} else {
			t.Skip("no node to run the vault JavaScript")
		}
	}
	prf := make([]byte, 32)
	rand.Read(prf)
	pk, _ := passkeyKey(prf)
	secret := []byte("AGE-SECRET-KEY-1NOTREAL\n")
	stored, _ := wrap(pk.PublicKey(), secret)
	replyKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	in := jsonBody(t, map[string]any{"prf": base64.StdEncoding.EncodeToString(prf), "envelope": stored,
		"reply_to": base64.StdEncoding.EncodeToString(replyKey.PublicKey().Bytes())})
	script := `
const fs = require("fs");
require("vm").runInThisContext(fs.readFileSync("static/vault.js", "utf8"));
(async () => {
  const e = JSON.parse(fs.readFileSync(0, "utf8"));
  const key = await Vault.passkeyKey(Vault.fromB64(e.prf));
  const plain = await Vault.unwrap(key, e.envelope);
  const back = await Vault.wrap(e.reply_to, plain);
  console.log(JSON.stringify({ pub: Vault.b64(key.pub), plain: Vault.b64(plain), back }));
})().catch((err) => { console.error(err); process.exit(1); });`
	cmd := exec.Command(node, "-e", script)
	cmd.Stdin = strings.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, stderr.String())
	}
	var r struct {
		Pub, Plain string
		Back       wrapped
	}
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("%v in %s", err, out)
	}
	if r.Pub != base64.StdEncoding.EncodeToString(pk.PublicKey().Bytes()) {
		t.Error("the browser derived another public key")
	}
	if p, _ := base64.StdEncoding.DecodeString(r.Plain); !bytes.Equal(p, secret) {
		t.Error("the browser did not open what the server encrypted")
	}
	if p, err := unwrap(replyKey, r.Back); err != nil || !bytes.Equal(p, secret) {
		t.Errorf("the server did not open what the browser encrypted: %v", err)
	}
}
