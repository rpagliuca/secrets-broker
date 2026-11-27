package web

// Google login, open only to the e-mails of the configuration: OAuth 2.0
// with code and PKCE. The id_token comes straight from Google's token
// endpoint over TLS, so its claims hold without checking the signature
// (OpenID Connect Core, 3.1.3.7). Whoever passes gets an HMAC-signed cookie.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// Login paths; they need no authentication.
const (
	pathSignIn  = "/login/google"
	pathSignOut = "/login/out"
	// DefaultCallbackPath is where Google sends the browser back, unless the
	// configuration names another (it must match the OAuth client).
	DefaultCallbackPath = "/login/callback"
)

const (
	cookieSession = "sb_login"
	cookieFlow    = "sb_login_fluxo"
	flowTTL       = 10 * time.Minute
	// loginTTL is how long a login lasts. Short, because from here grants
	// are revoked and, with a passkey, given.
	loginTTL = 7 * 24 * time.Hour
	// minKeyLen in bytes: the key signs the cookies.
	minKeyLen = 32
)

// Login is the configured, validated login.
type Login struct {
	oauth    *oauth2.Config
	base     string
	callback string
	key      []byte
	emails   []string
	secure   bool
	now      func() time.Time
	tr       *Translator
	// exchange trades the code for the id_token; tests replace it.
	exchange func(ctx context.Context, code, verifier string) (string, error)
}

// NewLogin validates the configuration. The secrets come ready, from the
// environment.
func NewLogin(baseURL, callbackPath, clientID, clientSecret, key string, emails []string, tr *Translator) (*Login, error) {
	base := strings.TrimRight(baseURL, "/")
	if callbackPath == "" {
		callbackPath = DefaultCallbackPath
	}
	switch {
	case !strings.HasPrefix(base, "https://") && !strings.HasPrefix(base, "http://localhost") && !strings.HasPrefix(base, "http://127.0.0.1"):
		return nil, fmt.Errorf("login: base_url must be https:// (Google takes http only on localhost): %q", baseURL)
	case clientID == "":
		return nil, errors.New("login: client_id is missing")
	case clientSecret == "":
		return nil, errors.New("login: the client secret is missing from the environment")
	case len(key) < minKeyLen:
		return nil, fmt.Errorf("login: the cookie key needs at least %d characters", minKeyLen)
	case len(emails) == 0:
		return nil, errors.New("login: no e-mail allowed")
	}
	l := &Login{
		oauth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     endpoints.Google,
			RedirectURL:  base + callbackPath,
			Scopes:       []string{"openid", "email"},
		},
		base:     base,
		callback: callbackPath,
		key:      []byte(key),
		secure:   strings.HasPrefix(base, "https://"),
		now:      time.Now,
		tr:       tr,
	}
	for _, e := range emails {
		l.emails = append(l.emails, strings.ToLower(strings.TrimSpace(e)))
	}
	l.exchange = l.exchangeWithGoogle
	return l, nil
}

type emailKey struct{}

// emailOf returns the e-mail of who is logged in, put in the context by
// Protect.
func emailOf(r *http.Request) string {
	email, _ := r.Context().Value(emailKey{}).(string)
	return email
}

// Protect puts next behind the login: without a valid cookie, navigation
// goes to Google and other calls get 401.
func (l *Login) Protect(next http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(pathSignIn, l.signIn)
	mux.HandleFunc(l.callback, l.back)
	mux.HandleFunc(pathSignOut, l.signOut)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if email, ok := l.cookieEmail(r); ok {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), emailKey{}, email)))
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, pathSignIn, http.StatusFound)
			return
		}
		replyError(w, http.StatusUnauthorized, l.tr.T("login.required"))
	}))
	return mux
}

func replyError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"message": message})
}

// The flow keeps the state and the PKCE verifier in a short signed cookie:
// nothing stays on the server.

func (l *Login) signIn(w http.ResponseWriter, r *http.Request) {
	state := randomToken()
	verifier := oauth2.GenerateVerifier()
	l.setCookie(w, cookieFlow, state+"|"+verifier, l.callback, flowTTL)
	u := l.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("prompt", "select_account"))
	http.Redirect(w, r, u, http.StatusFound)
}

func (l *Login) back(w http.ResponseWriter, r *http.Request) {
	flow, ok := l.readCookie(r, cookieFlow)
	l.clearCookie(w, cookieFlow, l.callback)
	state, verifier, _ := strings.Cut(flow, "|")
	q := r.URL.Query()
	switch {
	case q.Get("error") != "":
		replyError(w, http.StatusUnauthorized, l.tr.T("login.google_refused", q.Get("error")))
		return
	case !ok || state == "" || !hmac.Equal([]byte(state), []byte(q.Get("state"))):
		replyError(w, http.StatusBadRequest, l.tr.T("login.stale", pathSignIn))
		return
	}
	idToken, err := l.exchange(r.Context(), q.Get("code"), verifier)
	if err != nil {
		log.Printf("login: code exchange: %v", err)
		replyError(w, http.StatusBadGateway, l.tr.T("login.exchange_failed"))
		return
	}
	email, err := l.allowedEmail(idToken)
	if err != nil {
		log.Printf("login: refused: %v", err)
		replyError(w, http.StatusForbidden, err.Error())
		return
	}
	log.Printf("login: %s signed in", email)
	l.setCookie(w, cookieSession, email, "/", loginTTL)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (l *Login) signOut(w http.ResponseWriter, r *http.Request) {
	l.clearCookie(w, cookieSession, "/")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, l.tr.T("login.signed_out", pathSignIn))
}

func (l *Login) exchangeWithGoogle(ctx context.Context, code, verifier string) (string, error) {
	token, err := l.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", err
	}
	idToken, _ := token.Extra("id_token").(string)
	if idToken == "" {
		return "", errors.New("Google answered without an id_token")
	}
	return idToken, nil
}

// allowedEmail reads the claims of the id_token, received straight from
// Google over TLS, and checks issuer, audience, expiry, verified e-mail and
// the list.
func (l *Login) allowedEmail(idToken string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed id_token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("malformed id_token: %w", err)
	}
	var c struct {
		Iss           string `json:"iss"`
		Aud           string `json:"aud"`
		Exp           int64  `json:"exp"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", fmt.Errorf("malformed id_token: %w", err)
	}
	email := strings.ToLower(c.Email)
	switch {
	case c.Iss != "https://accounts.google.com" && c.Iss != "accounts.google.com":
		return "", fmt.Errorf("id_token from another issuer: %q", c.Iss)
	case c.Aud != l.oauth.ClientID:
		return "", errors.New("id_token for another OAuth client")
	case l.now().Unix() > c.Exp:
		return "", errors.New("expired id_token")
	case !c.EmailVerified:
		return "", errors.New(l.tr.T("login.unverified", email))
	case !slices.Contains(l.emails, email):
		return "", errors.New(l.tr.T("login.not_allowed", email))
	}
	return email, nil
}

// Cookies: value|expiry in unix, signed with HMAC-SHA256, in base64.

func (l *Login) setCookie(w http.ResponseWriter, name, value, path string, ttl time.Duration) {
	exp := l.now().Add(ttl)
	content := value + "|" + strconv.FormatInt(exp.Unix(), 10)
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    base64.RawURLEncoding.EncodeToString([]byte(content)) + "." + l.sign(name, content),
		Path:     path,
		Expires:  exp,
		HttpOnly: true,
		Secure:   l.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (l *Login) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: path, MaxAge: -1, HttpOnly: true, Secure: l.secure, SameSite: http.SameSiteLaxMode})
}

func (l *Login) readCookie(r *http.Request, name string) (string, bool) {
	c, err := r.Cookie(name)
	if err != nil {
		return "", false
	}
	data, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return "", false
	}
	content := string(raw)
	if !hmac.Equal([]byte(sig), []byte(l.sign(name, content))) {
		return "", false
	}
	i := strings.LastIndex(content, "|")
	if i < 0 {
		return "", false
	}
	exp, err := strconv.ParseInt(content[i+1:], 10, 64)
	if err != nil || l.now().Unix() > exp {
		return "", false
	}
	return content[:i], true
}

// cookieEmail also checks the current list: removing an e-mail from the
// configuration undoes its login.
func (l *Login) cookieEmail(r *http.Request) (string, bool) {
	email, ok := l.readCookie(r, cookieSession)
	return email, ok && slices.Contains(l.emails, email)
}

// sign includes the cookie name, so that one cookie's value cannot serve
// as another's.
func (l *Login) sign(name, content string) string {
	m := hmac.New(sha256.New, l.key)
	m.Write([]byte(name + "\x00" + content))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func randomToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
