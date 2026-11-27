package web

// Passkeys (WebAuthn). Granting a request on the panel needs, besides the
// Google login, the signature of a passkey with user verification (Face ID,
// Touch ID or the device password). The signature is for one request and
// one duration, kept on the server with the challenge.
//
// Registering a passkey needs a one-time code made on the broker's machine
// (secrets-broker-web registration-code): the Google login alone cannot
// create the second factor.

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	ceremonyTTL = 2 * time.Minute
	codeTTL     = 10 * time.Minute
)

// Passkey is a registered passkey. Only the public key is here.
type Passkey struct {
	Name       string              `json:"name"`
	Created    time.Time           `json:"created"`
	Credential webauthn.Credential `json:"credential"`
}

// UnmarshalJSON also reads the field names of earlier versions of the file.
func (k *Passkey) UnmarshalJSON(b []byte) error {
	var v struct {
		Name       string               `json:"name"`
		Created    time.Time            `json:"created"`
		Credential *webauthn.Credential `json:"credential"`
		OldName    string               `json:"nome"`
		OldCreated time.Time            `json:"criada"`
		OldCred    *webauthn.Credential `json:"credencial"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*k = Passkey{Name: v.Name, Created: v.Created}
	if k.Name == "" {
		k.Name = v.OldName
	}
	if k.Created.IsZero() {
		k.Created = v.OldCreated
	}
	switch {
	case v.Credential != nil:
		k.Credential = *v.Credential
	case v.OldCred != nil:
		k.Credential = *v.OldCred
	}
	return nil
}

// Kinds of action a passkey signature authorizes.
const (
	kindApprove = "approve" // grant a request for a duration
	kindPRF     = "prf"     // enable the passkey to open the vault
	kindOpen    = "open"    // open the vault
)

// action is what a signature authorizes. Each signature is for one action
// of one kind, kept on the server with the challenge.
type action struct {
	Kind     string
	Request  string
	Duration time.Duration
	// Codes are the one-time codes typed with the approval.
	Codes map[string]string
	// Only, when not empty, lists the credentials granted; the rest of the
	// request is refused.
	Only []string
	// Why is what the client reads about what was left out.
	Why string
	// reply is the ephemeral key the browser encrypts the vault key for,
	// when opening (kindOpen).
	reply *ecdh.PrivateKey
}

type ceremony struct {
	session webauthn.SessionData
	email   string
	action  *action // nil when registering
	expires time.Time
}

// Passkeys keeps the registered passkeys and the ceremonies in progress.
type Passkeys struct {
	mu         sync.Mutex
	path       string
	w          *webauthn.WebAuthn
	list       []Passkey
	ceremonies map[string]*ceremony
	now        func() time.Time
	tr         *Translator
}

// OpenPasskeys reads the passkeys file; baseURL is the panel's public origin.
func OpenPasskeys(path, baseURL string, tr *Translator) (*Passkeys, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("passkeys: invalid base_url: %q", baseURL)
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "secrets-broker",
		RPOrigins:     []string{strings.TrimRight(baseURL, "/")},
	})
	if err != nil {
		return nil, err
	}
	p := &Passkeys{path: path, w: w, ceremonies: map[string]*ceremony{}, now: time.Now, tr: tr}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		var file struct {
			Passkeys []Passkey `json:"passkeys"`
		}
		if err := json.Unmarshal(raw, &file); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		p.list = file.Passkeys
	}
	return p, nil
}

// List returns the registered passkeys.
func (p *Passkeys) List() []Passkey {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Passkey(nil), p.list...)
}

// user is the owner of the passkeys: there is one, who passed the login.
type user struct {
	email       string
	credentials []webauthn.Credential
}

func (u user) WebAuthnID() []byte                         { return []byte(u.email) }
func (u user) WebAuthnName() string                       { return u.email }
func (u user) WebAuthnDisplayName() string                { return u.email }
func (u user) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (p *Passkeys) user(email string) user {
	u := user{email: email}
	for _, k := range p.list {
		u.credentials = append(u.credentials, k.Credential)
	}
	return u
}

// keep records a ceremony and returns the token that names it.
func (p *Passkeys) keep(c *ceremony) string {
	now := p.now()
	for t, old := range p.ceremonies {
		if now.After(old.expires) {
			delete(p.ceremonies, t)
		}
	}
	c.expires = now.Add(ceremonyTTL)
	token := randomToken()
	p.ceremonies[token] = c
	return token
}

// take returns the ceremony of a token and deletes it: each is used once.
func (p *Passkeys) take(token, email string, registering bool) (*ceremony, error) {
	c := p.ceremonies[token]
	delete(p.ceremonies, token)
	if c == nil || p.now().After(c.expires) || c.email != email || (c.action == nil) != registering {
		return nil, errors.New(p.tr.T("passkey.expired"))
	}
	return c, nil
}

// BeginRegistration starts registering a passkey. It needs the one-time code.
func (p *Passkeys) BeginRegistration(email, code string) (string, *protocol.CredentialCreation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !codeMatches(p.path, code, p.now()) {
		return "", nil, errors.New(p.tr.T("passkey.bad_code"))
	}
	u := p.user(email)
	var existing []protocol.CredentialDescriptor
	for i := range u.credentials {
		existing = append(existing, u.credentials[i].Descriptor())
	}
	options, session, err := p.w.BeginRegistration(u,
		webauthn.WithExclusions(existing),
		// The passkey is created with the PRF extension, which opens the
		// vault (vault.go). It must be asked for here: the library refuses
		// an answer with an extension the server did not ask for.
		webauthn.WithExtensions(webauthn.WithExtensionPRFSupport()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		}))
	if err != nil {
		return "", nil, err
	}
	return p.keep(&ceremony{session: *session, email: email}), options, nil
}

// FinishRegistration checks the device's answer and stores the passkey. The
// registration code stops working.
func (p *Passkeys) FinishRegistration(email, token, name string, r *http.Request) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, err := p.take(token, email, true)
	if err != nil {
		return err
	}
	cred, err := p.w.FinishRegistration(p.user(email), c.session, r)
	if err != nil {
		return fmt.Errorf("%s: %w", p.tr.T("passkey.not_confirmed"), err)
	}
	if !cred.Flags.UserVerified {
		return errors.New(p.tr.T("passkey.needs_uv"))
	}
	if name = strings.TrimSpace(name); name == "" {
		name = "passkey"
	}
	p.list = append(p.list, Passkey{Name: name, Created: p.now().UTC(), Credential: *cred})
	os.Remove(codePath(p.path))
	return p.save()
}

// BeginApproval starts the signature that grants a request for a duration.
func (p *Passkeys) BeginApproval(email string, a action) (string, *protocol.CredentialAssertion, error) {
	a.Kind = kindApprove
	return p.BeginSignature(email, a, nil)
}

// FinishApproval checks the signature and returns what it authorizes.
func (p *Passkeys) FinishApproval(email, token string, r *http.Request) (action, error) {
	sig, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 64<<10))
	if err != nil {
		return action{}, errors.New(p.tr.T("passkey.too_big"))
	}
	a, _, err := p.FinishSignature(email, token, kindApprove, sig)
	return a, err
}

// BeginSignature starts a signature with user verification, bound to the
// action a. With only, only the passkeys of those credentials will do.
func (p *Passkeys) BeginSignature(email string, a action, only [][]byte) (string, *protocol.CredentialAssertion, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.list) == 0 {
		return "", nil, errors.New(p.tr.T("passkey.none"))
	}
	opts := []webauthn.LoginOption{webauthn.WithUserVerification(protocol.VerificationRequired)}
	if only != nil {
		var allowed []protocol.CredentialDescriptor
		for i := range p.list {
			for _, id := range only {
				if string(p.list[i].Credential.ID) == string(id) {
					allowed = append(allowed, p.list[i].Credential.Descriptor())
				}
			}
		}
		if allowed == nil {
			return "", nil, errors.New(p.tr.T("passkey.vault_one_gone"))
		}
		opts = append(opts, webauthn.WithAllowedCredentials(allowed))
	}
	options, session, err := p.w.BeginLogin(p.user(email), opts...)
	if err != nil {
		return "", nil, err
	}
	return p.keep(&ceremony{session: *session, email: email, action: &a}), options, nil
}

// FinishSignature checks the signature (the JSON the browser returns) and
// returns the action it authorizes, which must be of the expected kind, and
// the credential that signed.
func (p *Passkeys) FinishSignature(email, token, kind string, sig []byte) (action, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, err := p.take(token, email, false)
	if err != nil {
		return action{}, nil, err
	}
	if c.action.Kind != kind {
		return action{}, nil, errors.New(p.tr.T("passkey.other_action"))
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(sig)
	if err != nil {
		return action{}, nil, fmt.Errorf("%s: %w", p.tr.T("passkey.not_confirmed"), err)
	}
	cred, err := p.w.ValidateLogin(p.user(email), c.session, parsed)
	if err != nil {
		return action{}, nil, fmt.Errorf("%s: %w", p.tr.T("passkey.not_confirmed"), err)
	}
	if !cred.Flags.UserVerified {
		return action{}, nil, errors.New(p.tr.T("passkey.no_uv"))
	}
	for i := range p.list {
		if string(p.list[i].Credential.ID) == string(cred.ID) {
			p.list[i].Credential = *cred // signature counter updated
		}
	}
	if err := p.save(); err != nil {
		return action{}, nil, err
	}
	return *c.action, cred.ID, nil
}

func (p *Passkeys) save() error {
	raw, err := json.MarshalIndent(map[string]any{"passkeys": p.list}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	tmp := p.path + ".new"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.path)
}

// The registration code is kept next to the passkeys, only as a hash:
// "<sha256 in hex> <expiry in unix>".

func codePath(passkeysPath string) string { return passkeysPath + ".codigo" }

// NewRegistrationCode makes a new registration code, replacing any other.
func NewRegistrationCode(passkeysPath string, now time.Time) (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(code))
	line := hex.EncodeToString(sum[:]) + " " + strconv.FormatInt(now.Add(codeTTL).Unix(), 10) + "\n"
	if err := os.MkdirAll(filepath.Dir(passkeysPath), 0o700); err != nil {
		return "", err
	}
	return code, os.WriteFile(codePath(passkeysPath), []byte(line), 0o600)
}

func codeMatches(passkeysPath, code string, now time.Time) bool {
	raw, err := os.ReadFile(codePath(passkeysPath))
	if err != nil {
		return false
	}
	hash, expiry, ok := strings.Cut(strings.TrimSpace(string(raw)), " ")
	exp, err := strconv.ParseInt(expiry, 10, 64)
	if !ok || err != nil || now.Unix() > exp {
		return false
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(code))))
	return subtle.ConstantTimeCompare([]byte(hash), []byte(hex.EncodeToString(sum[:]))) == 1
}

// CredentialName returns the name the passkey was registered with.
func (p *Passkeys) CredentialName(id []byte) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.list {
		if string(p.list[i].Credential.ID) == string(id) {
			return p.list[i].Name
		}
	}
	return ""
}
