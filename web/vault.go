package web

// Opening the vault with a passkey, and the rotation page.
//
// A passkey only signs, but the WebAuthn PRF extension gives the browser,
// after user verification, a fixed secret of that passkey. The browser
// derives an X25519 key from it:
//
//   - Enable: the browser sends only the derived PUBLIC key, inside a
//     passkey signature. It is kept in prf.json.
//   - Store: whoever holds the vault key runs "secrets-broker-web
//     store-vault-key", which encrypts it for that public key and writes
//     cofre.json. The panel never sees the vault key in this step.
//   - Open: the panel sends cofre.json to the browser; after user
//     verification it derives the private key, decrypts, encrypts again
//     for an ephemeral key of the panel (so the key never crosses the
//     tunnel in clear) and sends it back. The panel hands the key to the
//     broker with the usual "unseal".
//
// Both ways use the same scheme: X25519, HKDF-SHA256 and AES-256-GCM, all
// in the browser's WebCrypto. The HKDF labels below are part of the stored
// files: changing them would lock out the passkeys already enabled.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/rpagliuca/secrets-broker/broker"
)

const (
	wrapInfo = "secrets-broker-web cofre v1" // HKDF of the encryption
	prfInfo  = "secrets-broker-web prf v1"   // HKDF from the passkey secret to the X25519 key
	saltText = "secrets-broker-web unseal v1"
)

// prfSalt is the fixed input the passkey gets in the PRF extension.
func prfSalt() []byte {
	sum := sha256.Sum256([]byte(saltText))
	return sum[:]
}

// wrapped is a value encrypted for an X25519 public key.
type wrapped struct {
	Ephemeral  string `json:"ephemeral"` // public key of who encrypted
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// UnmarshalJSON also reads the field names of earlier files.
func (w *wrapped) UnmarshalJSON(b []byte) error {
	var v struct {
		Ephemeral, Nonce, Ciphertext string
		Old1                         string `json:"efemera"`
		Old2                         string `json:"cifrado"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*w = wrapped{Ephemeral: v.Ephemeral, Nonce: v.Nonce, Ciphertext: v.Ciphertext}
	if w.Ephemeral == "" {
		w.Ephemeral = v.Old1
	}
	if w.Ciphertext == "" {
		w.Ciphertext = v.Old2
	}
	return nil
}

func wrapKey(shared, ephemeral, to []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, ephemeral...), to...), wrapInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// wrap encrypts plain for the public key to.
func wrap(to *ecdh.PublicKey, plain []byte) (wrapped, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return wrapped{}, err
	}
	shared, err := eph.ECDH(to)
	if err != nil {
		return wrapped{}, err
	}
	aead, err := wrapKey(shared, eph.PublicKey().Bytes(), to.Bytes())
	if err != nil {
		return wrapped{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return wrapped{}, err
	}
	b64 := base64.StdEncoding.EncodeToString
	return wrapped{Ephemeral: b64(eph.PublicKey().Bytes()), Nonce: b64(nonce), Ciphertext: b64(aead.Seal(nil, nonce, plain, nil))}, nil
}

// unwrap decrypts with the receiver's private key.
func unwrap(mine *ecdh.PrivateKey, w wrapped) ([]byte, error) {
	dec := base64.StdEncoding.DecodeString
	eph, err1 := dec(w.Ephemeral)
	nonce, err2 := dec(w.Nonce)
	ct, err3 := dec(w.Ciphertext)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("malformed envelope")
	}
	pub, err := ecdh.X25519().NewPublicKey(eph)
	if err != nil {
		return nil, errors.New("malformed envelope")
	}
	shared, err := mine.ECDH(pub)
	if err != nil {
		return nil, errors.New("malformed envelope")
	}
	aead, err := wrapKey(shared, eph, mine.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("malformed envelope")
	}
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("the envelope does not open with this key")
	}
	return plain, nil
}

// passkeyKey derives from a passkey's PRF secret the X25519 key, as the
// browser does. It serves the tests only: the secret never reaches the server.
func passkeyKey(prf []byte) (*ecdh.PrivateKey, error) {
	seed, err := hkdf.Key(sha256.New, prf, make([]byte, 32), prfInfo, 32)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(seed)
}

// Vault files, next to the passkeys.

// vaultPasskey is a passkey enabled to open the vault: its credential and
// the public key derived from its PRF. There may be several (a phone and a
// hardware key, for instance); each opens the vault alone.
type vaultPasskey struct {
	Credential string    `json:"credential"` // credential id, base64
	Public     string    `json:"public"`     // X25519 public key, base64
	Created    time.Time `json:"created"`
}

func (p *vaultPasskey) UnmarshalJSON(b []byte) error {
	var v struct {
		Credential, Public string
		Created            time.Time
		OldCred            string    `json:"credencial"`
		OldPublic          string    `json:"publica"`
		OldCreated         time.Time `json:"criada"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*p = vaultPasskey{Credential: v.Credential, Public: v.Public, Created: v.Created}
	if p.Credential == "" {
		p.Credential = v.OldCred
	}
	if p.Public == "" {
		p.Public = v.OldPublic
	}
	if p.Created.IsZero() {
		p.Created = v.OldCreated
	}
	return nil
}

// storedKey is the vault key encrypted for one of those passkeys.
type storedKey struct {
	wrapped
	Public  string    `json:"public"` // the public key it was encrypted for
	Created time.Time `json:"created"`
}

func (k *storedKey) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &k.wrapped); err != nil {
		return err
	}
	var v struct {
		Public     string
		Created    time.Time
		OldPublic  string    `json:"publica"`
		OldCreated time.Time `json:"criada"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	k.Public, k.Created = v.Public, v.Created
	if k.Public == "" {
		k.Public = v.OldPublic
	}
	if k.Created.IsZero() {
		k.Created = v.OldCreated
	}
	return nil
}

func vaultPasskeysFile(passkeys string) string {
	return filepath.Join(filepath.Dir(passkeys), "prf.json")
}

func storedKeysFile(passkeys string) string {
	return filepath.Join(filepath.Dir(passkeys), "cofre.json")
}

// readList reads a file holding a list; it also takes a single object.
func readList[T any](path string) ([]T, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []T
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var one T
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return []T{one}, nil
}

func readJSON(path string, v any) (bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return true, nil
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// StoreVaultKey is the "store-vault-key" command: it reads the vault key
// from in, checks it is this vault's, and stores it encrypted for each
// enabled passkey. It returns for how many.
func StoreVaultKey(passkeysPath, vaultPublicKey string, in io.Reader, now time.Time) (int, error) {
	enabled, err := readList[vaultPasskey](vaultPasskeysFile(passkeysPath))
	if err != nil {
		return 0, err
	}
	if len(enabled) == 0 {
		return 0, errors.New(`no passkey enabled for the vault: on the panel, in /vault, tap "Enable this passkey" first`)
	}
	key, err := io.ReadAll(io.LimitReader(in, 64<<10))
	if err != nil {
		return 0, err
	}
	defer clear(key)
	if err := checkVaultKey(key, vaultPublicKey); err != nil {
		return 0, err
	}
	var stored []storedKey
	for _, pk := range enabled {
		raw, err := base64.StdEncoding.DecodeString(pk.Public)
		if err != nil {
			return 0, errors.New("prf.json: malformed public key")
		}
		pub, err := ecdh.X25519().NewPublicKey(raw)
		if err != nil {
			return 0, errors.New("prf.json: malformed public key")
		}
		w, err := wrap(pub, key)
		if err != nil {
			return 0, err
		}
		stored = append(stored, storedKey{wrapped: w, Public: pk.Public, Created: now.UTC()})
	}
	return len(stored), writeJSON(storedKeysFile(passkeysPath), stored)
}

// checkVaultKey refuses what is not this vault's private key, so that
// nothing else is stored (or sent to the broker) by mistake.
func checkVaultKey(key []byte, publicKeyFile string) error {
	want, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return err
	}
	ids, err := age.ParseIdentities(bytes.NewReader(key))
	if err != nil {
		// Not wrapping the error: it may quote part of the key.
		return errors.New("the input is not an age key")
	}
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok && x.Recipient().String() == strings.TrimSpace(string(want)) {
			return nil
		}
	}
	return errors.New("the key received is not this vault's (it does not match the public key)")
}

// Rotation.

// Rotation is the rotation file: when the vault key was changed and when
// each secret got a new value. A secret without a date has a value older
// than the vault.
type Rotation struct {
	Vault struct {
		Public    string    `json:"public"`
		RotatedAt time.Time `json:"rotated_at"`
	} `json:"vault"`
	Secrets map[string]*time.Time `json:"secrets"`
	// Expiries says until when the value of each secret that has one is
	// valid at its service.
	Expiries map[string]time.Time `json:"expiries"`
}

// UnmarshalJSON also reads the key names of earlier files.
func (r *Rotation) UnmarshalJSON(b []byte) error {
	type vault struct {
		Public       string    `json:"public"`
		RotatedAt    time.Time `json:"rotated_at"`
		OldPublic    string    `json:"publica"`
		OldRotatedAt time.Time `json:"rotacionada_em"`
	}
	var v struct {
		Vault       *vault                `json:"vault"`
		OldVault    *vault                `json:"cofre"`
		Secrets     map[string]*time.Time `json:"secrets"`
		OldSecrets  map[string]*time.Time `json:"segredos"`
		Expiries    map[string]time.Time  `json:"expiries"`
		OldExpiries map[string]time.Time  `json:"vencimentos"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	vt := v.Vault
	if vt == nil {
		vt = v.OldVault
	}
	if vt != nil {
		r.Vault.Public, r.Vault.RotatedAt = vt.Public, vt.RotatedAt
		if r.Vault.Public == "" {
			r.Vault.Public = vt.OldPublic
		}
		if r.Vault.RotatedAt.IsZero() {
			r.Vault.RotatedAt = vt.OldRotatedAt
		}
	}
	r.Secrets, r.Expiries = v.Secrets, v.Expiries
	if r.Secrets == nil {
		r.Secrets = v.OldSecrets
	}
	if r.Expiries == nil {
		r.Expiries = v.OldExpiries
	}
	return nil
}

// renewAt is the share of the validity after which the panel asks for a
// renewal.
const renewAt = 0.7

// validity describes the validity of a secret: the text for the page (""
// when it does not expire), whether it is past 70% and whether it expired.
// The validity counts from the rotation date; without one, only the expiry
// warns.
func (r *Rotation) validity(file string, now time.Time, tr *Translator) (text string, renew, expired bool) {
	exp, ok := r.Expiries[file]
	if !ok || exp.IsZero() {
		return "", false, false
	}
	exp = exp.In(now.Location())
	when := exp.Format(tr.T("time.day"))
	if !now.Before(exp) {
		return tr.T("validity.expired", when), true, true
	}
	left := int(time.Date(exp.Year(), exp.Month(), exp.Day(), 0, 0, 0, 0, exp.Location()).
		Sub(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())).Hours()/24 + 0.5)
	switch left {
	case 0:
		text = tr.T("validity.today", when)
	case 1:
		text = tr.T("validity.tomorrow", when)
	default:
		text = tr.T("validity.days", left, when)
	}
	if start := r.Secrets[file]; start != nil && exp.After(*start) {
		limit := start.Add(time.Duration(float64(exp.Sub(*start)) * renewAt))
		renew = !now.Before(limit)
	}
	return text, renew, false
}

// toRenew lists, in order, the secrets past 70% of their validity or
// expired, with the validity text of each.
func (r *Rotation) toRenew(now time.Time, tr *Translator) []string {
	var out []string
	for file := range r.Expiries {
		if text, renew, _ := r.validity(file, now, tr); renew {
			out = append(out, file+": "+text)
		}
	}
	sort.Strings(out)
	return out
}

// LoadRotation reads the rotation file.
func LoadRotation(path string) (*Rotation, error) {
	var r Rotation
	exists, err := readJSON(path, &r)
	if err != nil {
		return nil, err
	}
	if !exists || r.Vault.RotatedAt.IsZero() {
		return nil, fmt.Errorf("%s: the rotation date of the vault key is missing", path)
	}
	return &r, nil
}

// secretUse is a broker name that uses a secret file. WithMFA says the key,
// under that name, is worth nothing without the one-time code: the broker
// asks for it and the provider enforces it (mfa_enforced_by_provider in the
// risks).
type secretUse struct {
	Name    string
	WithMFA bool
}

// secretUses says, for each secret file, which names use it.
func secretUses(cfg *broker.Config, risks map[string]Risk) map[string][]secretUse {
	use := map[string][]secretUse{}
	name := func(kind, n string) string {
		if strings.Contains(n, "/") {
			return n
		}
		return kind + ":" + n
	}
	or := func(secret, def string) string {
		if secret != "" {
			return secret
		}
		return def
	}
	add := func(file string, u secretUse) { use[file] = append(use[file], u) }
	for _, c := range cfg.Credentials {
		add(or(c.Secret, c.Name), secretUse{Name: c.Name})
	}
	for _, a := range cfg.AWS {
		n := name("aws", a.Name)
		add(or(a.Secret, a.Name), secretUse{Name: n, WithMFA: a.MFASerial != "" && risks[n].MFAEnforced})
	}
	if cfg.SSH != nil {
		for _, t := range cfg.SSH.Targets {
			add(or(t.Secret, t.Name), secretUse{Name: name("ssh", t.Name)})
		}
	}
	for _, c := range cfg.Commands {
		for _, f := range c.Files {
			add(f.Secret, secretUse{Name: name("command", c.Name)})
		}
	}
	return use
}

// onlyWithMFA says whether a secret only serves names whose provider
// enforces MFA: if the vault leaks, the key alone opens nothing.
func onlyWithMFA(uses []secretUse) bool {
	for _, u := range uses {
		if !u.WithMFA {
			return false
		}
	}
	return len(uses) > 0
}

// The vault page and actions.

type vaultView struct {
	Sealed bool
	// CanOpen: some enabled passkey already has the vault key stored.
	CanOpen            bool
	Passkeys           []vaultPasskeyView
	MissingKey         int // enabled passkeys still without the vault key
	KeyRotated, KeyAge string
	Pending, Total     int
	// PendingWithMFA: of the pending, those that only serve names with MFA.
	PendingWithMFA int
	Secrets        []vaultSecretView
	// ToRenew: how many secrets are past 70% of their validity or expired.
	ToRenew int
	// StoreKeyCommand is the command shown for step 2.
	StoreKeyCommand string
}

type vaultPasskeyView struct {
	Name, Enabled string
	KeyStored     bool
}

type vaultSecretView struct {
	File, Rotated string
	Pending       bool
	// WithMFA: every name using the secret needs MFA enforced by its provider.
	WithMFA bool
	Uses    []secretUse
	// Validity is the expiry text ("" when none); Renew, whether past 70%;
	// Expired, whether it expired.
	Validity       string
	Renew, Expired bool
}

// vaultState returns the enabled passkeys and, by public key, the vault key
// stored for each.
func (s *Server) vaultState() ([]vaultPasskey, map[string]storedKey, error) {
	enabled, err := readList[vaultPasskey](vaultPasskeysFile(s.passkeys.path))
	if err != nil {
		return nil, nil, err
	}
	stored, err := readList[storedKey](storedKeysFile(s.passkeys.path))
	if err != nil {
		return nil, nil, err
	}
	byPublic := map[string]storedKey{}
	for _, k := range stored {
		byPublic[k.Public] = k
	}
	return enabled, byPublic, nil
}

func (s *Server) vaultPage(w http.ResponseWriter, r *http.Request) {
	v := view{Email: emailOf(r), Notice: r.URL.Query().Get("notice"), Vault: &vaultView{StoreKeyCommand: s.storeKeyCommand}}
	c := v.Vault
	sealed, err := s.broker.Sealed()
	if err != nil {
		v.BrokerError = err.Error()
	}
	c.Sealed = sealed
	enabled, stored, err := s.vaultState()
	if err != nil {
		v.BrokerError = err.Error()
	}
	for _, pk := range enabled {
		id, _ := base64.StdEncoding.DecodeString(pk.Credential)
		name := s.passkeys.CredentialName(id)
		if name == "" {
			name = s.tr.T("vault.passkey_gone")
		}
		_, has := stored[pk.Public]
		c.Passkeys = append(c.Passkeys, vaultPasskeyView{Name: name, Enabled: pk.Created.In(s.zone).Format(s.tr.T("time.date")), KeyStored: has})
		if has {
			c.CanOpen = true
		} else {
			c.MissingKey++
		}
	}

	now := s.now()
	if s.rotation != nil {
		rot := s.rotation
		c.KeyRotated = rot.Vault.RotatedAt.In(s.zone).Format(s.tr.T("time.date"))
		c.KeyAge = s.daysAgo(rot.Vault.RotatedAt.In(s.zone), now.In(s.zone))
		uses := map[string][]secretUse{}
		if cfg, err := broker.LoadConfig(s.brokerConfig); err == nil {
			uses = secretUses(cfg, s.risks)
		}
		files := make([]string, 0, len(rot.Secrets))
		for f := range rot.Secrets {
			files = append(files, f)
		}
		sort.Strings(files)
		for _, f := range files {
			when := rot.Secrets[f]
			sv := vaultSecretView{File: f, Uses: uses[f], WithMFA: onlyWithMFA(uses[f])}
			// A rotation counts only if the new value came after the vault key.
			if when == nil || !when.After(rot.Vault.RotatedAt) {
				sv.Pending = true
				c.Pending++
				if sv.WithMFA {
					c.PendingWithMFA++
				}
			}
			if sv.Validity, sv.Renew, sv.Expired = rot.validity(f, now.In(s.zone), s.tr); sv.Renew {
				c.ToRenew++
			}
			if when == nil {
				sv.Rotated = s.tr.T("vault.older_than_vault")
			} else {
				sv.Rotated = when.In(s.zone).Format(s.tr.T("time.date"))
			}
			c.Secrets = append(c.Secrets, sv)
		}
		c.Total = len(c.Secrets)
		// What needs renewing first; then pending without MFA, pending with
		// MFA, and what is up to date.
		rank := func(v vaultSecretView) int {
			switch {
			case v.Renew:
				return -1
			case v.Pending && !v.WithMFA:
				return 0
			case v.Pending:
				return 1
			}
			return 2
		}
		sort.SliceStable(c.Secrets, func(i, j int) bool { return rank(c.Secrets[i]) < rank(c.Secrets[j]) })
	}
	s.show(w, "vault.html", v)
}

// daysAgo says how many calendar days ago: "today", "yesterday", "3 days
// ago". It counts by date, not by 24-hour periods.
func (s *Server) daysAgo(when, now time.Time) string {
	midnight := func(t time.Time) time.Time { return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location()) }
	switch n := int(midnight(now).Sub(midnight(when)).Hours()/24 + 0.5); {
	case n <= 0:
		return s.tr.T("days.today")
	case n == 1:
		return s.tr.T("days.yesterday")
	default:
		return s.tr.T("days.ago", n)
	}
}

type vaultInput struct {
	Signature json.RawMessage `json:"signature"`
	Public    string          `json:"public"` // when enabling
	Key       *wrapped        `json:"key"`    // when opening
}

func (s *Server) readVaultInput(w http.ResponseWriter, r *http.Request) (vaultInput, bool) {
	var in vaultInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&in); err != nil || len(in.Signature) == 0 {
		replyError(w, http.StatusBadRequest, s.tr.T("err.malformed"))
		return in, false
	}
	return in, true
}

// prfBegin and prfFinish enable a passkey to open the vault: the browser
// proves possession with a signature and sends the public key derived from
// its PRF.
func (s *Server) prfBegin(w http.ResponseWriter, r *http.Request) {
	token, options, err := s.passkeys.BeginSignature(emailOf(r), action{Kind: kindPRF}, nil)
	if err != nil {
		replyError(w, http.StatusConflict, err.Error())
		return
	}
	reply(w, map[string]any{"token": token, "options": options, "salt": base64.StdEncoding.EncodeToString(prfSalt())})
}

func (s *Server) prfFinish(w http.ResponseWriter, r *http.Request) {
	in, ok := s.readVaultInput(w, r)
	if !ok {
		return
	}
	_, cred, err := s.passkeys.FinishSignature(emailOf(r), r.URL.Query().Get("token"), kindPRF, in.Signature)
	if err != nil {
		replyError(w, http.StatusForbidden, err.Error())
		return
	}
	pub, err := base64.StdEncoding.DecodeString(in.Public)
	if err == nil {
		_, err = ecdh.X25519().NewPublicKey(pub)
	}
	if err != nil {
		replyError(w, http.StatusBadRequest, s.tr.T("vault.bad_public"))
		return
	}
	// The same passkey enabled again replaces its entry; the others stay.
	file := vaultPasskeysFile(s.passkeys.path)
	enabled, err := readList[vaultPasskey](file)
	if err != nil {
		replyError(w, http.StatusInternalServerError, err.Error())
		return
	}
	pk := vaultPasskey{Credential: base64.StdEncoding.EncodeToString(cred), Public: in.Public, Created: s.now().UTC()}
	enabled = append(slices.DeleteFunc(enabled, func(e vaultPasskey) bool { return e.Credential == pk.Credential }), pk)
	if err := writeJSON(file, enabled); err != nil {
		replyError(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("web: %s enabled a passkey to open the vault", emailOf(r))
	reply(w, map[string]string{"notice": s.tr.T("vault.enabled")})
}

// openBegin sends the browser the vault key encrypted for the passkey and
// an ephemeral key for the answer.
func (s *Server) openBegin(w http.ResponseWriter, r *http.Request) {
	enabled, stored, err := s.vaultState()
	if err != nil {
		replyError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Only passkeys that already have the vault key stored will do. The
	// browser gets each one's envelope, by credential id (base64url, as it
	// knows it), and uses that of the passkey that signs.
	var creds [][]byte
	envelopes := map[string]wrapped{}
	for _, pk := range enabled {
		k, has := stored[pk.Public]
		id, err := base64.StdEncoding.DecodeString(pk.Credential)
		if !has || err != nil {
			continue
		}
		creds = append(creds, id)
		envelopes[base64.RawURLEncoding.EncodeToString(id)] = k.wrapped
	}
	if len(creds) == 0 {
		replyError(w, http.StatusConflict, s.tr.T("vault.no_stored_key"))
		return
	}
	replyKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		replyError(w, http.StatusInternalServerError, err.Error())
		return
	}
	token, options, err := s.passkeys.BeginSignature(emailOf(r), action{Kind: kindOpen, reply: replyKey}, creds)
	if err != nil {
		replyError(w, http.StatusConflict, err.Error())
		return
	}
	reply(w, map[string]any{
		"token": token, "options": options, "salt": base64.StdEncoding.EncodeToString(prfSalt()),
		"envelopes": envelopes, "reply_to": base64.StdEncoding.EncodeToString(replyKey.PublicKey().Bytes()),
	})
}

// openFinish checks the signature, decrypts the key the browser sent back
// and hands it to the broker.
func (s *Server) openFinish(w http.ResponseWriter, r *http.Request) {
	in, ok := s.readVaultInput(w, r)
	if !ok {
		return
	}
	a, _, err := s.passkeys.FinishSignature(emailOf(r), r.URL.Query().Get("token"), kindOpen, in.Signature)
	if err != nil {
		replyError(w, http.StatusForbidden, err.Error())
		return
	}
	if in.Key == nil {
		replyError(w, http.StatusBadRequest, s.tr.T("vault.no_key"))
		return
	}
	key, err := unwrap(a.reply, *in.Key)
	if err != nil {
		replyError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer clear(key)
	if err := checkVaultKey(key, s.vaultPublicKey); err != nil {
		replyError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := s.broker.Unseal(key)
	if err != nil {
		log.Printf("web: %s tried to open the vault with a passkey: %v", emailOf(r), err)
		replyError(w, http.StatusConflict, s.tr.T("vault.broker_refused", err.Error()))
		return
	}
	log.Printf("web: %s opened the vault with a passkey (%s)", emailOf(r), result)
	reply(w, map[string]string{"notice": s.tr.T("vault.opened")})
}
