// Package agestore is a broker.Store backed by a directory of age-encrypted
// files, decrypted into memory when the vault key is delivered.
//
// Each secret is one file, <name>.age, whose plaintext is a JSON object:
//
//	{"value": "the-credential", "hosts": ["api.example.com"]}
//
// The files are encrypted to the vault recipient (a public key), so adding a
// secret needs no access to the vault key:
//
//	jq -Rc '{value: ., hosts: ["api.example.com"]}' | age -r age1... -o name.age
//
// The host list travels inside the encrypted file: only someone who knows
// the secret can decide where it may be sent.
package agestore

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/rpagliuca/secrets-broker/broker"
)

// maxSecretFile bounds the plaintext of one secret file.
const maxSecretFile = 64 << 10

// Store implements broker.Store, broker.Unsealer and broker.Reloader.
type Store struct {
	dir string

	mu         sync.RWMutex
	identities []age.Identity
	secrets    map[string]broker.Secret
}

// New returns a sealed store over dir.
func New(dir string) *Store { return &Store{dir: dir} }

// Get implements broker.Store.
func (s *Store) Get(name string) (broker.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.secrets == nil {
		return broker.Secret{}, broker.ErrSealed
	}
	sec, ok := s.secrets[name]
	if !ok {
		return broker.Secret{}, fmt.Errorf("%w: %s", broker.ErrNotFound, name)
	}
	return sec, nil
}

// Unseal parses key (one or more age identities, as written by age-keygen)
// and decrypts every file of the directory. If any file fails, the store
// keeps its previous state.
func (s *Store) Unseal(key []byte) (int, error) {
	ids, err := age.ParseIdentities(bytes.NewReader(key))
	if err != nil {
		// Never wrap err: a parse error may quote part of the key.
		return 0, errors.New("the vault key is not a valid age identity")
	}
	secrets, err := s.load(ids)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.identities, s.secrets = ids, secrets
	s.mu.Unlock()
	return len(secrets), nil
}

// Reload decrypts the directory again with the key already in memory, to
// pick up secrets added since the unseal.
func (s *Store) Reload() error {
	s.mu.RLock()
	ids := s.identities
	s.mu.RUnlock()
	if ids == nil {
		return broker.ErrSealed
	}
	secrets, err := s.load(ids)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.identities != nil { // not sealed in the meantime
		s.secrets = secrets
	}
	s.mu.Unlock()
	return nil
}

// Seal forgets the key and every secret.
func (s *Store) Seal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sec := range s.secrets {
		clear(sec.Value)
	}
	s.identities, s.secrets = nil, nil
}

func (s *Store) load(ids []age.Identity) (map[string]broker.Secret, error) {
	files, err := filepath.Glob(filepath.Join(s.dir, "*.age"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.age file in %s", s.dir)
	}
	secrets := map[string]broker.Secret{}
	for _, path := range files {
		name := strings.TrimSuffix(filepath.Base(path), ".age")
		sec, err := decrypt(path, ids)
		if err != nil {
			return nil, fmt.Errorf("secret %s: %w", name, err)
		}
		secrets[name] = sec
	}
	return secrets, nil
}

func decrypt(path string, ids []age.Identity) (broker.Secret, error) {
	f, err := os.Open(path)
	if err != nil {
		return broker.Secret{}, err
	}
	defer f.Close()
	var src io.Reader = bufio.NewReader(f)
	if head, _ := src.(*bufio.Reader).Peek(len(armor.Header)); string(head) == armor.Header {
		src = armor.NewReader(src)
	}
	plain, err := age.Decrypt(src, ids...)
	if err != nil {
		return broker.Secret{}, err
	}
	data, err := io.ReadAll(io.LimitReader(plain, maxSecretFile+1))
	if err != nil {
		return broker.Secret{}, err
	}
	defer clear(data)
	if len(data) > maxSecretFile {
		return broker.Secret{}, errors.New("file is too large")
	}
	var doc struct {
		Value string   `json:"value"`
		Hosts []string `json:"hosts"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		// Never wrap err: a JSON syntax error may quote the plaintext.
		return broker.Secret{}, errors.New(`plaintext must be a JSON object {"value": "...", "hosts": ["..."]}`)
	}
	if doc.Value == "" || len(doc.Hosts) == 0 {
		return broker.Secret{}, errors.New("value and hosts are both required")
	}
	return broker.Secret{Value: []byte(doc.Value), Hosts: doc.Hosts}, nil
}
