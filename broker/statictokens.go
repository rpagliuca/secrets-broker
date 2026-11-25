package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// StaticTokens is an Authenticator backed by a JSON file:
//
//	{"tokens": [{"id": "agent-1", "sha256": "<hex>", "groups": ["team-a"],
//	             "expires": "2030-01-01T00:00:00Z"}]}
//
// The file stores the SHA-256 of each token, never the token. Tokens must be
// random and long (see "secrets-broker token"), which is what makes a plain
// hash enough.
type StaticTokens struct {
	path string
	mu   sync.RWMutex
	byID map[[sha256.Size]byte]staticToken
}

type staticToken struct {
	ID      string     `json:"id"`
	SHA256  string     `json:"sha256"`
	Groups  []string   `json:"groups"`
	Expires *time.Time `json:"expires,omitempty"`
}

// LoadStaticTokens reads the tokens file.
func LoadStaticTokens(path string) (*StaticTokens, error) {
	t := &StaticTokens{path: path}
	return t, t.Reload()
}

// Reload re-reads the file. On error the previous tokens stay in use.
func (t *StaticTokens) Reload() error {
	data, err := os.ReadFile(t.path)
	if err != nil {
		return err
	}
	var file struct {
		Tokens []staticToken `json:"tokens"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return fmt.Errorf("%s: %w", t.path, err)
	}
	byID := map[[sha256.Size]byte]staticToken{}
	for _, tok := range file.Tokens {
		raw, err := hex.DecodeString(tok.SHA256)
		if err != nil || len(raw) != sha256.Size || tok.ID == "" || len(tok.Groups) == 0 {
			return fmt.Errorf("%s: token %q needs id, groups and a hex sha256", t.path, tok.ID)
		}
		byID[[sha256.Size]byte(raw)] = tok
	}
	t.mu.Lock()
	t.byID = byID
	t.mu.Unlock()
	return nil
}

// Authenticate implements Authenticator.
func (t *StaticTokens) Authenticate(_ context.Context, token string) (Principal, error) {
	t.mu.RLock()
	tok, ok := t.byID[sha256.Sum256([]byte(token))]
	t.mu.RUnlock()
	if !ok {
		return Principal{}, errors.New("unknown token")
	}
	if tok.Expires != nil && time.Now().After(*tok.Expires) {
		return Principal{}, errors.New("expired token")
	}
	return Principal{ID: tok.ID, Groups: tok.Groups}, nil
}
