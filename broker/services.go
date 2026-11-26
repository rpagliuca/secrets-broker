package broker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Service is a client that runs without a person: a timer, a daemon. It
// has a token of its own and a fixed list of credentials it may use, with
// no approval step. Anything outside the list is refused, and it cannot ask
// for more. The token is a secret of the service, to be kept where only the
// service reads it; what it is worth is limited to that list, while the
// broker is unsealed.
type Service struct {
	// ID identifies the service; it appears in the audit log as "service:<id>".
	ID string `json:"id"`
	// Name is a label for people.
	Name string `json:"name,omitempty"`
	// SHA256 is the hex SHA-256 of the token (see "secrets-broker token").
	SHA256 string `json:"sha256"`
	// Groups are checked against the groups of each credential, as for any
	// client.
	Groups []string `json:"groups"`
	// Credentials are the names the service may use, as in grants:
	// "name", "ssh:<target>", "aws:<account>", "command:<name>".
	Credentials []string `json:"credentials"`
}

const servicePrefix = "service:"

var errServiceCredential = errors.New("this service may not use this credential")

// ErrNotGranted refuses a use without a grant when requests are explicit.
var ErrNotGranted = errors.New("not granted; ask first with POST /requests (secrets-broker request), then retry")

func (c *Config) validateServices() error {
	ids, sums := map[string]bool{}, map[string]bool{}
	for _, s := range c.Services {
		raw, err := hex.DecodeString(s.SHA256)
		if !nameRE.MatchString(s.ID) || ids[s.ID] || err != nil || len(raw) != sha256.Size || sums[s.SHA256] {
			return fmt.Errorf("service %q: needs a unique id and the SHA-256 of its own token", s.ID)
		}
		ids[s.ID], sums[s.SHA256] = true, true
		if len(s.Groups) == 0 || len(s.Credentials) == 0 {
			return fmt.Errorf("service %q: needs groups and credentials", s.ID)
		}
		catalog := c.catalog(s.Groups)
		for _, name := range s.Credentials {
			if _, ok := catalog[name]; !ok {
				return fmt.Errorf("service %q: %q is not something its groups may use", s.ID, name)
			}
		}
	}
	return nil
}

// services puts the configured services in front of the authenticator and
// of the approver of the other clients.
type services struct {
	cfg   func() *Config
	auth  Authenticator
	inner Approver // nil when approval is not configured
}

// open reports whether a credential needs no approval.
func (s *services) open(credential string) bool {
	cfg := s.cfg()
	return cfg.Approval != nil && slices.Contains(cfg.Approval.Open, credential)
}

func (s *services) byID(principal string) *Service {
	id, ok := strings.CutPrefix(principal, servicePrefix)
	if !ok {
		return nil
	}
	cfg := s.cfg()
	for i := range cfg.Services {
		if cfg.Services[i].ID == id {
			return &cfg.Services[i]
		}
	}
	return &Service{} // a service that left the configuration: nothing allowed
}

// Authenticate implements Authenticator.
func (s *services) Authenticate(ctx context.Context, token string) (Principal, error) {
	sum := sha256.Sum256([]byte(token))
	got := hex.EncodeToString(sum[:])
	cfg := s.cfg()
	for i := range cfg.Services {
		sv := &cfg.Services[i]
		if subtle.ConstantTimeCompare([]byte(got), []byte(strings.ToLower(sv.SHA256))) == 1 {
			return Principal{ID: servicePrefix + sv.ID, Name: sv.Name, Groups: sv.Groups}, nil
		}
	}
	p, err := s.auth.Authenticate(ctx, token)
	if err == nil && strings.HasPrefix(p.ID, servicePrefix) {
		return Principal{}, errors.New("the authenticator returned a reserved id")
	}
	return p, err
}

// Authorize implements Approver.
func (s *services) Authorize(p Principal, credential string, hosts []string) error {
	if sv := s.byID(p.ID); sv != nil {
		if slices.Contains(sv.Credentials, credential) {
			return nil
		}
		return errServiceCredential
	}
	if s.inner == nil || s.open(credential) {
		return nil
	}
	if cfg := s.cfg(); cfg.Approval != nil && cfg.Approval.ExplicitOnly && !s.inner.Granted(p.ID, credential) {
		return ErrNotGranted
	}
	return s.inner.Authorize(p, credential, hosts)
}

// Granted implements Approver.
func (s *services) Granted(principal, credential string) bool {
	if sv := s.byID(principal); sv != nil {
		return slices.Contains(sv.Credentials, credential)
	}
	return s.inner == nil || s.open(credential) || s.inner.Granted(principal, credential)
}

// Until returns when a grant ends. A service has no end; neither has a
// client when approval is not configured.
func (s *services) Until(principal, credential string) time.Time {
	if sv := s.byID(principal); sv != nil {
		if slices.Contains(sv.Credentials, credential) {
			return time.Now().Add(maxGrant)
		}
		return time.Time{}
	}
	if u, ok := s.inner.(interface {
		Until(principal, credential string) time.Time
	}); ok && !s.open(credential) {
		return u.Until(principal, credential)
	}
	return time.Now().Add(maxGrant)
}

// Request asks ahead for several credentials. A service cannot ask.
func (s *services) Request(p Principal, credentials, hosts []string, suggested time.Duration, reasons map[string]string) (string, error) {
	if s.byID(p.ID) != nil {
		return "", errors.New("a service cannot ask for approval: its credentials are fixed in the configuration")
	}
	r, ok := s.inner.(interface {
		Request(p Principal, credentials, hosts []string, suggested time.Duration, reasons map[string]string) (string, error)
	})
	if !ok {
		return "", errors.New("approval is not configured: there is nothing to ask for")
	}
	// What is open is not asked for.
	credentials = slices.DeleteFunc(slices.Clone(credentials), s.open)
	if len(credentials) == 0 {
		return "", nil
	}
	return r.Request(p, credentials, hosts, suggested, reasons)
}
