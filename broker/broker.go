// Package broker implements a credential-injecting HTTPS proxy for clients
// that must be able to use a credential without ever seeing it, such as AI
// agents.
//
// A client opens a tunnel with CONNECT, authenticating with a token of its
// own. The broker terminates TLS, checks that the request really targets the
// host the credential is bound to, and performs the request against that host
// with the real Authorization header. The secret never travels towards the
// client, and it is never written anywhere but that one header.
//
// This package depends only on the standard library. Storage, identity and
// audit are interfaces, so each deployment plugs in its own.
package broker

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrSealed is returned by a Store that has not been unsealed yet.
	ErrSealed = errors.New("secret store is sealed")
	// ErrNotFound is returned by a Store that has no secret under a name.
	ErrNotFound = errors.New("secret not found")
)

// Secret is a credential value together with the hosts it may be sent to.
//
// The host list is stored with the value, not in the configuration: whoever
// can edit the configuration can narrow where a secret goes, but cannot
// point it at a new host.
type Secret struct {
	Value []byte
	Hosts []string
}

// Store gives access to secrets by name.
type Store interface {
	Get(name string) (Secret, error)
}

// Unsealer is implemented by stores that start sealed and are opened with a
// key delivered at run time.
type Unsealer interface {
	// Unseal loads the secrets with key and reports how many were loaded.
	Unseal(key []byte) (int, error)
	// Seal forgets every secret and the key.
	Seal()
}

// Principal is an authenticated client.
type Principal struct {
	ID     string   `json:"id"`
	Groups []string `json:"groups"`
	// Name is a label for people, shown to whoever approves requests.
	Name string `json:"name,omitempty"`
}

// Authenticator turns the token a client presents into a Principal.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (Principal, error)
}

// Event is one audit record. It never carries a secret or a client token.
type Event struct {
	Time time.Time `json:"time"`
	// Decision is "allowed" or "denied" for a request, and "requested",
	// "granted", "refused", "expired", "revoked" or "unblocked" for the
	// approval of a client.
	Decision  string `json:"decision"`
	Reason    string `json:"reason,omitempty"`
	Principal string `json:"principal,omitempty"`
	// Name is the display name of the principal. It is set on the events of
	// an approval, so that a reader of the log can tell who an id was.
	Name       string   `json:"name,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	Credential string   `json:"credential,omitempty"`
	Host       string   `json:"host,omitempty"`
	Method     string   `json:"method,omitempty"`
	Path       string   `json:"path,omitempty"`
	Status     int      `json:"status,omitempty"`
}

// Auditor receives one Event per decision the broker takes.
type Auditor interface {
	Record(Event)
}

// Reloader is implemented by stores and authenticators that can re-read
// their source on SIGHUP.
type Reloader interface {
	Reload() error
}
