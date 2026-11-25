package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Options is what a binary hands to Run.
type Options struct {
	Config *Config
	Store  Store // also an Unsealer when it starts sealed
	Auth   Authenticator
	Audit  Auditor
	// Notifier delivers approval requests to a person. Used only when the
	// configuration has an approval block; without a Notifier, requests are
	// answered through the control socket.
	Notifier Notifier
	// NoMlock skips mlockall. For development only: pages with secrets may
	// then reach swap.
	NoMlock bool
}

// Run hardens the process, writes the CA certificate, and serves the proxy
// and the control socket until ctx is cancelled. SIGHUP reloads the store
// and the authenticator when they implement Reloader.
func Run(ctx context.Context, o Options) error {
	if err := Harden(!o.NoMlock); err != nil {
		return err
	}
	srv, err := NewServer(o.Config, o.Store, o.Auth, o.Audit)
	if err != nil {
		return err
	}
	if o.Config.CACertFile != "" {
		if err := os.WriteFile(o.Config.CACertFile, srv.CACertPEM(), 0o644); err != nil {
			return err
		}
	}

	ctl := &Control{Sealed: srv.Sealed}
	ctl.Unsealer, _ = o.Store.(Unsealer)
	if o.Config.Approval != nil {
		ctl.Grants = NewGrants(*o.Config.Approval, o.Notifier, o.Audit)
		srv.Approver = ctl.Grants
	}

	errc := make(chan error, 2)
	if o.Config.ControlSocket != "" {
		cl, err := ListenControl(o.Config.ControlSocket)
		if err != nil {
			return err
		}
		defer cl.Close()
		go func() { errc <- ctl.Serve(cl) }()
	}

	l, err := net.Listen("tcp", o.Config.Listen)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	go func() { errc <- hs.Serve(l) }()
	log.Printf("secrets-broker listening on %s (sealed=%t)", l.Addr(), srv.Sealed())

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			return hs.Close()
		case err := <-errc:
			hs.Close()
			return err
		case <-hup:
			for _, x := range []any{o.Store, o.Auth} {
				if r, ok := x.(Reloader); ok {
					if err := r.Reload(); err != nil && !errors.Is(err, ErrSealed) {
						log.Printf("reload: %v", err)
					}
				}
			}
			log.Printf("reloaded")
		}
	}
}

// JSONAudit writes one JSON object per event.
type JSONAudit struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONAudit returns an Auditor that writes to w.
func NewJSONAudit(w io.Writer) *JSONAudit {
	return &JSONAudit{enc: json.NewEncoder(w)}
}

// Record implements Auditor.
func (a *JSONAudit) Record(ev Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enc.Encode(ev)
}
