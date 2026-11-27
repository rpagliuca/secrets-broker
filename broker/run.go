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
	// ReloadConfig, when set, is called on SIGHUP to read the configuration
	// again. Credentials and SSH targets are replaced without a restart.
	ReloadConfig func() (*Config, error)
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
		ctl.Grants.CodeHooks(srv.needsCode, srv.unlockWithCode)
		srv.Approver = ctl.Grants
	}

	// Services come before the other clients, both to be recognised and to
	// have their fixed list instead of an approval.
	sv := &services{cfg: func() *Config { c, _ := srv.state(); return c }, auth: o.Auth}
	if ctl.Grants != nil {
		sv.inner = ctl.Grants
	}
	if ctl.Grants != nil || len(o.Config.Services) > 0 {
		srv.Approver = sv
	}
	srv.auth = sv

	errc := make(chan error, 3)
	var sp *SSHProxy
	if o.Config.SSH != nil {
		sp, err = NewSSHProxy(o.Config.SSH, o.Store, o.Auth, o.Audit)
		if err != nil {
			return err
		}
		sp.auth, sp.Approver = sv, srv.Approver
		sp.Commands = srv
		sl, err := net.Listen("tcp", o.Config.SSH.Listen)
		if err != nil {
			return err
		}
		defer sl.Close()
		if f := o.Config.SSH.KnownHostsFile; f != "" {
			if err := os.WriteFile(f, sp.KnownHosts(sl.Addr().String()), 0o644); err != nil {
				return err
			}
		}
		go func() { errc <- sp.Serve(sl) }()
		log.Printf("secrets-broker SSH proxy listening on %s", sl.Addr())
	}
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
	watched := make(chan struct{})
	wctx, stopWatch := context.WithCancel(context.Background())
	go func() { srv.WatchCommands(wctx, 5*time.Second); close(watched) }()
	swept := make(chan struct{})
	go func() { srv.WatchIssued(wctx, time.Minute); close(swept) }()
	// Commands are stopped, and their files removed, and issued tokens are
	// deleted, before Run returns.
	defer func() { stopWatch(); <-watched; <-swept }()
	hs := &http.Server{Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	go func() { errc <- hs.Serve(l) }()
	log.Printf("secrets-broker listening on %s (sealed=%t)", l.Addr(), srv.Sealed())

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			if ctl.Grants != nil {
				ctl.Grants.Close(15 * time.Second)
			}
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
			if o.ReloadConfig != nil {
				if err := reloadConfig(&o, srv, sp); err != nil {
					log.Printf("configuration NOT reloaded: %v", err)
				}
			}
			log.Printf("reloaded")
		}
	}
}

// reloadConfig applies a new configuration to the running proxies. What a
// listener or the approval table was built from only changes with a restart.
func reloadConfig(o *Options, srv *Server, sp *SSHProxy) error {
	nc, err := o.ReloadConfig()
	if err != nil {
		return err
	}
	old := o.Config
	sshListen := func(c *Config) string {
		if c.SSH == nil {
			return ""
		}
		return c.SSH.Listen
	}
	if nc.Listen != old.Listen || nc.ControlSocket != old.ControlSocket || nc.CACertFile != old.CACertFile || nc.CommandsDir != old.CommandsDir ||
		sshListen(nc) != sshListen(old) || (nc.Approval == nil) != (old.Approval == nil) {
		return errors.New("listen addresses, control socket, CA file and the presence of ssh or approval only change with a restart")
	}
	if nc.SSH != nil {
		nc.SSH.KnownHostsFile = old.SSH.KnownHostsFile
		if err := nc.SSH.validate(); err != nil {
			return err
		}
	}
	if err := srv.SetConfig(nc); err != nil {
		return err
	}
	if nc.CACertFile != "" {
		if err := os.WriteFile(nc.CACertFile, srv.CACertPEM(), 0o644); err != nil {
			return err
		}
	}
	if sp != nil {
		if err := sp.SetConfig(nc.SSH); err != nil {
			return err
		}
	}
	o.Config = nc
	return nil
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
