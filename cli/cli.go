// Package cli is the secrets-broker command line. The reference binary
// calls Main with no customisation; a deployment with its own identity,
// audit or approval channel calls it with a Customize function and gets the
// same commands.
package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/rpagliuca/secrets-broker/agestore"
	"github.com/rpagliuca/secrets-broker/broker"
)

const usage = `usage: secrets-broker <command> [flags]

  serve   -config FILE [-no-mlock]   run the proxy (starts sealed)
  token                              print a new client token and its SHA-256

Commands sent to the control socket (-socket PATH):

  unseal                 read the vault key from standard input and unseal
  seal                   forget the vault key and every secret
  status                 report whether the broker is sealed
  pending                list the requests waiting for approval
  approve ID DURATION    grant a request, for example: approve 3f9a1c22 1h
  deny ID                refuse a request
  grants                 list the grants in force
  revoke PRINCIPAL|all   end grants before they expire
`

// Customize adjusts the options of "serve" before the broker starts. It
// receives the defaults: the age directory as the store, the tokens file as
// the authenticator when the configuration names one, and JSON lines on
// standard output as the audit log.
type Customize func(cfg *broker.Config, o *broker.Options) error

// Main runs the command line and exits.
func Main(customize Customize) {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	switch cmd {
	case "serve":
		config := fs.String("config", "", "configuration file")
		noMlock := fs.Bool("no-mlock", false, "do not lock memory (development only)")
		fs.Parse(args)
		if err := serve(*config, *noMlock, customize); err != nil {
			log.Fatalf("secrets-broker: %v", err)
		}
	case "unseal", "seal", "status", "pending", "approve", "deny", "grants", "revoke":
		socket := fs.String("socket", "/run/secrets-broker/control.sock", "control socket")
		fs.Parse(args)
		var in io.Reader // stays a nil interface unless there is a key to send
		if cmd == "unseal" {
			// The key passes through this process: keep it out of core
			// dumps and away from other processes of the same user.
			if err := broker.Harden(false); err != nil {
				log.Fatalf("secrets-broker: %v", err)
			}
			in = os.Stdin
		}
		reply, err := broker.ControlRequest(*socket, strings.Join(append([]string{cmd}, fs.Args()...), " "), in)
		if err != nil {
			log.Fatalf("secrets-broker: %v", err)
		}
		fmt.Println(reply)
	case "token":
		raw := make([]byte, 32)
		rand.Read(raw)
		token := hex.EncodeToString(raw)
		sum := sha256.Sum256([]byte(token))
		fmt.Printf("token:  %s\nsha256: %s\n", token, hex.EncodeToString(sum[:]))
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func serve(configPath string, noMlock bool, customize Customize) error {
	cfg, err := broker.LoadConfig(configPath)
	if err != nil {
		return err
	}
	if cfg.SecretsDir == "" || cfg.Listen == "" {
		return fmt.Errorf("%s: listen and secrets_dir are required", configPath)
	}
	o := broker.Options{
		Config:  cfg,
		Store:   agestore.New(cfg.SecretsDir),
		Audit:   broker.NewJSONAudit(os.Stdout),
		NoMlock: noMlock,
		ReloadConfig: func() (*broker.Config, error) {
			return broker.LoadConfig(configPath)
		},
	}
	if cfg.TokensFile != "" {
		auth, err := broker.LoadStaticTokens(cfg.TokensFile)
		if err != nil {
			return err
		}
		o.Auth = auth
	}
	if customize != nil {
		if err := customize(cfg, &o); err != nil {
			return err
		}
	}
	if o.Auth == nil {
		return errors.New("no authenticator: set tokens_file in the configuration")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return broker.Run(ctx, o)
}
