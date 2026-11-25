// Command secrets-broker is the reference binary: age-encrypted directory as
// the store, a tokens file as the authenticator, JSON lines on standard
// output as the audit log.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/rpagliuca/secrets-broker/agestore"
	"github.com/rpagliuca/secrets-broker/broker"
)

const usage = `usage: secrets-broker <command> [flags]

  serve   -config FILE [-no-mlock]   run the proxy (starts sealed)
  unseal  -socket PATH               read the vault key from standard input and unseal
  seal    -socket PATH               forget the vault key and every secret
  status  -socket PATH               report whether the broker is sealed
  token                              print a new client token and its SHA-256
`

func main() {
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
		if err := serve(*config, *noMlock); err != nil {
			log.Fatalf("secrets-broker: %v", err)
		}
	case "unseal", "seal", "status":
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
		reply, err := broker.Control(*socket, cmd, in)
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

func serve(configPath string, noMlock bool) error {
	cfg, err := broker.LoadConfig(configPath)
	if err != nil {
		return err
	}
	if cfg.SecretsDir == "" || cfg.TokensFile == "" || cfg.Listen == "" {
		return fmt.Errorf("%s: listen, secrets_dir and tokens_file are required", configPath)
	}
	auth, err := broker.LoadStaticTokens(cfg.TokensFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return broker.Run(ctx, broker.Options{
		Config:  cfg,
		Store:   agestore.New(cfg.SecretsDir),
		Auth:    auth,
		Audit:   broker.NewJSONAudit(os.Stdout),
		NoMlock: noMlock,
	})
}
