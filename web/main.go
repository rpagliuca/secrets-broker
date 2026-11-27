package web

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

const usage = `usage: secrets-broker-web <command> -config FILE

  serve               runs the panel
  registration-code   makes the one-time code to register a passkey
  store-vault-key     reads the vault key from standard input and stores it
                      encrypted for the passkeys enabled on the panel
`

// Main is the secrets-broker-web command line, for this program and for
// programs that add Options (such as a SessionNames). It returns the exit
// status.
func Main(args []string, opts Options, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd := args[1]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "configuration file")
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}
	cfg, err := LoadConfig(*config)
	if err != nil {
		fmt.Fprintf(stderr, "secrets-broker-web: %v\n", err)
		return 1
	}
	switch cmd {
	case "serve":
		err = Serve(cfg, opts)
	case "registration-code":
		var code string
		if code, err = NewRegistrationCode(cfg.Passkeys, time.Now()); err == nil {
			fmt.Fprintf(stdout, "%s\n\nValid for 10 minutes, once. Type it at %s/passkey\n", code, strings.TrimRight(cfg.BaseURL, "/"))
		}
	case "store-vault-key":
		var n int
		if n, err = StoreVaultKey(cfg.Passkeys, cfg.VaultPublicKey, stdin, time.Now()); err == nil {
			fmt.Fprintf(stdout, "ok: vault key stored, encrypted for %d enabled passkey(s)\n", n)
		}
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "secrets-broker-web: %v\n", err)
		return 1
	}
	return 0
}
