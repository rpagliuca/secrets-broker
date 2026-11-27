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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rpagliuca/secrets-broker/agestore"
	"github.com/rpagliuca/secrets-broker/broker"
)

const usage = `usage: secrets-broker <command> [flags]

  serve   -config FILE [-no-mlock]   run the proxy (starts sealed)
  token                              print a new client token and its SHA-256
  aws-credentials ACCOUNT            print temporary AWS credentials (for credential_process)
  access                             list what this client may ask for and what it holds
  request [-for 4h] NAME[=WHY]...    ask ahead, in one question, for what a task needs
  wait [-for 4h] NAME[=WHY]...       ask, and wait for the answer (exit 0 granted,
                                     2 refused in all or part, 3 no answer in 24 h)
  sql NAME TIMEOUT WHY < QUERY       ask for one query on a database, wait for the
                                     approver to read it, run it once, print TSV
  encrypt -name NAME -recipient FILE [-config FILE] [-host HOST]... [-file FILE]
          [-out DIR] [-rotation FILE [-new] [-expires 90d|DATE]]
                                     write DIR/NAME.age for the store, bound to the
                                     hosts of the names that use it

Commands sent to the control socket (-socket PATH):

  unseal                 read the vault key from standard input and unseal
  seal                   forget the vault key and every secret
  status                 report whether the broker is sealed
  pending [json]         list the requests waiting for approval
  approve ID DURATION [-only NAME,NAME] [NAME=CODE]... [-why TEXT...]
                         grant a request, for example: approve 3f9a1c22 1h
                         (NAME=CODE: one-time code of a credential that needs one)
  deny ID [TEXT...]      refuse a request; the text is shown to the client
  grants [json]          list the grants in force
  revoke PRINCIPAL|all   end grants before they expire
  blocked                list the clients kept from asking again after a refusal
  unblock PRINCIPAL|all  let them ask again at once (grants nothing)
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
	case "unseal", "seal", "status", "pending", "approve", "deny", "grants", "revoke", "blocked", "unblock":
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
	case "aws-credentials":
		// For "credential_process" in an AWS configuration file.
		addr := fs.String("url", "http://127.0.0.1:8471", "address of the broker")
		env := fs.String("token-env", "SECRETS_BROKER_TOKEN", "environment variable that holds the client token")
		fs.Parse(args)
		if fs.NArg() != 1 {
			log.Fatal("usage: secrets-broker aws-credentials [-url URL] [-token-env NAME] ACCOUNT")
		}
		req, err := http.NewRequest(http.MethodGet, *addr+"/aws/"+fs.Arg(0), nil)
		if err != nil {
			log.Fatalf("secrets-broker: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+os.Getenv(*env))
		client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("secrets-broker: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			log.Fatal(strings.TrimSpace(string(body)))
		}
		os.Stdout.Write(body)
	case "request", "access":
		// "access" lists what the client may ask for and holds; "request"
		// asks ahead for several credentials in one question.
		addr := fs.String("url", "http://127.0.0.1:8471", "address of the broker")
		env := fs.String("token-env", "SECRETS_BROKER_TOKEN", "environment variable that holds the client token")
		d := fs.String("for", "", "how long the credentials are needed, such as 4h (a suggestion to the approver)")
		fs.Parse(args)
		method, path, body := http.MethodGet, "/grants", ""
		if cmd == "request" {
			if fs.NArg() == 0 {
				log.Fatal(`usage: secrets-broker request [-for 4h] NAME[=WHY]...   (WHY: why you want it, 200 characters at most)`)
			}
			// NAME=WHY gives the reason for that credential, shown to the
			// approver as the client's own words.
			payload := struct {
				Credentials []string          `json:"credentials"`
				Duration    string            `json:"duration,omitempty"`
				Reasons     map[string]string `json:"reasons,omitempty"`
			}{Duration: *d}
			for _, a := range fs.Args() {
				name, why, has := strings.Cut(a, "=")
				payload.Credentials = append(payload.Credentials, name)
				if has {
					if payload.Reasons == nil {
						payload.Reasons = map[string]string{}
					}
					payload.Reasons[name] = why
				}
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				log.Fatalf("secrets-broker: %v", err)
			}
			method, path, body = http.MethodPost, "/requests", string(raw)
		}
		req, err := http.NewRequest(method, *addr+path, strings.NewReader(body))
		if err != nil {
			log.Fatalf("secrets-broker: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+os.Getenv(*env))
		client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("secrets-broker: %v", err)
		}
		out, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			log.Fatal(strings.TrimSpace(string(out)))
		}
		os.Stdout.Write(out)
	case "wait", "sql":
		addr := fs.String("url", "http://127.0.0.1:8471", "address of the broker")
		env := fs.String("token-env", "SECRETS_BROKER_TOKEN", "environment variable that holds the client token")
		d := fs.String("for", "", "how long the credentials are needed (wait), a suggestion to the approver")
		fs.Parse(args)
		c, err := newClient(*addr, *env)
		if err != nil {
			log.Fatalf("secrets-broker: %v", err)
		}
		if cmd == "sql" {
			if fs.NArg() != 3 {
				log.Fatal("usage: secrets-broker sql NAME TIMEOUT WHY < QUERY")
			}
			query, err := io.ReadAll(os.Stdin)
			if err != nil || strings.TrimSpace(string(query)) == "" {
				log.Fatal("secrets-broker: the query comes on standard input")
			}
			os.Exit(runSQL(c, fs.Arg(0), fs.Arg(1), fs.Arg(2), string(query), 5*time.Second, 24*time.Hour, os.Stdout, os.Stderr))
		}
		if fs.NArg() == 0 {
			log.Fatal(`usage: secrets-broker wait [-for 4h] NAME[=WHY]...`)
		}
		names, reasons := parseNames(fs.Args())
		payload := map[string]any{"credentials": names, "reasons": reasons}
		if *d != "" {
			payload["duration"] = *d
		}
		os.Exit(wait(c, payload, names, 5*time.Second, 24*time.Hour, os.Stdout, os.Stderr))
	case "encrypt":
		var o encryptOptions
		fs.StringVar(&o.name, "name", "", "name of the secret (written as DIR/NAME.age)")
		fs.StringVar(&o.file, "file", "", "file with the value, copied as is; without it, standard input without the final newline")
		fs.StringVar(&o.config, "config", "", "broker configuration, to find the hosts of the names that use the secret")
		fs.StringVar(&o.recipient, "recipient", "", "file with the vault's public key (age)")
		fs.StringVar(&o.out, "out", ".", "directory of the encrypted secrets")
		fs.StringVar(&o.rotation, "rotation", "", "rotation file to update (optional)")
		fs.BoolVar(&o.isNew, "new", false, "the value is new (it was changed at the service): record the rotation")
		fs.StringVar(&o.expires, "expires", "", "validity at the service: days (90d) or a date (2027-02-24)")
		fs.Func("host", "host the secret is bound to (repeatable); without it, from -config", func(v string) error {
			o.hosts = append(o.hosts, v)
			return nil
		})
		fs.Parse(args)
		if err := encrypt(o, os.Stdin, os.Stdout); err != nil {
			log.Fatalf("secrets-broker: %v", err)
		}
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
