package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rpagliuca/secrets-broker/broker"
)

// Config is the JSON file of the panel. Secrets are never in it: they come
// from the environment variables it names. Paths take $HOME and
// $XDG_RUNTIME_DIR.
type Config struct {
	// Listen is where the panel listens; loopback only.
	Listen string `json:"listen"`
	// BaseURL is the public origin (https://…). Passkeys are for this
	// domain, and Google returns to BaseURL + CallbackPath.
	BaseURL      string `json:"base_url"`
	CallbackPath string `json:"callback_path,omitempty"`
	ClientID     string `json:"client_id"`
	// ClientSecretEnv and CookieKeyEnv name the environment variables.
	ClientSecretEnv string   `json:"client_secret_env"`
	CookieKeyEnv    string   `json:"cookie_key_env"`
	Emails          []string `json:"emails"`
	// ControlSocket and BrokerUnit say where the broker is; BrokerConfig,
	// where the durations it accepts come from.
	ControlSocket string `json:"control_socket"`
	BrokerUnit    string `json:"broker_unit"`
	BrokerConfig  string `json:"broker_config"`
	// Passkeys is the file of registered passkeys (public keys only).
	Passkeys string `json:"passkeys"`
	// Risks classifies the credentials (see Risk).
	Risks string `json:"risks"`
	// Rotation and VaultPublicKey serve the vault page.
	Rotation       string `json:"rotation"`
	VaultPublicKey string `json:"vault_public_key"`
	// Language of the pages: "en" (default) or "pt-BR".
	Language string `json:"language,omitempty"`
	// TimeZone of the times shown, as in the tz database. Default UTC.
	TimeZone string `json:"time_zone,omitempty"`
	// MFADevices maps the key names used in the risks ("yk1") to their
	// serial numbers, and MFACodeCommand is the command shown to copy a
	// code: {serial} and {account} ("Issuer:account", quoted) are filled,
	// e.g. ykman --device {serial} oath accounts code -s {account}.
	MFADevices     map[string]string `json:"mfa_devices,omitempty"`
	MFACodeCommand string            `json:"mfa_code_command,omitempty"`
	// StoreKeyCommand is shown on the vault page, to store the vault key
	// for the enabled passkeys from where that key is kept. Default: the
	// plain store-vault-key command.
	StoreKeyCommand string `json:"store_key_command,omitempty"`
}

// LoadConfig reads the panel's configuration.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, p := range []*string{&cfg.ControlSocket, &cfg.BrokerConfig, &cfg.Passkeys, &cfg.Risks, &cfg.Rotation, &cfg.VaultPublicKey} {
		*p = os.ExpandEnv(*p)
	}
	switch {
	case cfg.ControlSocket == "" || cfg.BrokerUnit == "" || cfg.BrokerConfig == "" || cfg.Passkeys == "":
		return nil, fmt.Errorf("%s: control_socket, broker_unit, broker_config and passkeys are required", path)
	case !loopback(cfg.Listen):
		return nil, fmt.Errorf("%s: listen must be a loopback address (127.0.0.1:port): %q", path, cfg.Listen)
	}
	return &cfg, nil
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// brokerDurations reads the durations the broker accepts in a grant.
func brokerDurations(path string) ([]time.Duration, error) {
	cfg, err := broker.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	if cfg.Approval == nil || len(cfg.Approval.Durations) == 0 {
		return nil, fmt.Errorf("%s: no approval.durations", path)
	}
	var out []time.Duration
	for _, d := range cfg.Approval.Durations {
		out = append(out, time.Duration(d))
	}
	return out, nil
}

// Options are what a program built on the panel may add.
type Options struct {
	// Names gives clients a name and a state (optional).
	Names SessionNames
}

// parsePages parses the templates with the translator's functions.
func parsePages(tr *Translator) (*template.Template, error) {
	return template.New("").Funcs(template.FuncMap{
		"t":    tr.T,
		"lang": tr.Lang,
	}).ParseFS(files, "pages/*.html")
}

// NewServer builds the panel from its configuration.
func NewServer(cfg *Config, opts Options) (*Server, *Login, error) {
	tr, err := NewTranslator(cfg.Language)
	if err != nil {
		return nil, nil, err
	}
	if cfg.ClientSecretEnv == "" || cfg.CookieKeyEnv == "" {
		return nil, nil, errors.New("client_secret_env and cookie_key_env are required")
	}
	login, err := NewLogin(cfg.BaseURL, cfg.CallbackPath, cfg.ClientID, os.Getenv(cfg.ClientSecretEnv), os.Getenv(cfg.CookieKeyEnv), cfg.Emails, tr)
	if err != nil {
		return nil, nil, err
	}
	passkeys, err := OpenPasskeys(cfg.Passkeys, cfg.BaseURL, tr)
	if err != nil {
		return nil, nil, err
	}
	durations, err := brokerDurations(cfg.BrokerConfig)
	if err != nil {
		return nil, nil, err
	}
	risks, err := LoadRisks(cfg.Risks)
	if err != nil {
		return nil, nil, err
	}
	var rotation *Rotation
	if cfg.Rotation != "" {
		if rotation, err = LoadRotation(cfg.Rotation); err != nil {
			return nil, nil, err
		}
	}
	zone := time.UTC
	if cfg.TimeZone != "" {
		if zone, err = time.LoadLocation(cfg.TimeZone); err != nil {
			return nil, nil, fmt.Errorf("time_zone: %w", err)
		}
	}
	pages, err := parsePages(tr)
	if err != nil {
		return nil, nil, err
	}
	names := opts.Names
	if names == nil {
		names = noNames{}
	}
	s := &Server{
		broker:          &SocketBroker{Socket: cfg.ControlSocket, Unit: cfg.BrokerUnit},
		passkeys:        passkeys,
		names:           names,
		risks:           risks,
		rotation:        rotation,
		brokerConfig:    cfg.BrokerConfig,
		vaultPublicKey:  cfg.VaultPublicKey,
		durations:       durations,
		origin:          strings.TrimRight(cfg.BaseURL, "/"),
		zone:            zone,
		now:             time.Now,
		tr:              tr,
		pages:           pages,
		mfaDevices:      cfg.MFADevices,
		mfaCommand:      cfg.MFACodeCommand,
		storeKeyCommand: cfg.StoreKeyCommand,
	}
	if s.storeKeyCommand == "" {
		s.storeKeyCommand = "secrets-broker-web store-vault-key -config <file> < vault-key"
	}
	return s, login, nil
}

// Serve runs the panel until it fails.
func Serve(cfg *Config, opts Options) error {
	s, login, err := NewServer(cfg, opts)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           login.Protect(s.Routes()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	log.Printf("secrets-broker-web: listening on %s, published as %s", cfg.Listen, s.origin)
	return server.ListenAndServe()
}
