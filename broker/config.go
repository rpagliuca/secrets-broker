package broker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Config is the broker configuration. It holds no secret: it can live in
// version control and be reviewed.
type Config struct {
	// Listen is the proxy address, such as "127.0.0.1:8471". The host part
	// is mandatory, so the proxy never binds every interface by accident.
	Listen string `json:"listen"`
	// ControlSocket is the Unix socket that receives unseal and seal.
	ControlSocket string `json:"control_socket"`
	// CACertFile is where the certificate of the ephemeral CA is written at
	// start-up, for clients to trust.
	CACertFile string `json:"ca_cert_file"`
	// SecretsDir and TokensFile are used by the reference binary.
	SecretsDir string `json:"secrets_dir,omitempty"`
	TokensFile string `json:"tokens_file,omitempty"`

	// Approval, when set, makes every use of a credential depend on a
	// time-limited grant given to that client by a person.
	Approval *Approval `json:"approval,omitempty"`

	Credentials []Credential `json:"credentials"`

	// AWS lists the accounts for which clients can obtain temporary
	// credentials.
	AWS []AWSAccount `json:"aws,omitempty"`

	// Services are clients that run without a person, each with a fixed
	// list of credentials and no approval step.
	Services []Service `json:"services,omitempty"`

	// Commands are programs the broker runs for clients, with secrets
	// written to CommandsDir while they run.
	Commands    []Command `json:"commands,omitempty"`
	CommandsDir string    `json:"commands_dir,omitempty"`

	// SSH, when set, starts the SSH proxy.
	SSH *SSH `json:"ssh,omitempty"`
}

// Credential binds one secret to the hosts that receive it and to the groups
// of clients allowed to use it.
type Credential struct {
	// Name identifies the credential in the audit log.
	Name string `json:"name"`
	// Secret is the name of the secret in the Store. Defaults to Name.
	Secret string `json:"secret,omitempty"`
	// Hosts are the exact host names that receive the credential.
	Hosts []string `json:"hosts"`
	// Groups are the client groups allowed to use the credential.
	Groups []string `json:"groups"`
	// Scheme is "bearer" (Authorization: Bearer <secret>), "basic"
	// (Authorization: Basic base64(username:secret)) or "oauth2" (the
	// secret is {"client_id","client_secret","refresh_token"}; the broker
	// obtains an access token at TokenURL and sends it as Bearer).
	Scheme   string `json:"scheme"`
	Username string `json:"username,omitempty"`
	// TokenURL is the OAuth token endpoint, for scheme oauth2. The secret
	// must be bound to its host too.
	TokenURL string `json:"token_url,omitempty"`
	// Upstream, when set, is where the requests really go, as
	// "http://host:port" or "https://host:port", instead of "https://<the
	// host the client named>". It serves a service that listens on another
	// port, or without TLS on a private network that is already encrypted
	// (a VPN): the client still talks HTTPS to the broker under the name in
	// Hosts, and the secret stays bound to that name. With "http://" the
	// credential crosses that network in clear text.
	Upstream string `json:"upstream,omitempty"`
	// Methods, when set, restricts the HTTP methods (for example GET and
	// HEAD for a read-only credential).
	Methods []string `json:"methods,omitempty"`
	// GitHubApp is the app of scheme github_app (see GitHubApp).
	GitHubApp *GitHubApp `json:"github_app,omitempty"`
	// Default marks the credential used on a host that several credentials
	// serve for the same group, when the client does not name one. The
	// client names a credential as the user name of the proxy
	// (http://<credential>:<token>@broker).
	Default bool `json:"default,omitempty"`

	// template is the credential with {repo} in its name that this one was
	// resolved from, for one repository.
	template *Credential
}

var (
	nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	// pathNameRE is the name of something a client asks for. It may be a
	// path, such as "team/github/ssh/all-repositories": see grantName.
	pathNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$`)
	hostRE     = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// allowedMethods is every method the broker forwards. TRACE is left out on
// purpose (the server would echo the injected header back), and so is
// CONNECT.
var allowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

// LoadConfig reads and validates a configuration file. Unknown fields are an
// error, so a typo never silently loosens a rule.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	if c.Listen != "" {
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil || host == "" {
			return fmt.Errorf("listen %q: must be host:port with an explicit host", c.Listen)
		}
	}
	if c.Approval != nil {
		if err := c.Approval.validate(); err != nil {
			return err
		}
	}
	if c.SSH != nil {
		if err := c.SSH.validate(); err != nil {
			return err
		}
	}
	awsNames := map[string]bool{}
	for i := range c.AWS {
		if err := c.AWS[i].validate(); err != nil {
			return err
		}
		if awsNames[c.AWS[i].Name] {
			return fmt.Errorf("aws account %q: duplicate name", c.AWS[i].Name)
		}
		awsNames[c.AWS[i].Name] = true
		if c.AWS[i].MFASerial != "" && c.Approval == nil {
			return fmt.Errorf("aws account %q: mfa_serial needs approval, which is where the one-time code is typed", c.AWS[i].Name)
		}
	}
	cmdNames := map[string]bool{}
	for i := range c.Commands {
		if err := c.Commands[i].validate(); err != nil {
			return err
		}
		if cmdNames[c.Commands[i].Name] || !filepath.IsAbs(c.CommandsDir) {
			return fmt.Errorf("command %q: duplicate name, or commands_dir is not an absolute path", c.Commands[i].Name)
		}
		cmdNames[c.Commands[i].Name] = true
	}
	if err := c.grantNamesAreUnique(); err != nil {
		return err
	}
	if err := c.validateServices(); err != nil {
		return err
	}
	if c.Approval != nil {
		for _, name := range c.Approval.Open {
			if !c.known(name) {
				return fmt.Errorf("approval: open names %q, which is not configured", name)
			}
		}
	}
	if len(c.Credentials) == 0 && c.SSH == nil && len(c.AWS) == 0 {
		return fmt.Errorf("no credentials configured")
	}
	names := map[string]bool{}
	pairs := map[string][]*Credential{}
	for i := range c.Credentials {
		cr := &c.Credentials[i]
		if !pathNameRE.MatchString(strings.Replace(cr.Name, repoPlaceholder, "repo", 1)) || (cr.isTemplate() && cr.Scheme != "github_app") {
			return fmt.Errorf("credential %d: invalid name %q", i, cr.Name)
		}
		if strings.Contains(cr.Name, "/") && cr.Secret == "" {
			return fmt.Errorf("credential %q: a name that is a path needs \"secret\"", cr.Name)
		}
		if names[cr.Name] {
			return fmt.Errorf("credential %q: duplicate name", cr.Name)
		}
		names[cr.Name] = true
		if cr.Secret != "" && !nameRE.MatchString(cr.Secret) {
			return fmt.Errorf("credential %q: invalid secret name %q", cr.Name, cr.Secret)
		}
		if cr.Upstream != "" {
			u, err := url.Parse(cr.Upstream)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
				strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
				return fmt.Errorf("credential %q: upstream must be http://host[:port] or https://host[:port], and nothing else", cr.Name)
			}
			if len(cr.Hosts) != 1 {
				return fmt.Errorf("credential %q: with upstream, hosts must name exactly one host", cr.Name)
			}
		}
		switch cr.Scheme {
		case "bearer":
			if cr.Username != "" {
				return fmt.Errorf("credential %q: username is only used with scheme basic", cr.Name)
			}
		case "basic":
			if cr.Username == "" || strings.Contains(cr.Username, ":") {
				return fmt.Errorf("credential %q: scheme basic needs a username without ':'", cr.Name)
			}
		case "oauth2":
			u, err := url.Parse(cr.TokenURL)
			if err != nil || u.Scheme != "https" || !hostRE.MatchString(u.Host) || cr.Username != "" {
				return fmt.Errorf("credential %q: scheme oauth2 needs an https token_url and no username", cr.Name)
			}
		case "github_app":
			if err := cr.validateGitHubApp(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("credential %q: scheme must be bearer, basic, oauth2 or github_app", cr.Name)
		}
		if cr.Scheme != "github_app" && cr.GitHubApp != nil {
			return fmt.Errorf("credential %q: github_app is only used with scheme github_app", cr.Name)
		}
		if cr.Scheme != "oauth2" && cr.TokenURL != "" {
			return fmt.Errorf("credential %q: token_url is only used with scheme oauth2", cr.Name)
		}
		if len(cr.Hosts) == 0 || len(cr.Groups) == 0 {
			return fmt.Errorf("credential %q: needs at least one host and one group", cr.Name)
		}
		for _, m := range cr.Methods {
			if !slices.Contains(allowedMethods, m) {
				return fmt.Errorf("credential %q: method %q is not supported", cr.Name, m)
			}
		}
		for _, h := range cr.Hosts {
			if !hostRE.MatchString(h) {
				return fmt.Errorf("credential %q: host %q must be a lower-case DNS name, without port or wildcard", cr.Name, h)
			}
			for _, g := range cr.Groups {
				if g == "" {
					return fmt.Errorf("credential %q: empty group", cr.Name)
				}
				// A template serves only when the client names it, so it
				// never takes part in the choice of a default.
				if !cr.isTemplate() {
					key := h + "\x00" + g
					pairs[key] = append(pairs[key], cr)
				}
			}
		}
	}
	// Several credentials may serve one host for one group only when exactly
	// one of them is the default: there is never a silent choice.
	for key, crs := range pairs {
		if len(crs) > 1 && len(slices.DeleteFunc(slices.Clone(crs), func(cr *Credential) bool { return !cr.Default })) != 1 {
			h, g, _ := strings.Cut(key, "\x00")
			return fmt.Errorf("credentials %q and %q both serve host %s for group %s: mark exactly one as default", crs[0].Name, crs[1].Name, h, g)
		}
	}
	return nil
}

// hosts returns every configured host, sorted and without repetition.
func (c *Config) hosts() []string {
	var out []string
	for _, cr := range c.Credentials {
		out = append(out, cr.Hosts...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// credentialFor returns the credential bound to host that a client in groups
// may use. When there is none, the second value says why.
// credentialFor chooses the credential of a client on a host. want is the
// user name the client gave to the proxy: when it is the name of a
// credential, that one is used or nothing; otherwise the only credential, or
// the default among several.
func (c *Config) credentialFor(host string, groups []string, want string) (*Credential, string) {
	if cr := c.resolveTemplate(want); cr != nil {
		switch {
		case !slices.Contains(cr.Hosts, host):
			return nil, "the named credential does not serve this client on this host"
		case !slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(cr.Groups, g) }):
			return nil, "the named credential does not serve this client on this host"
		}
		return cr, ""
	}
	var found, named, byDefault *Credential
	known, wantIsName, n := false, false, 0
	for i := range c.Credentials {
		cr := &c.Credentials[i]
		if cr.isTemplate() {
			continue // serves only by one of its names, above
		}
		wantIsName = wantIsName || cr.Name == want
		if !slices.Contains(cr.Hosts, host) {
			continue
		}
		known = true
		if !slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(cr.Groups, g) }) {
			continue
		}
		found, n = cr, n+1
		if cr.Name == want {
			named = cr
		}
		if cr.Default {
			byDefault = cr
		}
	}
	switch {
	case named != nil:
		return named, ""
	case wantIsName:
		return nil, "the named credential does not serve this client on this host"
	case n > 1 && byDefault != nil:
		return byDefault, ""
	case n > 1:
		return nil, "more than one credential matches this client on this host"
	case found != nil:
		return found, ""
	case known:
		return nil, "this client may not use a credential on this host"
	default:
		return nil, "host is not configured"
	}
}

// resolveTemplate returns the credential that name stands for through a
// name with {repo}, or nil.
func (c *Config) resolveTemplate(name string) *Credential {
	for i := range c.Credentials {
		if cr := c.Credentials[i].resolve(name); cr != nil {
			return cr
		}
	}
	return nil
}

func (cr *Credential) secretName() string {
	if cr.Secret != "" {
		return cr.Secret
	}
	return cr.Name
}

func (cr *Credential) allows(method string) bool {
	if !slices.Contains(allowedMethods, method) {
		return false
	}
	return len(cr.Methods) == 0 || slices.Contains(cr.Methods, method)
}

// authorization builds the Authorization header value for secret.
func (cr *Credential) authorization(secret []byte) string {
	if cr.Scheme == "basic" {
		return "Basic " + base64.StdEncoding.EncodeToString(append([]byte(cr.Username+":"), secret...))
	}
	return "Bearer " + string(secret)
}

// normalizeHost lower-cases a host name and drops a trailing dot.
func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// grantName is the name of a credential, account, target or command in
// grants and requests. A plain name carries its kind in front ("ssh:web",
// "aws:prod", "command:vpn"; a proxied credential has none). A name that is
// a path ("team/aws/prod/read-only") says its kind where the writer wants
// it and is used whole, so that the approver reads one name, chosen to
// state the most that it gives access to.
func grantName(kind, name string) string {
	if kind == "" || strings.Contains(name, "/") {
		return name
	}
	return kind + ":" + name
}

// grantNamesAreUnique refuses two things of different kinds under the same
// name in grants, which path names make possible.
func (c *Config) grantNamesAreUnique() error {
	seen := map[string]bool{}
	add := func(name string) error {
		if seen[name] {
			return fmt.Errorf("%q names more than one thing a client can ask for", name)
		}
		seen[name] = true
		return nil
	}
	for i := range c.Credentials {
		if err := add(c.Credentials[i].Name); err != nil {
			return err
		}
	}
	for i := range c.AWS {
		if err := add(c.AWS[i].grantName()); err != nil {
			return err
		}
	}
	for i := range c.Commands {
		if err := add(c.Commands[i].grantName()); err != nil {
			return err
		}
	}
	if c.SSH != nil {
		for i := range c.SSH.Targets {
			if err := add(c.SSH.Targets[i].grantName()); err != nil {
				return err
			}
		}
	}
	// A name with {repo} stands for many: none of them may be another
	// thing's name, and two of them may not meet.
	for i := range c.Credentials {
		a := &c.Credentials[i]
		if !a.isTemplate() {
			continue
		}
		for name := range seen {
			if a.resolve(name) != nil {
				return fmt.Errorf("%q is also a name of %q", name, a.Name)
			}
		}
		for j := i + 1; j < len(c.Credentials); j++ {
			if b := &c.Credentials[j]; b.isTemplate() && templatesOverlap(a.Name, b.Name) {
				return fmt.Errorf("%q and %q may name the same thing", a.Name, b.Name)
			}
		}
	}
	return nil
}
