package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

// CloudflareToken makes a credential out of a Cloudflare token that may
// create tokens. The secret is that token, and it is never sent on a
// client's request: for each client the broker creates a token of its own,
// limited to the policies of the credential and expiring with the grant,
// sends that one, and deletes it when the grant ends.
type CloudflareToken struct {
	// AccountID makes the issued tokens account-owned (created with
	// POST /accounts/{id}/tokens, which needs "Account API Tokens Write").
	// Without it they are user tokens (POST /user/tokens, which needs
	// "API Tokens Write" and reaches every account of the user).
	AccountID string `json:"account_id,omitempty"`
	// Policies of the issued token, in the format of the Cloudflare API:
	// {"effect": "allow", "resources": {...}, "permission_groups": [{"id": "..."}]}.
	Policies []json.RawMessage `json:"policies"`
	// RequestIP, when set, limits the issued token to these addresses
	// (CIDR), as seen by Cloudflare.
	RequestIP []string `json:"request_ip,omitempty"`
	// MaxDuration is the longest an issued token lives, renewed before it
	// ends while the grant lasts (default 1h). A grant that ends sooner
	// ends the token sooner.
	MaxDuration string `json:"max_duration,omitempty"`
	// APIHost defaults to api.cloudflare.com.
	APIHost string `json:"api_host,omitempty"`
}

var (
	cloudflareIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// The resource keys of the Cloudflare API: an account, a zone, a user,
	// or every account, zone or user ("*").
	cloudflareResourceRE = regexp.MustCompile(`^com\.cloudflare\.api\.(account|account\.zone|user)\.([0-9a-f]{32}|\*)$`)
)

const (
	cloudflareDefaultLife = time.Hour
	cloudflareMinLife     = 5 * time.Minute
	cloudflareRenewBefore = 5 * time.Minute
)

func (c *CloudflareToken) apiHost() string {
	if c.APIHost != "" {
		return c.APIHost
	}
	return "api.cloudflare.com"
}

func (c *CloudflareToken) life() time.Duration {
	d, err := time.ParseDuration(c.MaxDuration)
	if err != nil || d <= 0 {
		return cloudflareDefaultLife
	}
	return d
}

// tokensPath is where tokens are created, and under which one is deleted.
func (c *CloudflareToken) tokensPath() string {
	if c.AccountID != "" {
		return "/client/v4/accounts/" + c.AccountID + "/tokens"
	}
	return "/client/v4/user/tokens"
}

func (cr *Credential) validateCloudflare() error {
	c := cr.Cloudflare
	if c == nil || len(c.Policies) == 0 {
		return fmt.Errorf("credential %q: scheme cloudflare_token needs cloudflare with policies", cr.Name)
	}
	if cr.Username != "" || cr.TokenURL != "" || cr.GitHubApp != nil {
		return fmt.Errorf("credential %q: scheme cloudflare_token takes no username, token_url or github_app", cr.Name)
	}
	// The issued token serves the API and nothing else.
	if !hostRE.MatchString(c.apiHost()) || len(cr.Hosts) != 1 || cr.Hosts[0] != c.apiHost() {
		return fmt.Errorf("credential %q: scheme cloudflare_token serves exactly the API host %q", cr.Name, c.apiHost())
	}
	if c.AccountID != "" && !cloudflareIDRE.MatchString(c.AccountID) {
		return fmt.Errorf("credential %q: account_id must be 32 lower-case hex digits", cr.Name)
	}
	if c.MaxDuration != "" {
		if d, err := time.ParseDuration(c.MaxDuration); err != nil || d < cloudflareMinLife || d > 24*time.Hour {
			return fmt.Errorf("credential %q: max_duration must be between 5m and 24h", cr.Name)
		}
	}
	for _, ip := range c.RequestIP {
		if _, err := netip.ParsePrefix(ip); err != nil {
			return fmt.Errorf("credential %q: request_ip %q is not a CIDR", cr.Name, ip)
		}
	}
	for i, raw := range c.Policies {
		if err := validCloudflarePolicy(raw); err != nil {
			return fmt.Errorf("credential %q: policy %d: %w", cr.Name, i, err)
		}
	}
	return nil
}

func validCloudflarePolicy(raw json.RawMessage) error {
	var p struct {
		Effect           string          `json:"effect"`
		Resources        json.RawMessage `json:"resources"`
		PermissionGroups []struct {
			ID string `json:"id"`
		} `json:"permission_groups"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("not a policy with effect, resources and permission_groups: %w", err)
	}
	if p.Effect != "allow" && p.Effect != "deny" {
		return errors.New("effect must be allow or deny")
	}
	if len(p.PermissionGroups) == 0 {
		return errors.New("no permission_groups")
	}
	for _, g := range p.PermissionGroups {
		if !cloudflareIDRE.MatchString(g.ID) {
			return fmt.Errorf("permission group id %q is not 32 lower-case hex digits", g.ID)
		}
	}
	return validCloudflareResources(p.Resources, 0)
}

// validCloudflareResources accepts {"<resource key>": "*"} and, one level
// down, {"<account key>": {"<zone key>": "*"}}.
func validCloudflareResources(raw json.RawMessage, depth int) error {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || len(m) == 0 {
		return errors.New("resources must be a non-empty object")
	}
	for k, v := range m {
		if !cloudflareResourceRE.MatchString(k) {
			return fmt.Errorf("unknown resource key %q", k)
		}
		if string(v) == `"*"` {
			continue
		}
		if depth > 0 || !strings.HasPrefix(k, "com.cloudflare.api.account.") || strings.HasPrefix(k, "com.cloudflare.api.account.zone.") {
			return fmt.Errorf("resource %q must be \"*\"", k)
		}
		if err := validCloudflareResources(v, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// issuedToken is one token the broker created for one client and one
// credential.
type issuedToken struct {
	id, value string
	expires   time.Time
	principal string
	cred      string // credential name
	secret    string // name of the master token in the store
	spec      string // what it was issued for, to notice a reload
	path      string // where it is deleted, under the API host
	host      string
}

// spec is what an issued token depends on: a reload that changes it makes
// the broker issue another one and delete the old.
func (c *CloudflareToken) spec() string {
	b, _ := json.Marshal([]any{c.apiHost(), c.AccountID, c.Policies, c.RequestIP})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// cloudflareAuthorization returns the Authorization header for a request of
// client p with a cloudflare_token credential, creating the client's token
// when it has none or the one it has is about to end.
func (s *Server) cloudflareAuthorization(ctx context.Context, p Principal, cred *Credential, sec Secret) (string, [][]byte, error) {
	c := cred.Cloudflare
	if !slices.Contains(sec.Hosts, c.apiHost()) {
		return "", nil, errHostNotBound
	}
	needles := [][]byte{sec.Value}
	key := p.ID + "\x00" + cred.Name
	spec := c.spec()

	s.issueMu.Lock() // one creation at a time: two requests must not issue two tokens
	defer s.issueMu.Unlock()
	s.cacheMu.Lock()
	tok, hit := s.cfCache[key]
	s.cacheMu.Unlock()

	now := time.Now()
	end := now.Add(c.life())
	if u, ok := s.Approver.(interface {
		Until(principal, credential string) time.Time
	}); ok {
		if until := u.Until(p.ID, cred.Name); !until.IsZero() && until.Before(end) {
			end = until
		}
	}
	// Cloudflare takes whole seconds; a token that would end in under a
	// minute is not worth creating.
	end = end.UTC().Truncate(time.Second)
	// The token in hand serves until shortly before it ends, or to its end
	// when a new one would not last longer (the grant ends with it).
	if hit && tok.spec == spec && now.Before(tok.expires) &&
		(tok.expires.Sub(now) >= cloudflareRenewBefore || !end.After(tok.expires)) {
		return "Bearer " + tok.value, append(needles, []byte(tok.value)), nil
	}
	if end.Sub(now) < time.Minute {
		return "", nil, errors.New("the grant ends in under a minute; ask again")
	}
	fresh, err := createCloudflareToken(ctx, s.Transport, c, sec.Value, cred.Name, p.ID, now, end)
	if err != nil {
		return "", nil, err
	}
	fresh.principal, fresh.cred, fresh.spec, fresh.secret = p.ID, cred.Name, spec, cred.secretName()
	s.cacheMu.Lock()
	if s.cfCache == nil {
		s.cfCache = map[string]issuedToken{}
	}
	s.cfCache[key] = fresh
	s.cacheMu.Unlock()
	s.audit.Record(Event{Time: now.UTC(), Decision: "allowed", Method: "token-create", Principal: p.ID, Groups: p.Groups,
		Credential: cred.Name, Host: c.apiHost(), Reason: "issued " + fresh.id + " until " + end.Format(time.RFC3339)})
	if hit {
		// The old one is replaced: it goes now rather than at its end.
		s.deleteIssued(ctx, sec.Value, tok, "renewed")
	}
	return "Bearer " + fresh.value, append(needles, []byte(fresh.value)), nil
}

func createCloudflareToken(ctx context.Context, rt http.RoundTripper, c *CloudflareToken, master []byte, credName, principal string, now, end time.Time) (issuedToken, error) {
	name := "secrets-broker " + credName + " " + principal + " " + now.UTC().Format("2006-01-02T15:04:05Z")
	if len(name) > 120 {
		name = name[:120]
	}
	in := map[string]any{"name": name, "policies": c.Policies, "expires_on": end.Format(time.RFC3339)}
	if len(c.RequestIP) > 0 {
		in["condition"] = map[string]any{"request_ip": map[string]any{"in": c.RequestIP}}
	}
	body, _ := json.Marshal(in)
	var out struct {
		Result struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		} `json:"result"`
	}
	status, err := cloudflareCall(ctx, rt, http.MethodPost, c.apiHost(), c.tokensPath(), master, body, &out)
	if err != nil {
		return issuedToken{}, fmt.Errorf("creating the token: %w", err)
	}
	if status != http.StatusOK || out.Result.ID == "" || len(out.Result.Value) < minSecretLen {
		return issuedToken{}, fmt.Errorf("Cloudflare answered %d to the token creation without a token", status)
	}
	return issuedToken{id: out.Result.ID, value: out.Result.Value, expires: end,
		path: c.tokensPath() + "/" + out.Result.ID, host: c.apiHost()}, nil
}

// cloudflareCall makes one call with the master token. Only the codes and
// messages of Cloudflare's errors are returned: they hold no secret.
func cloudflareCall(ctx context.Context, rt http.RoundTripper, method, host, path string, master, body []byte, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, "https://"+host+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+string(bytes.TrimSpace(master)))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(data, &env) != nil || !env.Success {
		var msgs []string
		for _, e := range env.Errors {
			m := e.Message
			if len(m) > 200 {
				m = m[:200]
			}
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, m))
		}
		return resp.StatusCode, fmt.Errorf("Cloudflare answered %d %q", resp.StatusCode, strings.Join(msgs, "; "))
	}
	if out != nil {
		json.Unmarshal(data, out)
	}
	return resp.StatusCode, nil
}

// deleteIssued deletes one issued token, best effort: one that cannot be
// deleted still ends at its expiry.
func (s *Server) deleteIssued(ctx context.Context, master []byte, tok issuedToken, why string) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ev := Event{Time: time.Now().UTC(), Decision: "allowed", Method: "token-delete", Principal: tok.principal,
		Credential: tok.cred, Host: tok.host, Reason: why + ": deleted " + tok.id}
	if _, err := cloudflareCall(ctx, s.Transport, http.MethodDelete, tok.host, tok.path, master, nil, nil); err != nil {
		ev.Decision, ev.Reason = "error", why+": could not delete "+tok.id+": "+err.Error()
	}
	s.audit.Record(ev)
}

// SweepIssued deletes the issued tokens that are no longer needed: the
// grant ended or was revoked, the credential left the configuration or
// changed, or the token expired. With all set (the broker is stopping) it
// deletes every one.
func (s *Server) SweepIssued(ctx context.Context, all bool) {
	cfg, _ := s.state()
	type doomed struct {
		tok issuedToken
		why string
	}
	var gone []doomed
	s.cacheMu.Lock()
	for key, tok := range s.cfCache {
		why := ""
		cred := cfg.credentialNamed(tok.cred)
		switch {
		case all:
			why = "the broker is stopping"
		case !time.Now().Before(tok.expires):
			why = "expired"
		case cred == nil || cred.Cloudflare == nil || cred.Cloudflare.spec() != tok.spec:
			why = "the credential changed"
		case s.Approver != nil && !s.Approver.Granted(tok.principal, tok.cred):
			why = "grant ended"
		}
		if why != "" {
			delete(s.cfCache, key)
			gone = append(gone, doomed{tok, why})
		}
	}
	s.cacheMu.Unlock()
	for _, d := range gone {
		// The secret is looked up again: a credential that left the
		// configuration is deleted with the secret it was issued from.
		sec, err := s.store.Get(d.tok.secret)
		if err != nil {
			s.audit.Record(Event{Time: time.Now().UTC(), Decision: "error", Method: "token-delete", Principal: d.tok.principal,
				Credential: d.tok.cred, Host: d.tok.host, Reason: d.why + ": no master token to delete " + d.tok.id + "; it ends at its expiry"})
			continue
		}
		s.deleteIssued(ctx, sec.Value, d.tok, d.why)
	}
}

// WatchIssued runs SweepIssued every interval, and once more with every
// token when ctx ends.
func (s *Server) WatchIssued(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			s.SweepIssued(context.Background(), true)
			return
		case <-tick.C:
			s.SweepIssued(ctx, false)
		}
	}
}

// credentialNamed returns the credential of that exact name, or nil.
func (c *Config) credentialNamed(name string) *Credential {
	for i := range c.Credentials {
		if c.Credentials[i].Name == name {
			return &c.Credentials[i]
		}
	}
	return nil
}
