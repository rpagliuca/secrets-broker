package broker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// GitHubApp makes a credential out of a GitHub App: the secret is the
// private key of the app, and what reaches the service is an installation
// token, which GitHub issues for one hour and for the repositories and
// permissions asked for. The client never holds either.
type GitHubApp struct {
	// AppID is the app ID or the client ID of the app (the JWT issuer).
	AppID string `json:"app_id"`
	// InstallationID is the installation on the account or organisation
	// that owns the repositories.
	InstallationID int64 `json:"installation_id"`
	// Repositories limits the token to these repositories of the
	// installation, by name without the owner. A credential whose name
	// holds {repo} is limited to the repository of the name instead.
	// Without either, the token reaches every repository of the
	// installation.
	Repositories []string `json:"repositories,omitempty"`
	// Permissions are those of the token, such as {"contents": "write"};
	// at most what the installation has. Required.
	Permissions map[string]string `json:"permissions"`
	// APIHost is where tokens are asked for. Defaults to api.github.com.
	// Requests to this host carry the token as Bearer; requests to any
	// other host of the credential (github.com, for git over HTTPS) carry
	// it as Basic with the user x-access-token.
	APIHost string `json:"api_host,omitempty"`
}

// repoPlaceholder in a credential name stands for any repository: the
// client names one, and the grant, the log and the token are for that one.
const repoPlaceholder = "{repo}"

var (
	repoNameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)
	permissionRE = regexp.MustCompile(`^[a-z_]{1,64}$`)
)

func (g *GitHubApp) apiHost() string {
	if g.APIHost != "" {
		return g.APIHost
	}
	return "api.github.com"
}

func (cr *Credential) isTemplate() bool { return strings.Contains(cr.Name, repoPlaceholder) }

func (cr *Credential) validateGitHubApp() error {
	g := cr.GitHubApp
	if g == nil || g.AppID == "" || g.InstallationID <= 0 || len(g.Permissions) == 0 {
		return fmt.Errorf("credential %q: scheme github_app needs github_app with app_id, installation_id and permissions", cr.Name)
	}
	if cr.Username != "" || cr.TokenURL != "" || cr.Default {
		return fmt.Errorf("credential %q: scheme github_app takes no username, token_url or default", cr.Name)
	}
	if !hostRE.MatchString(g.apiHost()) || !slices.Contains(cr.Hosts, g.apiHost()) {
		return fmt.Errorf("credential %q: the API host %q must be one of the hosts", cr.Name, g.apiHost())
	}
	for k, v := range g.Permissions {
		if !permissionRE.MatchString(k) || (v != "read" && v != "write" && v != "admin") {
			return fmt.Errorf("credential %q: permission %q: %q must be read, write or admin", cr.Name, k, v)
		}
	}
	for _, r := range g.Repositories {
		if !repoNameRE.MatchString(r) {
			return fmt.Errorf("credential %q: invalid repository %q", cr.Name, r)
		}
	}
	if cr.isTemplate() {
		pre, post, _ := strings.Cut(cr.Name, repoPlaceholder)
		if strings.Contains(post, repoPlaceholder) || (pre != "" && !strings.HasSuffix(pre, "/")) || (post != "" && !strings.HasPrefix(post, "/")) {
			return fmt.Errorf("credential %q: {repo} must be one whole part of the name, once", cr.Name)
		}
		if len(g.Repositories) > 0 {
			return fmt.Errorf("credential %q: a name with {repo} takes no repositories list", cr.Name)
		}
		if cr.Secret == "" {
			return fmt.Errorf("credential %q: a name with {repo} needs \"secret\"", cr.Name)
		}
	}
	return nil
}

// resolve returns the credential that a template stands for under name, or
// nil when name is not one of its names.
func (cr *Credential) resolve(name string) *Credential {
	if !cr.isTemplate() || cr.GitHubApp == nil {
		return nil
	}
	pre, post, _ := strings.Cut(cr.Name, repoPlaceholder)
	repo, ok := strings.CutPrefix(name, pre)
	if !ok {
		return nil
	}
	if repo, ok = strings.CutSuffix(repo, post); !ok || !repoNameRE.MatchString(repo) || strings.HasSuffix(repo, ".git") {
		return nil
	}
	out := *cr
	g := *cr.GitHubApp
	g.Repositories = []string{repo}
	out.GitHubApp, out.Name, out.template = &g, name, cr
	return &out
}

// sameCredential tells whether a and b are the same credential of the same
// configuration: the same entry, or the same name of the same template.
func sameCredential(a, b *Credential) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a == b || (a.template != nil && a.template == b.template && a.Name == b.Name)
}

// templatesOverlap tells whether some name matches both templates.
func templatesOverlap(a, b string) bool {
	apre, apost, _ := strings.Cut(a, repoPlaceholder)
	bpre, bpost, _ := strings.Cut(b, repoPlaceholder)
	return (strings.HasPrefix(apre, bpre) || strings.HasPrefix(bpre, apre)) &&
		(strings.HasSuffix(apost, bpost) || strings.HasSuffix(bpost, apost))
}

// githubAppAuthorization returns the Authorization header for one request
// of a GitHub App credential, asking GitHub for an installation token when
// there is none in memory, or when it is about to expire.
func (s *Server) githubAppAuthorization(ctx context.Context, cred *Credential, sec Secret, host string) (string, [][]byte, error) {
	g := cred.GitHubApp
	if !slices.Contains(sec.Hosts, g.apiHost()) {
		return "", nil, errHostNotBound
	}
	needles := [][]byte{sec.Value}
	key, err := parseRSAKey(sec.Value)
	if err != nil {
		return "", nil, err
	}
	needles = append(needles, key.D.Bytes())
	// The token is kept for what it was issued for: a reload that changes
	// the repositories or the permissions gets a new one.
	what, _ := json.Marshal([]any{g.AppID, g.InstallationID, g.Repositories, g.Permissions})
	cacheKey := "github_app\x00" + cred.Name + "\x00" + string(what)
	s.cacheMu.Lock()
	tok, hit := s.oauthCache[cacheKey]
	s.cacheMu.Unlock()
	if !hit || time.Until(tok.expires) < 5*time.Minute {
		if tok, err = installationToken(ctx, s.Transport, g, key, time.Now()); err != nil {
			return "", nil, err
		}
		s.cacheMu.Lock()
		if s.oauthCache == nil {
			s.oauthCache = map[string]oauthToken{}
		}
		s.oauthCache[cacheKey] = tok
		s.cacheMu.Unlock()
	}
	needles = append(needles, []byte(tok.access))
	if host == g.apiHost() {
		return "Bearer " + tok.access, needles, nil
	}
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + tok.access))
	return "Basic " + basic, append(needles, []byte(basic)), nil
}

func parseRSAKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes.TrimSpace(pemBytes))
	if block == nil {
		return nil, errors.New("the secret is not a PEM private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if rk, ok := k.(*rsa.PrivateKey); err == nil && ok {
		return rk, nil
	}
	return nil, errors.New("the secret is not an RSA private key")
}

// appJWT is the token that authenticates as the app itself, valid for ten
// minutes (GitHub accepts at most ten), back-dated one minute for clock
// drift.
func appJWT(appID string, key *rsa.PrivateKey, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": appID})
	signed := header + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signed + "." + enc.EncodeToString(sig), nil
}

func installationToken(ctx context.Context, rt http.RoundTripper, g *GitHubApp, key *rsa.PrivateKey, now time.Time) (oauthToken, error) {
	jwt, err := appJWT(g.AppID, key, now)
	if err != nil {
		return oauthToken{}, err
	}
	body, _ := json.Marshal(map[string]any{"repositories": g.Repositories, "permissions": g.Permissions})
	if len(g.Repositories) == 0 {
		body, _ = json.Marshal(map[string]any{"permissions": g.Permissions})
	}
	u := "https://" + g.apiHost() + "/app/installations/" + strconv.FormatInt(g.InstallationID, 10) + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return oauthToken{}, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return oauthToken{}, fmt.Errorf("installation token: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
		Message   string    `json:"message"`
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if json.Unmarshal(data, &out) != nil || resp.StatusCode != http.StatusCreated || len(out.Token) < minSecretLen {
		// GitHub's message says what was wrong (no such repository in the
		// installation, a permission the app lacks) and holds no secret.
		msg := out.Message
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return oauthToken{}, fmt.Errorf("GitHub answered %d to the installation token: %q", resp.StatusCode, msg)
	}
	if out.ExpiresAt.IsZero() {
		out.ExpiresAt = now.Add(time.Hour)
	}
	return oauthToken{out.Token, out.ExpiresAt}, nil
}
