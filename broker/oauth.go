package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type oauthToken struct {
	access  string
	expires time.Time
}

// authorizationFor returns the Authorization header of a credential and the
// values that must never come back in a response.
func (s *Server) authorizationFor(ctx context.Context, cred *Credential, sec Secret, host string) (string, [][]byte, error) {
	if cred.Scheme == "github_app" {
		return s.githubAppAuthorization(ctx, cred, sec, host)
	}
	if cred.Scheme != "oauth2" {
		authz := cred.authorization(sec.Value)
		needles := [][]byte{sec.Value}
		if cred.Scheme == "basic" {
			needles = append(needles, []byte(strings.TrimPrefix(authz, "Basic ")))
		}
		return authz, needles, nil
	}
	// The secret is an OAuth client with a refresh token. The broker
	// exchanges it for an access token and injects that one; the client
	// holds neither.
	var k struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
	}
	if json.Unmarshal(sec.Value, &k) != nil || k.ClientID == "" || k.RefreshToken == "" {
		return "", nil, errors.New("the secret is not an OAuth client with a refresh token")
	}
	u, _ := url.Parse(cred.TokenURL)
	if !slices.Contains(sec.Hosts, u.Hostname()) {
		return "", nil, errHostNotBound
	}
	needles := [][]byte{[]byte(k.RefreshToken)}
	if len(k.ClientSecret) >= minSecretLen {
		needles = append(needles, []byte(k.ClientSecret))
	}
	s.cacheMu.Lock()
	tok, hit := s.oauthCache[cred.Name]
	s.cacheMu.Unlock()
	if !hit || time.Until(tok.expires) < time.Minute {
		form := url.Values{"grant_type": {"refresh_token"}, "client_id": {k.ClientID}, "refresh_token": {k.RefreshToken}}
		if k.ClientSecret != "" {
			form.Set("client_secret", k.ClientSecret)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cred.TokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return "", nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := s.Transport.RoundTrip(req)
		if err != nil {
			return "", nil, fmt.Errorf("token endpoint: %w", err)
		}
		defer resp.Body.Close()
		var out struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
			Error       string `json:"error"`
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if json.Unmarshal(data, &out) != nil || resp.StatusCode != http.StatusOK || len(out.AccessToken) < minSecretLen {
			// Only the status and the error code: the body may echo the request.
			return "", nil, fmt.Errorf("token endpoint answered %d %q", resp.StatusCode, out.Error)
		}
		life := time.Duration(out.ExpiresIn) * time.Second
		if life <= 0 {
			life = 5 * time.Minute
		}
		tok = oauthToken{out.AccessToken, time.Now().Add(life)}
		s.cacheMu.Lock()
		if s.oauthCache == nil {
			s.oauthCache = map[string]oauthToken{}
		}
		s.oauthCache[cred.Name] = tok
		s.cacheMu.Unlock()
	}
	return "Bearer " + tok.access, append(needles, []byte(tok.access)), nil
}
