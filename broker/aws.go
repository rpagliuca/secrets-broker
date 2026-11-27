package broker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// AWSAccount lets clients obtain temporary AWS credentials. The broker holds
// a long-term access key and asks STS for a session; the client receives
// credentials that expire, never the key.
type AWSAccount struct {
	// Name is what the client asks for: GET /aws/<name>.
	Name string `json:"name"`
	// Secret is the name, in the Store, of "ACCESS_KEY_ID:SECRET_ACCESS_KEY".
	// Defaults to Name. It must be bound to the STS host of the region.
	Secret string `json:"secret,omitempty"`
	// Groups are the client groups allowed to use the account.
	Groups []string `json:"groups"`
	// Region selects the STS endpoint. Default us-east-1.
	Region string `json:"region,omitempty"`
	// RoleARN, when set, is assumed (AssumeRole). Without it the session
	// belongs to the user of the key (GetSessionToken).
	RoleARN string `json:"role_arn,omitempty"`
	// MaxDuration limits how long the credentials last. Default 1h. With
	// approval they also end with the grant, but never last under 15m,
	// which is the shortest session STS issues.
	MaxDuration Duration `json:"max_duration,omitempty"`
	// MFASerial is the serial number (ARN) of the MFA device the session
	// must be opened with, for a role or a policy that requires MFA. The
	// one-time code is typed by whoever approves the request, so such an
	// account needs approval and cannot be granted from a notification
	// button. The session is opened once, when the request is approved,
	// and is not renewed: the grant ends with it.
	MFASerial string `json:"mfa_serial,omitempty"`
}

var awsRegionRE = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)

const awsMinSession = 15 * time.Minute

func (a *AWSAccount) secretName() string {
	if a.Secret != "" {
		return a.Secret
	}
	return a.Name
}

func (a *AWSAccount) grantName() string { return grantName("aws", a.Name) }

func (a *AWSAccount) region() string {
	if a.Region != "" {
		return a.Region
	}
	return "us-east-1"
}

func (a *AWSAccount) stsHost() string { return "sts." + a.region() + ".amazonaws.com" }

func (a *AWSAccount) maxDuration() time.Duration {
	if a.MaxDuration > 0 {
		return time.Duration(a.MaxDuration)
	}
	return time.Hour
}

func (a *AWSAccount) validate() error {
	switch {
	case !pathNameRE.MatchString(a.Name):
		return fmt.Errorf("aws account: invalid name %q", a.Name)
	case strings.Contains(a.Name, "/") && a.Secret == "":
		return fmt.Errorf("aws account %q: a name that is a path needs \"secret\"", a.Name)
	case a.Secret != "" && !nameRE.MatchString(a.Secret):
		return fmt.Errorf("aws account %q: invalid secret name", a.Name)
	case len(a.Groups) == 0 || slices.Contains(a.Groups, ""):
		return fmt.Errorf("aws account %q: needs at least one group", a.Name)
	case a.Region != "" && !awsRegionRE.MatchString(a.Region):
		return fmt.Errorf("aws account %q: invalid region %q", a.Name, a.Region)
	case a.RoleARN != "" && !strings.HasPrefix(a.RoleARN, "arn:aws"):
		return fmt.Errorf("aws account %q: role_arn must be an ARN", a.Name)
	case a.MaxDuration != 0 && (time.Duration(a.MaxDuration) < awsMinSession || time.Duration(a.MaxDuration) > 12*time.Hour):
		return fmt.Errorf("aws account %q: max_duration must be between 15m and 12h", a.Name)
	}
	return nil
}

func (c *Config) awsAccount(name string, groups []string) *AWSAccount {
	for i := range c.AWS {
		a := &c.AWS[i]
		if a.Name == name && slices.ContainsFunc(a.Groups, func(g string) bool { return slices.Contains(groups, g) }) {
			return a
		}
	}
	return nil
}

// awsCredentials is the output format of an AWS credential_process.
type awsCredentials struct {
	Version         int       `json:"Version"`
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken"`
	Expiration      time.Time `json:"Expiration"`
}

// aws serves GET /aws/<name>: temporary credentials for one account.
func (s *Server) aws(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/aws/")
	ev := Event{Time: time.Now().UTC(), Method: "aws-credentials", Credential: grantName("aws", name)}
	deny := func(code int, reason string) {
		ev.Decision, ev.Reason, ev.Status = "denied", reason, code
		s.audit.Record(ev)
		http.Error(w, "secrets-broker: "+reason, code)
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		deny(http.StatusUnauthorized, "missing token")
		return
	}
	p, err := s.auth.Authenticate(r.Context(), token)
	if err != nil {
		deny(http.StatusUnauthorized, "invalid token")
		return
	}
	ev.Principal, ev.Groups = p.ID, p.Groups
	cfg, _ := s.state()
	acct := cfg.awsAccount(name, p.Groups)
	if acct == nil {
		deny(http.StatusForbidden, "no such account for this client")
		return
	}
	ev.Host = acct.stsHost()
	sec, err := s.store.Get(acct.secretName())
	if err == nil && !slices.Contains(sec.Hosts, acct.stsHost()) {
		err = errHostNotBound
	}
	if err != nil {
		if errors.Is(err, ErrSealed) {
			s.forget()
		}
		deny(statusFor(err), err.Error())
		return
	}
	keyID, secretKey, ok := strings.Cut(string(sec.Value), ":")
	if !ok || keyID == "" || secretKey == "" {
		deny(http.StatusInternalServerError, "the secret is not ACCESS_KEY_ID:SECRET_ACCESS_KEY")
		return
	}
	d := acct.maxDuration()
	if s.Approver != nil {
		if err := s.Approver.Authorize(p, acct.grantName(), []string{acct.stsHost()}); err != nil {
			deny(http.StatusForbidden, err.Error())
			return
		}
		if u, ok := s.Approver.(interface {
			Until(principal, credential string) time.Time
		}); ok {
			d = min(d, time.Until(u.Until(p.ID, acct.grantName())))
		}
	}
	d = max(d, awsMinSession).Truncate(time.Second)

	// One STS call serves every request of the same client until shortly
	// before the session ends.
	key := p.ID + "\x00" + acct.Name
	s.cacheMu.Lock()
	creds, hit := s.awsCache[key]
	s.cacheMu.Unlock()
	if acct.MFASerial != "" {
		// The session was opened with the one-time code when the request
		// was approved. The broker cannot open another on its own.
		if s.Approver == nil || !hit || !time.Now().Before(creds.Expiration) {
			if e, ok := s.Approver.(interface {
				End(principal, credential, why string)
			}); ok {
				e.End(p.ID, acct.grantName(), "the session opened with the one-time code is over")
			}
			deny(http.StatusForbidden, "the session opened with the one-time code is over; ask again")
			return
		}
	} else if !hit || time.Until(creds.Expiration) < 5*time.Minute {
		creds, err = stsSession(r.Context(), s.Transport, acct, keyID, secretKey, d, p.ID, "", time.Now())
		if err != nil {
			deny(http.StatusBadGateway, "upstream: "+err.Error())
			return
		}
		s.cacheMu.Lock()
		if s.awsCache == nil {
			s.awsCache = map[string]awsCredentials{}
		}
		s.awsCache[key] = creds
		s.cacheMu.Unlock()
	}
	ev.Decision, ev.Status = "allowed", http.StatusOK
	s.audit.Record(ev)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(creds)
}

var oneTimeCodeRE = regexp.MustCompile(`^[0-9]{6,8}$`)

// needsCode reports whether a credential, by the name used in grants, can
// only be granted with a one-time code: an AWS account with an MFA device.
func (s *Server) needsCode(credential string) bool {
	cfg, _ := s.state()
	for i := range cfg.AWS {
		if cfg.AWS[i].grantName() == credential {
			return cfg.AWS[i].MFASerial != ""
		}
	}
	return false
}

// unlockWithCode opens the AWS session of an account with an MFA device,
// with the one-time code typed by the approver, and keeps it for the
// client. It returns when the session ends: the grant must not outlive it.
func (s *Server) unlockWithCode(p Principal, credential, code string, d time.Duration) (time.Time, error) {
	cfg, _ := s.state()
	var acct *AWSAccount
	for i := range cfg.AWS {
		if cfg.AWS[i].grantName() == credential {
			acct = cfg.awsAccount(cfg.AWS[i].Name, p.Groups)
		}
	}
	if acct == nil || acct.MFASerial == "" {
		return time.Time{}, fmt.Errorf("%s takes no one-time code", credential)
	}
	if !oneTimeCodeRE.MatchString(code) {
		return time.Time{}, fmt.Errorf("the one-time code for %s must be 6 to 8 digits", credential)
	}
	sec, err := s.store.Get(acct.secretName())
	if err == nil && !slices.Contains(sec.Hosts, acct.stsHost()) {
		err = errHostNotBound
	}
	if err != nil {
		return time.Time{}, err
	}
	keyID, secretKey, ok := strings.Cut(string(sec.Value), ":")
	if !ok || keyID == "" || secretKey == "" {
		return time.Time{}, errors.New("the secret is not ACCESS_KEY_ID:SECRET_ACCESS_KEY")
	}
	d = max(min(d, acct.maxDuration()), awsMinSession).Truncate(time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	creds, err := stsSession(ctx, s.Transport, acct, keyID, secretKey, d, p.ID, code, time.Now())
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", credential, err)
	}
	s.cacheMu.Lock()
	if s.awsCache == nil {
		s.awsCache = map[string]awsCredentials{}
	}
	s.awsCache[p.ID+"\x00"+acct.Name] = creds
	s.cacheMu.Unlock()
	return creds.Expiration, nil
}

// forget drops what was derived from secrets and is kept between requests.
// Sealed, the broker cannot delete the tokens it issued: they end at their
// expiry.
func (s *Server) forget() {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.awsCache, s.oauthCache, s.cfCache = nil, nil, nil
}

var (
	awsSessionNameRE = regexp.MustCompile(`[^\w+=,.@-]`)
	awsErrorCodeRE   = regexp.MustCompile(`<Code>([A-Za-z0-9.]+)</Code>`)
	// STS explains a refusal in <Message>: it tells a wrong one-time code
	// from a wrong device serial. It names no secret.
	awsErrorMessageRE = regexp.MustCompile(`<Message>([^<]{1,300})</Message>`)
)

// stsSession asks STS for temporary credentials, signing with the long-term
// key. code is the one-time code of the MFA device of the account, when it
// has one. Only the error code of a refusal is kept.
//
// A role with an MFA device is reached in two steps: GetSessionToken with the
// code, then AssumeRole signed with that session. Calling AssumeRole with the
// key and the code would satisfy the trust policy of the role, but not a
// policy on the user that denies what is done without MFA: the MFA of the
// call is not in the context the user's own policies see.
func stsSession(ctx context.Context, rt http.RoundTripper, a *AWSAccount, keyID, secretKey string, d time.Duration, client, code string, now time.Time) (awsCredentials, error) {
	form := url.Values{"Version": {"2011-06-15"}, "DurationSeconds": {strconv.Itoa(int(d.Seconds()))}, "Action": {"GetSessionToken"}}
	if a.MFASerial != "" {
		form.Set("SerialNumber", a.MFASerial)
		form.Set("TokenCode", code)
	}
	token := ""
	if a.RoleARN != "" && a.MFASerial != "" {
		user, err := stsCall(ctx, rt, a, form, keyID, secretKey, "", now)
		if err != nil {
			return awsCredentials{}, err
		}
		keyID, secretKey, token = user.AccessKeyID, user.SecretAccessKey, user.SessionToken
		form = url.Values{"Version": {"2011-06-15"}, "DurationSeconds": form["DurationSeconds"]}
	}
	if a.RoleARN != "" {
		name := awsSessionNameRE.ReplaceAllString(client, "-")
		form.Set("Action", "AssumeRole")
		form.Set("RoleArn", a.RoleARN)
		form.Set("RoleSessionName", (name + "--")[:min(len(name)+2, 64)])
	}
	return stsCall(ctx, rt, a, form, keyID, secretKey, token, now)
}

// stsCall sends one STS request. token is the session token of temporary
// credentials, or "" for a long-term key.
func stsCall(ctx context.Context, rt http.RoundTripper, a *AWSAccount, form url.Values, keyID, secretKey, token string, now time.Time) (awsCredentials, error) {
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+a.stsHost()+"/", strings.NewReader(body))
	if err != nil {
		return awsCredentials{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	signV4(req, body, keyID, secretKey, token, a.region(), "sts", now)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return awsCredentials{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		code := "no error code"
		if m := awsErrorCodeRE.FindSubmatch(data); m != nil {
			code = string(m[1])
		}
		return awsCredentials{}, fmt.Errorf("STS answered %d (%s)", resp.StatusCode, code+stsErrorMessage(data))
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			return awsCredentials{}, errors.New("STS answer without credentials")
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "Credentials" {
			var c struct {
				AccessKeyId, SecretAccessKey, SessionToken string
				Expiration                                 time.Time
			}
			if err := dec.DecodeElement(&c, &se); err != nil || c.AccessKeyId == "" || c.SecretAccessKey == "" {
				return awsCredentials{}, errors.New("STS answer without credentials")
			}
			return awsCredentials{1, c.AccessKeyId, c.SecretAccessKey, c.SessionToken, c.Expiration.UTC()}, nil
		}
	}
}

// signV4 adds an AWS Signature Version 4 to a request with a known body.
// Signed headers: content-type, host and x-amz-date, and
// x-amz-security-token when token (of temporary credentials) is not "".
func signV4(req *http.Request, body, keyID, secretKey, token, region, service string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	date := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)
	if token != "" {
		req.Header.Set("X-Amz-Security-Token", token)
	}
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	mac := func(key []byte, s string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(s))
		return m.Sum(nil)
	}

	uri := req.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	signed := "content-type;host;x-amz-date"
	headers := []string{
		"content-type:" + req.Header.Get("Content-Type"),
		"host:" + req.URL.Host,
		"x-amz-date:" + amzDate,
	}
	if token != "" {
		signed += ";x-amz-security-token"
		headers = append(headers, "x-amz-security-token:"+token)
	}
	canonical := strings.Join(append(append([]string{req.Method, uri, req.URL.RawQuery}, headers...), "", signed, sum(body)), "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sum(canonical)
	key := mac(mac(mac(mac([]byte("AWS4"+secretKey), date), region), service), "aws4_request")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+keyID+"/"+scope+
		", SignedHeaders="+signed+", Signature="+hex.EncodeToString(mac(key, toSign)))
}

// stsErrorMessage is the explanation STS gave with an error, as ": text" on
// one line, or "" when there is none.
func stsErrorMessage(data []byte) string {
	m := awsErrorMessageRE.FindSubmatch(data)
	if m == nil {
		return ""
	}
	msg := strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " ")
	if msg == "" {
		return ""
	}
	return ": " + msg
}
