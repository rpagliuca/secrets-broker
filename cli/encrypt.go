package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
)

// encryptOptions are the flags of "encrypt".
type encryptOptions struct {
	name, file, config, recipient, out, rotation, expires string
	hosts                                                 []string
	isNew                                                 bool
}

// renewAt is the share of the validity after which a secret should be
// renewed (the panel warns from then on).
const renewAt = 0.7

// encrypt writes <out>/<name>.age in the store's format ({"value","hosts"}),
// encrypted for the vault's public key. It only encrypts: it runs anywhere.
// The value comes from a file or from standard input and is never printed.
// Without -host, the hosts are those of the names of the configuration that
// use the secret.
func encrypt(o encryptOptions, stdin io.Reader, out io.Writer) error {
	if o.name == "" {
		return errors.New("-name is required")
	}
	now := time.Now()
	expiry, err := parseExpiry(o.expires, now)
	if err != nil {
		return fmt.Errorf("-expires: %w", err)
	}
	hosts := o.hosts
	if len(hosts) == 0 {
		if hosts, err = configHosts(o.config, o.name); err != nil {
			return err
		}
	}
	if len(hosts) == 0 {
		return fmt.Errorf("no host for %q: no -host, and no name in the configuration uses this secret", o.name)
	}
	pub, err := os.ReadFile(o.recipient)
	if err != nil {
		return err
	}
	to, err := age.ParseX25519Recipient(strings.TrimSpace(string(pub)))
	if err != nil {
		return fmt.Errorf("%s: %w", o.recipient, err)
	}
	var value []byte
	if o.file != "" {
		value, err = os.ReadFile(o.file)
	} else if value, err = io.ReadAll(stdin); err == nil {
		value = []byte(strings.TrimRight(string(value), "\r\n"))
	}
	if err != nil || len(value) < 8 {
		return errors.New("value unreadable or too short")
	}
	plain, _ := json.Marshal(map[string]any{"value": string(value), "hosts": hosts})
	path := filepath.Join(o.out, o.name+".age")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w, err := age.Encrypt(f, to)
	if err == nil {
		if _, err = w.Write(plain); err == nil {
			err = w.Close()
		}
	}
	if err != nil || f.Close() != nil {
		os.Remove(path)
		return errors.New("encryption failed")
	}
	fmt.Fprintf(out, "%s: bound to %s\n", path, strings.Join(hosts, ", "))
	if o.rotation != "" {
		return recordRotation(o.rotation, o.name, o.isNew, now, expiry, out)
	}
	if o.isNew || !expiry.IsZero() {
		return errors.New("-new and -expires need -rotation")
	}
	return nil
}

// parseExpiry reads "90d" (days from now) or "2027-02-24" (the end of that
// day). Empty is no expiry.
func parseExpiry(text string, now time.Time) (time.Time, error) {
	if text == "" {
		return time.Time{}, nil
	}
	if d, ok := strings.CutSuffix(text, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n < 1 || n > 3650 {
			return time.Time{}, fmt.Errorf("invalid duration %q: use days, such as 90d", text)
		}
		return now.AddDate(0, 0, n), nil
	}
	day, err := time.ParseInLocation("2006-01-02", text, now.Location())
	if err != nil {
		return time.Time{}, fmt.Errorf("use days (90d) or a date (2027-02-24), not %q", text)
	}
	end := day.AddDate(0, 0, 1).Add(-time.Second)
	if !end.After(now) {
		return time.Time{}, fmt.Errorf("the date %s is past", text)
	}
	return end, nil
}

// recordRotation notes in the rotation file when the secret got a new
// value. Encrypting the same value again is no rotation: only -new changes
// the date. A secret not yet in the file enters without a date, which the
// panel shows as a value older than the vault. An expiry is counted from
// the rotation date, so it needs one. The file keeps the key names it has
// (an earlier version used Portuguese ones).
func recordRotation(path, name string, isNew bool, now, expiry time.Time, out io.Writer) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var file map[string]json.RawMessage
	if err := json.Unmarshal(raw, &file); err != nil {
		return err
	}
	secretsKey, expiriesKey := "secrets", "expiries"
	if _, old := file["segredos"]; old {
		secretsKey, expiriesKey = "segredos", "vencimentos"
	}
	secrets := map[string]*string{}
	expiries := map[string]string{}
	if v, ok := file[secretsKey]; ok {
		json.Unmarshal(v, &secrets)
	}
	if v, ok := file[expiriesKey]; ok {
		json.Unmarshal(v, &expiries)
	}
	_, exists := secrets[name]
	_, hadExpiry := expiries[name]
	changed := true
	switch {
	case isNew:
		when := now.Format(time.RFC3339)
		secrets[name] = &when
		fmt.Fprintf(out, "%s: rotation of %s recorded at %s\n", path, name, when)
		if expiry.IsZero() && hadExpiry {
			delete(expiries, name)
			fmt.Fprintf(out, "%s: the expiry of the previous value of %s was removed (use -expires if the new one has one)\n", path, name)
		}
	case !exists:
		secrets[name] = nil
		fmt.Fprintf(out, "%s: %s entered without a rotation date (use -new when the value is new)\n", path, name)
	default:
		fmt.Fprintf(out, "%s: rotation date of %s kept (use -new if the value was changed at the service)\n", path, name)
		changed = false
	}
	if !expiry.IsZero() {
		since := secrets[name]
		if since == nil {
			return fmt.Errorf("%s has no rotation date: use -expires with -new", name)
		}
		start, err := time.Parse(time.RFC3339, *since)
		if err != nil || !expiry.After(start) {
			return fmt.Errorf("the expiry of %s is not after its rotation (%s)", name, *since)
		}
		expiries[name] = expiry.Format(time.RFC3339)
		renew := start.Add(time.Duration(float64(expiry.Sub(start)) * renewAt))
		fmt.Fprintf(out, "%s: %s expires on %s; renew from %s (70%% of the validity)\n", path, name, expiry.Format("2006-01-02"), renew.Format("2006-01-02"))
		changed = true
	}
	if !changed {
		return nil
	}
	file[secretsKey], _ = json.Marshal(secrets)
	if len(expiries) > 0 {
		file[expiriesKey], _ = json.Marshal(expiries)
	} else {
		delete(file, expiriesKey)
	}
	res, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(res, '\n'), 0o644)
}

// configHosts gathers the hosts a secret must be bound to: those of the
// credentials, SSH targets and AWS accounts that use it, and the names of
// the commands (as "command:<name>", or the path) whose files it fills.
func configHosts(path, name string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	var c struct {
		Credentials []struct {
			Name, Secret string
			Hosts        []string
			TokenURL     string `json:"token_url"`
		}
		SSH struct {
			Targets []struct{ Name, Secret, Address string }
		}
		AWS      []struct{ Name, Secret, Region string }
		Commands []struct {
			Name  string
			Files []struct{ Secret string }
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var out []string
	add := func(secret, def string, hosts ...string) {
		if secret == "" {
			secret = def
		}
		for _, h := range hosts {
			if secret == name && !slices.Contains(out, h) {
				out = append(out, h)
			}
		}
	}
	for _, cr := range c.Credentials {
		add(cr.Secret, cr.Name, cr.Hosts...)
		if u, err := url.Parse(cr.TokenURL); err == nil && u.Hostname() != "" {
			add(cr.Secret, cr.Name, u.Hostname())
		}
	}
	for _, a := range c.AWS {
		if a.Region == "" {
			a.Region = "us-east-1"
		}
		add(a.Secret, a.Name, "sts."+a.Region+".amazonaws.com")
	}
	for _, t := range c.SSH.Targets {
		if host, _, err := net.SplitHostPort(t.Address); err == nil {
			add(t.Secret, t.Name, host)
		}
	}
	for _, cm := range c.Commands {
		bound := "command:" + cm.Name
		if strings.Contains(cm.Name, "/") {
			bound = cm.Name
		}
		for _, f := range cm.Files {
			add(f.Secret, f.Secret, bound)
		}
	}
	return out, nil
}
