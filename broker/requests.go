package broker

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

// catalog lists what a client of these groups may ask for, by the name used
// in grants, with the hosts shown to the approver.
func (c *Config) catalog(groups []string) map[string][]string {
	allowed := func(gs []string) bool {
		return slices.ContainsFunc(gs, func(g string) bool { return slices.Contains(groups, g) })
	}
	out := map[string][]string{}
	for i := range c.Credentials {
		if cr := &c.Credentials[i]; allowed(cr.Groups) {
			out[cr.Name] = cr.Hosts
		}
	}
	for i := range c.AWS {
		if a := &c.AWS[i]; allowed(a.Groups) {
			out[a.grantName()] = []string{a.stsHost()}
		}
	}
	for i := range c.Commands {
		if cm := &c.Commands[i]; allowed(cm.Groups) {
			out[cm.grantName()] = []string{cm.grantName()}
		}
	}
	if c.SSH != nil {
		for i := range c.SSH.Targets {
			if t := &c.SSH.Targets[i]; allowed(t.Groups) {
				out[t.grantName()] = []string{t.Address}
			}
		}
	}
	return out
}

// known reports whether a name, as used in grants, exists in the
// configuration, for any group.
func (c *Config) known(name string) bool {
	if rest, ok := strings.CutPrefix(name, "ssh:"); ok {
		return c.SSH != nil && c.SSH.target(rest) != nil
	}
	if rest, ok := strings.CutPrefix(name, "aws:"); ok {
		return slices.ContainsFunc(c.AWS, func(a AWSAccount) bool { return a.Name == rest })
	}
	if rest, ok := strings.CutPrefix(name, "command:"); ok {
		return slices.ContainsFunc(c.Commands, func(cm Command) bool { return cm.Name == rest })
	}
	return slices.ContainsFunc(c.Credentials, func(cr Credential) bool { return cr.Name == name })
}

// access serves the two calls a client uses to plan its work:
//
//	GET  /grants    what it may ask for and what it holds now
//	POST /requests  {"credentials": ["a", "ssh:b"], "duration": "4h", "reasons": {"a": "why"}}
//
// A request made ahead covers everything a task needs in one question to
// the approver, instead of one question at each first use. The client names
// credentials and suggests a duration. It may say why it wants each one, in
// at most 200 characters: the only text of its own in the request, kept
// apart in Request.Reasons so that nothing shows it as if it were the
// broker's word.
func (s *Server) access(w http.ResponseWriter, r *http.Request) {
	ev := Event{Time: time.Now().UTC(), Method: "request"}
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
	catalog := cfg.catalog(p.Groups)
	asker, _ := s.Approver.(interface {
		Request(p Principal, credentials, hosts []string, suggested time.Duration, reasons map[string]string) (string, error)
		Until(principal, credential string) time.Time
	})
	if asker == nil {
		deny(http.StatusNotImplemented, "approval is not configured: there is nothing to ask for")
		return
	}
	type grant struct {
		Credential string    `json:"credential"`
		Until      time.Time `json:"until"`
	}
	held := func(names []string) []grant {
		out := []grant{}
		for _, n := range names {
			if u := asker.Until(p.ID, n); time.Now().Before(u) {
				out = append(out, grant{n, u.UTC()})
			}
		}
		return out
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/grants":
		names := make([]string, 0, len(catalog))
		for n := range catalog {
			names = append(names, n)
		}
		slices.Sort(names)
		json.NewEncoder(w).Encode(map[string]any{"available": names, "grants": held(names)})
	case r.Method == http.MethodPost && r.URL.Path == "/requests":
		var in struct {
			Credentials []string          `json:"credentials"`
			Duration    Duration          `json:"duration"`
			Reasons     map[string]string `json:"reasons"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in) != nil || len(in.Credentials) == 0 {
			deny(http.StatusBadRequest, `send {"credentials": ["name", ...], "duration": "4h"}`)
			return
		}
		var hosts []string
		for _, n := range in.Credentials {
			h, ok := catalog[n]
			if !ok {
				deny(http.StatusBadRequest, "unknown name in the request; GET /grants lists what is available")
				return
			}
			hosts = append(hosts, h...)
		}
		id, err := asker.Request(p, in.Credentials, hosts, time.Duration(in.Duration), in.Reasons)
		var ae *ApprovalError
		if err != nil && !errors.As(err, &ae) {
			deny(http.StatusBadRequest, err.Error())
			return
		}
		out := map[string]any{"grants": held(in.Credentials)}
		switch {
		case err != nil:
			out["refused"] = err.Error()
		case id != "":
			out["request"] = id
			out["waiting"] = "the approver was asked; use the credentials after the answer"
		}
		json.NewEncoder(w).Encode(out)
	default:
		deny(http.StatusMethodNotAllowed, "use GET /grants or POST /requests")
	}
}
