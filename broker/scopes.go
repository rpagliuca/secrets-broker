package broker

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

// Scope is a narrow name for part of what a credential reaches. It uses the
// secret of its credential, on the same hosts, but a grant of the scope
// allows only the requests that match one of its rules. The name may have
// parameters, written {param} as a whole segment, so that one scope in the
// configuration serves many names:
//
//	"name": "team/git-host/repo/{repo}/read-and-comment",
//	"rules": [
//	  {"methods": ["GET", "HEAD"], "paths": ["/2.0/repositories/team/{repo}/**"]},
//	  {"methods": ["POST"], "paths": ["/2.0/repositories/team/{repo}/pullrequests/*/comments"]}
//	]
//
// A client asks for "team/git-host/repo/web/read-and-comment" and, once
// granted, may read the repository web and comment on its pull requests,
// and nothing else with that grant. A grant of the credential's own name
// still allows everything the credential allows.
type Scope struct {
	Name  string      `json:"name"`
	Rules []ScopeRule `json:"rules"`
}

// ScopeRule allows some methods on some paths. A path pattern starts with
// "/"; within a segment, "*" stands for any text and {param} for the value
// the client gave in the name, compared without regard to case; "**" as the
// last segment stands for any number of further segments, none included.
// The query string is not looked at.
type ScopeRule struct {
	Methods []string `json:"methods"`
	Paths   []string `json:"paths"`
}

var (
	paramRE        = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)
	scopeSegmentRE = regexp.MustCompile(`^([a-z0-9][a-z0-9._-]*|\{[a-z][a-z0-9_]*\})$`)
	nameSegmentRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	patternRE      = regexp.MustCompile(`^(/([^/{}*]|\*|\{[a-z][a-z0-9_]*\})+)*(/\*\*)?$`)
)

func (sc *Scope) validate(cr *Credential) error {
	if cr.isTemplate() {
		return fmt.Errorf("credential %q: a name with %s has no scopes", cr.Name, repoPlaceholder)
	}
	segs := strings.Split(sc.Name, "/")
	params := map[string]bool{}
	for _, seg := range segs {
		if !scopeSegmentRE.MatchString(seg) {
			return fmt.Errorf("credential %q: scope %q: invalid name", cr.Name, sc.Name)
		}
		if m := paramRE.FindStringSubmatch(seg); m != nil {
			if params[m[1]] {
				return fmt.Errorf("credential %q: scope %q: parameter {%s} appears twice", cr.Name, sc.Name, m[1])
			}
			params[m[1]] = true
		}
	}
	if len(sc.Rules) == 0 {
		return fmt.Errorf("credential %q: scope %q: needs at least one rule", cr.Name, sc.Name)
	}
	used := map[string]bool{}
	for _, rule := range sc.Rules {
		if len(rule.Methods) == 0 || len(rule.Paths) == 0 {
			return fmt.Errorf("credential %q: scope %q: each rule needs methods and paths", cr.Name, sc.Name)
		}
		for _, m := range rule.Methods {
			if !slices.Contains(allowedMethods, m) {
				return fmt.Errorf("credential %q: scope %q: method %q is not supported", cr.Name, sc.Name, m)
			}
			if len(cr.Methods) > 0 && !slices.Contains(cr.Methods, m) {
				return fmt.Errorf("credential %q: scope %q: method %q is not allowed by the credential", cr.Name, sc.Name, m)
			}
		}
		for _, p := range rule.Paths {
			if p == "" || p[0] != '/' || !patternRE.MatchString(p) || strings.Contains(strings.TrimSuffix(p, "/**"), "**") {
				return fmt.Errorf("credential %q: scope %q: invalid path pattern %q", cr.Name, sc.Name, p)
			}
			for _, m := range paramRE.FindAllStringSubmatch(p, -1) {
				if !params[m[1]] {
					return fmt.Errorf("credential %q: scope %q: path %q uses {%s}, which is not in the name", cr.Name, sc.Name, p, m[1])
				}
				used[m[1]] = true
			}
		}
	}
	for p := range params {
		if !used[p] {
			return fmt.Errorf("credential %q: scope %q: parameter {%s} restricts no path", cr.Name, sc.Name, p)
		}
	}
	return nil
}

// match returns the parameters of name when name is an instance of the
// scope.
func (sc *Scope) match(name string) (map[string]string, bool) {
	tmpl, segs := strings.Split(sc.Name, "/"), strings.Split(name, "/")
	if len(tmpl) != len(segs) {
		return nil, false
	}
	params := map[string]string{}
	for i, t := range tmpl {
		if m := paramRE.FindStringSubmatch(t); m != nil {
			if !nameSegmentRE.MatchString(segs[i]) {
				return nil, false
			}
			params[m[1]] = segs[i]
		} else if t != segs[i] {
			return nil, false
		}
	}
	return params, true
}

// overlaps reports whether some name could be an instance of both scopes.
func (sc *Scope) overlaps(other string) bool {
	a, b := strings.Split(sc.Name, "/"), strings.Split(other, "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !paramRE.MatchString(a[i]) && !paramRE.MatchString(b[i]) && a[i] != b[i] {
			return false
		}
	}
	return true
}

// allows reports whether a request with method on segments (the decoded
// path, split by scopePath) matches a rule, with the parameters of the
// granted name.
func (sc *Scope) allows(params map[string]string, method, path string) bool {
	for _, rule := range sc.Rules {
		if !slices.Contains(rule.Methods, method) {
			continue
		}
		for _, p := range rule.Paths {
			if patternRegexp(p, params).MatchString(path) {
				return true
			}
		}
	}
	return false
}

// patternRegexp turns a path pattern into an anchored expression, with the
// parameters replaced by their values.
func patternRegexp(pattern string, params map[string]string) *regexp.Regexp {
	rest, tail := pattern, ""
	if r, ok := strings.CutSuffix(pattern, "/**"); ok {
		rest, tail = r, "(/.*)?"
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(rest); {
		switch {
		case rest[i] == '*':
			b.WriteString("[^/]*")
			i++
		case rest[i] == '{':
			end := strings.IndexByte(rest[i:], '}')
			b.WriteString("(?i:" + regexp.QuoteMeta(params[rest[i+1:i+end]]) + ")")
			i += end + 1
		default:
			j := i
			for j < len(rest) && rest[j] != '*' && rest[j] != '{' {
				j++
			}
			b.WriteString(regexp.QuoteMeta(rest[i:j]))
			i = j
		}
	}
	b.WriteString(tail + "$")
	return regexp.MustCompile(b.String())
}

var errPathNotClean = errors.New("path is not in a form scopes can judge (encoded separators, dot segments, ';' or empty segments)")

// scopePath returns the decoded path of a request judged by a scope, or an
// error when the service might read it otherwise than the broker: an
// encoded "/", "\", "." or ";", a backslash, a ";" (path parameters, which
// some servers drop before routing), a dot segment, an empty segment, or a
// doubly encoded character.
func scopePath(r *http.Request) (string, error) {
	esc := r.URL.EscapedPath()
	low := strings.ToLower(esc)
	if r.URL.Opaque != "" || !strings.HasPrefix(esc, "/") || strings.ContainsAny(esc, `\;`) {
		return "", errPathNotClean
	}
	for _, bad := range []string{"%2f", "%5c", "%2e", "%3b", "%25", "%00"} {
		if strings.Contains(low, bad) {
			return "", errPathNotClean
		}
	}
	segs := strings.Split(r.URL.Path[1:], "/")
	for i, s := range segs {
		if s == "." || s == ".." || (s == "" && i != len(segs)-1) {
			return "", errPathNotClean
		}
	}
	return r.URL.Path, nil
}

// scopeFor returns the scope of the credential that name is an instance of.
func (cr *Credential) scopeFor(name string) (*Scope, map[string]string) {
	for i := range cr.Scopes {
		if params, ok := cr.Scopes[i].match(name); ok {
			return &cr.Scopes[i], params
		}
	}
	return nil, nil
}

// GrantLister is implemented by approvers that can list the names a client
// holds a grant for now. Scopes need it: a request is allowed by any of the
// scopes the client holds on the credential.
type GrantLister interface {
	GrantsOf(principal string) []string
}

// heldScopes returns the names of the scopes of cred that p holds now.
func (s *Server) heldScopes(p Principal, cred *Credential) []string {
	gl, ok := s.Approver.(GrantLister)
	if !ok || len(cred.Scopes) == 0 {
		return nil
	}
	var out []string
	for _, name := range gl.GrantsOf(p.ID) {
		if sc, _ := cred.scopeFor(name); sc != nil && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// errScopeDenied refuses a request that none of the scopes held allows.
type errScopeDenied struct{ held []string }

func (e errScopeDenied) Error() string {
	return "method or path not allowed by the scopes granted to this client: " + strings.Join(e.held, ", ")
}

// authorize decides one request of a tunnel, or the tunnel itself when r is
// nil. A grant of the credential allows everything the credential allows.
// Otherwise a grant of one of its scopes is needed, and the request must
// match one of the rules of a scope held. It returns the scope that allowed
// the request, if any.
func (s *Server) authorize(p Principal, cred *Credential, r *http.Request) (string, error) {
	if s.Approver == nil {
		return "", nil
	}
	if len(cred.Scopes) == 0 || s.Approver.Granted(p.ID, cred.Name) {
		return "", s.Approver.Authorize(p, cred.Name, cred.Hosts)
	}
	held := s.heldScopes(p, cred)
	if len(held) == 0 {
		// The credential itself is asked for, as without scopes.
		return "", s.Approver.Authorize(p, cred.Name, cred.Hosts)
	}
	if r == nil {
		return "", nil
	}
	path, err := scopePath(r)
	if err != nil {
		return "", err
	}
	for _, name := range held {
		sc, params := cred.scopeFor(name)
		if sc.allows(params, r.Method, path) {
			return name, nil
		}
	}
	return "", errScopeDenied{held}
}
