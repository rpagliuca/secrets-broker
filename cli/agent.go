package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// client talks to the broker's HTTP side as a client (an agent).
type client struct {
	url   string
	token string
	http  *http.Client
}

func newClient(url, tokenEnv string) (*client, error) {
	token := os.Getenv(tokenEnv)
	if token == "" {
		return nil, fmt.Errorf("no client token in $%s", tokenEnv)
	}
	return &client{url: strings.TrimRight(url, "/"), token: token,
		http: &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{Proxy: nil}}}, nil
}

func (c *client) call(method, path string, body any, out any) (int, error) {
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		r = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, c.url+path, r)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, errors.New(strings.TrimSpace(string(raw)))
	}
	if out != nil {
		return resp.StatusCode, json.Unmarshal(raw, out)
	}
	return resp.StatusCode, nil
}

// requestAnswer is the answer of POST /requests.
type requestAnswer struct {
	Grants []struct {
		Credential string    `json:"credential"`
		Until      time.Time `json:"until"`
	} `json:"grants"`
	Request string `json:"request"`
	Refused string `json:"refused"`
}

func (a requestAnswer) holds(name string) bool {
	for _, g := range a.Grants {
		if g.Credential == name {
			return true
		}
	}
	return false
}

// Exit statuses of wait and sql.
const (
	exitGranted = 0
	exitError   = 1
	exitRefused = 2
	exitTimeout = 3
)

var (
	acceptedAfter = regexp.MustCompile(`accepted after (\S+)`)
	approverSaid  = regexp.MustCompile(`\(the approver said: ("(?:[^"\\]|\\.)*")\)`)
)

// explainRefusal turns the broker's refusal into one line: when a new
// request is accepted (local time) and what the approver said.
func explainRefusal(refused string) string {
	var parts []string
	if m := acceptedAfter.FindStringSubmatch(refused); m != nil {
		if t, err := time.Parse(time.RFC3339Nano, strings.TrimRight(m[1], ".;,")); err == nil {
			parts = append(parts, "ask again after "+t.Local().Format("15:04")+", and only with a new reason")
		}
	}
	if m := approverSaid.FindStringSubmatch(refused); m != nil {
		var said string
		if json.Unmarshal([]byte(m[1]), &said) == nil && said != "" {
			parts = append(parts, "the approver said: "+said)
		}
	}
	if len(parts) == 0 {
		return refused
	}
	return strings.Join(parts, "; ")
}

// wait asks for credentials, as "request" does, and waits for the answer,
// asking again every few seconds (which does not notify the approver
// again). It prints what was granted and what was refused.
func wait(c *client, payload map[string]any, names []string, every, limit time.Duration, out, errOut io.Writer) int {
	end := time.Now().Add(limit)
	told := false
	for time.Now().Before(end) {
		var a requestAnswer
		if _, err := c.call(http.MethodPost, "/requests", payload, &a); err != nil {
			fmt.Fprintln(errOut, err)
			return exitError
		}
		var got, missing []string
		for _, n := range names {
			if a.holds(n) {
				got = append(got, n)
			} else {
				missing = append(missing, n)
			}
		}
		switch {
		case len(missing) == 0:
			fmt.Fprintln(out, "granted: "+strings.Join(got, " "))
			return exitGranted
		case a.Refused != "":
			msg := "refused: " + strings.Join(missing, " ") + " (" + explainRefusal(a.Refused) + ")"
			if len(got) > 0 {
				msg = "partly granted: " + strings.Join(got, " ") + "; " + msg
			}
			fmt.Fprintln(out, msg)
			return exitRefused
		}
		if !told {
			fmt.Fprintln(errOut, "waiting for the approver: "+strings.Join(missing, " "))
			told = true
		}
		time.Sleep(every)
	}
	fmt.Fprintln(errOut, "no answer in "+limit.String()+": the request expired; it may be made again")
	return exitTimeout
}

// parseNames reads NAME[=WHY] arguments.
func parseNames(args []string) ([]string, map[string]string) {
	var names []string
	reasons := map[string]string{}
	for _, a := range args {
		name, why, has := strings.Cut(a, "=")
		names = append(names, name)
		if has {
			reasons[name] = why
		}
	}
	return names, reasons
}

// sqlResult is the answer of POST /sql/<name>.
type sqlResult struct {
	Columns   []string    `json:"columns"`
	Rows      [][]*string `json:"rows"`
	Truncated bool        `json:"truncated"`
}

// runSQL asks for one query on a database, waits for the approver to read
// and grant it, runs it once and prints the result as tab-separated text.
func runSQL(c *client, name, timeout, why, query string, every, limit time.Duration, out, errOut io.Writer) int {
	payload := map[string]any{
		"credentials": []string{name},
		"reasons":     map[string]string{name: why},
		"queries":     map[string]any{name: map[string]string{"sql": query, "timeout": timeout}},
	}
	if code := wait(c, payload, []string{name}, every, limit, errOut, errOut); code != exitGranted {
		return code
	}
	var res sqlResult
	if _, err := c.call(http.MethodPost, "/sql/"+name, nil, &res); err != nil {
		fmt.Fprintln(errOut, err)
		return exitError
	}
	if len(res.Columns) > 0 {
		fmt.Fprintln(out, strings.Join(res.Columns, "\t"))
		clean := strings.NewReplacer("\t", " ", "\n", " ", "\r", " ")
		for _, row := range res.Rows {
			cells := make([]string, len(row))
			for i, v := range row {
				if v == nil {
					cells[i] = "NULL"
				} else {
					cells[i] = clean.Replace(*v)
				}
			}
			fmt.Fprintln(out, strings.Join(cells, "\t"))
		}
	}
	if res.Truncated {
		fmt.Fprintln(errOut, "(result cut at the row limit)")
	}
	return exitGranted
}
