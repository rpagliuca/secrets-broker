package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
)

func TestParseExpiry(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	if v, err := parseExpiry("", now); err != nil || !v.IsZero() {
		t.Fatalf("empty: %v %v", v, err)
	}
	if v, err := parseExpiry("90d", now); err != nil || !v.Equal(now.AddDate(0, 0, 90)) {
		t.Fatalf("90d: %v %v", v, err)
	}
	if v, err := parseExpiry("2027-02-24", now); err != nil || v.Format(time.RFC3339) != "2027-02-24T23:59:59Z" {
		t.Fatalf("date: %v %v", v, err)
	}
	for _, bad := range []string{"0d", "-3d", "90", "3 months", "2026-11-25", "9999d"} {
		if _, err := parseExpiry(bad, now); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRecordRotation(t *testing.T) {
	for _, old := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "rotation.json")
		secretsKey, expiriesKey := "secrets", "expiries"
		if old {
			secretsKey, expiriesKey = "segredos", "vencimentos"
			os.WriteFile(path, []byte(`{"cofre": {"publica": "age1x"}, "segredos": {"older": null}}`), 0o644)
		} else {
			os.WriteFile(path, []byte(`{"vault": {"public": "age1x"}, "secrets": {"older": null}}`), 0o644)
		}
		read := func() map[string]json.RawMessage {
			raw, _ := os.ReadFile(path)
			m := map[string]json.RawMessage{}
			json.Unmarshal(raw, &m)
			return m
		}
		now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
		if err := recordRotation(path, "older", false, now, now.AddDate(0, 0, 90), io.Discard); err == nil {
			t.Fatal("an expiry without a rotation date was accepted")
		}
		if err := recordRotation(path, "token", true, now, now.AddDate(0, 0, 90), io.Discard); err != nil {
			t.Fatal(err)
		}
		m := read()
		var exp map[string]string
		var sec map[string]*string
		json.Unmarshal(m[expiriesKey], &exp)
		json.Unmarshal(m[secretsKey], &sec)
		if _, has := sec["older"]; exp["token"] != "2027-02-24T12:00:00Z" || !has || sec["token"] == nil || len(m) != 3 {
			t.Fatalf("old=%v: %s", old, readAll(path))
		}
		if err := recordRotation(path, "token", true, now.AddDate(0, 0, 2), time.Time{}, io.Discard); err != nil {
			t.Fatal(err)
		}
		if _, has := read()[expiriesKey]; has {
			t.Fatalf("the previous expiry stayed: %s", readAll(path))
		}
	}
}

func readAll(path string) string {
	raw, _ := os.ReadFile(path)
	return string(raw)
}

func TestEncryptBindsToTheNamesThatUseTheSecret(t *testing.T) {
	dir := t.TempDir()
	id, _ := age.GenerateX25519Identity()
	pub := filepath.Join(dir, "vault.pub")
	os.WriteFile(pub, []byte(id.Recipient().String()+"\n"), 0o644)
	cfg := filepath.Join(dir, "config.json")
	os.WriteFile(cfg, []byte(`{
	  "credentials": [{"name": "api", "secret": "key", "hosts": ["api.example.com"]}],
	  "aws": [{"name": "org/aws/acct/read", "secret": "key"}],
	  "commands": [{"name": "org/vpn/site/device", "files": [{"secret": "key"}]}, {"name": "vpn", "files": [{"secret": "key"}]}],
	  "ssh": {"targets": [{"name": "web", "secret": "key", "address": "10.0.0.5:22"}]}
	}`), 0o644)
	var out bytes.Buffer
	err := encrypt(encryptOptions{name: "key", config: cfg, recipient: pub, out: dir}, strings.NewReader("a-long-enough-value\n"), &out)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(filepath.Join(dir, "key.age"))
	r, err := age.Decrypt(f, id)
	if err != nil {
		t.Fatal(err)
	}
	var sec struct {
		Value string
		Hosts []string
	}
	raw, _ := io.ReadAll(r)
	json.Unmarshal(raw, &sec)
	want := "api.example.com,sts.us-east-1.amazonaws.com,10.0.0.5,org/vpn/site/device,command:vpn"
	if sec.Value != "a-long-enough-value" || strings.Join(sec.Hosts, ",") != want {
		t.Fatalf("%+v", sec)
	}
	if strings.Contains(out.String(), "a-long-enough-value") {
		t.Fatal("the value was printed")
	}
	if err := encrypt(encryptOptions{name: "nobody", config: cfg, recipient: pub, out: dir}, strings.NewReader("a-long-enough-value"), io.Discard); err == nil {
		t.Fatal("a secret no name uses was encrypted without -host")
	}
}

func TestExplainRefusal(t *testing.T) {
	got := explainRefusal(`not approved (the approver said: "ask for one \"repo\""); a new request is accepted after 2030-01-01T10:11:12Z`)
	if !strings.Contains(got, `the approver said: ask for one "repo"`) || !strings.Contains(got, "ask again after") {
		t.Fatalf("%q", got)
	}
}

// fakeBroker answers POST /requests with what the test says, in turn.
func fakeBroker(t *testing.T, answers ...string) (*client, *[]string) {
	var mu sync.Mutex
	var calls []string
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, r.URL.Path+" "+string(body))
		if r.URL.Path == "/sql/db" {
			io.WriteString(w, `{"columns":["n","name"],"rows":[["1","a\tb"],["2",null]],"truncated":true}`)
			return
		}
		a := answers[min(i, len(answers)-1)]
		i++
		io.WriteString(w, a)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("TEST_TOKEN", "tok")
	c, err := newClient(srv.URL, "TEST_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	return c, &calls
}

func TestWaitUntilGrantedOrRefused(t *testing.T) {
	c, calls := fakeBroker(t, `{"grants":[],"request":"r1"}`, `{"grants":[{"credential":"a"},{"credential":"b"}]}`)
	var out, errOut bytes.Buffer
	if code := wait(c, map[string]any{"credentials": []string{"a", "b"}}, []string{"a", "b"}, time.Millisecond, time.Minute, &out, &errOut); code != exitGranted {
		t.Fatalf("%d %s %s", code, out.String(), errOut.String())
	}
	if out.String() != "granted: a b\n" || len(*calls) != 2 || !strings.Contains(errOut.String(), "waiting for the approver: a b") {
		t.Fatalf("%q %q %v", out.String(), errOut.String(), *calls)
	}
	c, _ = fakeBroker(t, `{"grants":[{"credential":"a"}],"refused":"not approved (the approver said: \"no\"); a new request is accepted after 2030-01-01T10:11:12Z"}`)
	out.Reset()
	if code := wait(c, map[string]any{}, []string{"a", "b"}, time.Millisecond, time.Minute, &out, io.Discard); code != exitRefused {
		t.Fatalf("%d", code)
	}
	if !strings.HasPrefix(out.String(), "partly granted: a; refused: b (") || !strings.Contains(out.String(), "the approver said: no") {
		t.Fatalf("%q", out.String())
	}
	c, _ = fakeBroker(t, `{"grants":[],"request":"r1"}`)
	if code := wait(c, map[string]any{}, []string{"a"}, time.Millisecond, 5*time.Millisecond, io.Discard, io.Discard); code != exitTimeout {
		t.Fatalf("%d", code)
	}
}

func TestSQLAsksWithTheQueryAndPrintsTSV(t *testing.T) {
	c, calls := fakeBroker(t, `{"grants":[{"credential":"db"}]}`)
	var out, errOut bytes.Buffer
	if code := runSQL(c, "db", "30s", "size of the tables", "SELECT 1", time.Millisecond, time.Minute, &out, &errOut); code != exitGranted {
		t.Fatalf("%d %s", code, errOut.String())
	}
	if out.String() != "n\tname\n1\ta b\n2\tNULL\n" || !strings.Contains(errOut.String(), "row limit") {
		t.Fatalf("%q %q", out.String(), errOut.String())
	}
	if !strings.Contains((*calls)[0], `"queries":{"db":{"sql":"SELECT 1","timeout":"30s"}}`) || (*calls)[1] != "/sql/db " {
		t.Fatalf("%v", *calls)
	}
}
