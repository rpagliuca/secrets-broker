package broker

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// The token is a presigned "connect" URL for the user, without the scheme.
func TestRDSAuthToken(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	tok := rdsAuthToken("db.example.com", "3306", "reader", "us-east-1",
		awsCredentials{AccessKeyID: "ASIATEMP", SecretAccessKey: "temp-secret", SessionToken: "temp token"}, at)
	host, rawQuery, ok := strings.Cut(tok, "/?")
	if !ok || host != "db.example.com:3306" || strings.Contains(tok, "temp-secret") {
		t.Fatalf("token = %s", tok)
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"Action": "connect", "DBUser": "reader", "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
		"X-Amz-Credential": "ASIATEMP/20300102/us-east-1/rds-db/aws4_request", "X-Amz-Date": "20300102T030405Z",
		"X-Amz-Expires": "900", "X-Amz-SignedHeaders": "host", "X-Amz-Security-Token": "temp token",
	} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if len(q.Get("X-Amz-Signature")) != 64 || strings.Contains(rawQuery, "+") {
		t.Fatalf("query = %s", rawQuery)
	}
}

// A query is granted as written, and runs once.
func TestQueryGrantRunsOnce(t *testing.T) {
	g, _, _, _ := newTestGrants()
	a := Principal{ID: "agent-a"}
	q := Query{SQL: "SELECT 1", Timeout: Duration(30 * time.Second)}
	id, err := g.RequestQueries(a, []string{"sql:prod"}, nil, 0, nil, map[string]Query{"sql:prod": q})
	if err != nil || id == "" {
		t.Fatalf("%q %v", id, err)
	}
	if p := g.Pending(); len(p) != 1 || p[0].Queries["sql:prod"] != q {
		t.Fatalf("pending = %+v", p)
	}
	if err := g.Decide(id, time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	got, err := g.UseQuery("agent-a", "sql:prod")
	if err != nil || got != q {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := g.UseQuery("agent-a", "sql:prod"); err == nil {
		t.Fatal("the query ran twice on one approval")
	}
	if g.Granted("agent-a", "sql:prod") {
		t.Fatal("the grant outlived its one run")
	}
}

func TestDatabaseQueryIsChecked(t *testing.T) {
	d := &Database{Name: "prod"}
	for name, q := range map[string]Query{
		"empty":        {SQL: " ", Timeout: Duration(time.Second)},
		"no timeout":   {SQL: "SELECT 1"},
		"long timeout": {SQL: "SELECT 1", Timeout: Duration(time.Hour)},
		"too long":     {SQL: strings.Repeat("x", maxQuery+1), Timeout: Duration(time.Second)},
	} {
		if err := d.checkQuery(q); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := d.checkQuery(Query{SQL: "SELECT 1", Timeout: Duration(time.Minute)}); err != nil {
		t.Fatal(err)
	}
}

// In front of the grants there is the services layer, as when the broker
// runs: queries, their one run, and ending a grant all go through it.
func TestServicesPassQueriesThrough(t *testing.T) {
	g, _, _, _ := newTestGrants()
	sv := &services{cfg: func() *Config { return &Config{} }, inner: g}
	a := Principal{ID: "agent-a"}
	q := Query{SQL: "SELECT 1", Timeout: Duration(30 * time.Second)}
	id, err := sv.RequestQueries(a, []string{"sql:prod"}, nil, 0, nil, map[string]Query{"sql:prod": q})
	if err != nil || id == "" {
		t.Fatalf("%q %v", id, err)
	}
	if err := g.Decide(id, time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	if got, err := sv.UseQuery("agent-a", "sql:prod"); err != nil || got != q {
		t.Fatalf("%+v %v", got, err)
	}
	id = requestID(t, g.Authorize(a, "svc", nil))
	g.Decide(id, time.Hour, "test")
	sv.End("agent-a", "svc", "test")
	if g.Granted("agent-a", "svc") {
		t.Fatal("End did not reach the grants")
	}
}
