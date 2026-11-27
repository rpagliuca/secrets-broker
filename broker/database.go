package broker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-sql-driver/mysql"
)

// Database lets a client run SQL it wrote, after the approver read it. The
// client never gets a connection: it asks for a statement with POST
// /requests ("queries"), the approver grants that text, and POST
// /sql/<name> runs it once. The broker signs in with an IAM token of an
// AWS account (with MFA, typed at the approval), so no database password is
// kept. Only MySQL is supported.
type Database struct {
	// Name is what the client asks for.
	Name string `json:"name"`
	// Groups are the client groups allowed to ask.
	Groups []string `json:"groups"`
	// Address is host:port of the endpoint.
	Address string `json:"address"`
	// User is the database user the IAM token is for.
	User string `json:"user"`
	// AWS names the AWS account (in "aws") whose session signs the token. It
	// must have mfa_serial: the code typed at the approval opens it.
	AWS string `json:"aws"`
	// CAFile is the PEM bundle the server certificate is checked against
	// (for RDS, the global bundle). TLS is required.
	CAFile string `json:"ca_file"`
	// Write lets statements change data. Without it every statement runs
	// in a READ ONLY transaction.
	Write bool `json:"write,omitempty"`
	// MaxRows caps the rows returned. Default 1000.
	MaxRows int `json:"max_rows,omitempty"`
	// MaxTimeout caps the time a client may ask for. Default 5m.
	MaxTimeout Duration `json:"max_timeout,omitempty"`
}

const maxQuery = 64 << 10 // bytes of SQL in one query

func (d *Database) grantName() string { return grantName("sql", d.Name) }

func (d *Database) maxRows() int {
	if d.MaxRows > 0 {
		return d.MaxRows
	}
	return 1000
}

func (d *Database) maxTimeout() time.Duration {
	if d.MaxTimeout > 0 {
		return time.Duration(d.MaxTimeout)
	}
	return 5 * time.Minute
}

func (d *Database) validate(c *Config) error {
	if !pathNameRE.MatchString(d.Name) || len(d.Groups) == 0 || slices.Contains(d.Groups, "") {
		return fmt.Errorf("database %q: needs a valid name and at least one group", d.Name)
	}
	if host, port, err := net.SplitHostPort(d.Address); err != nil || host == "" || port == "" {
		return fmt.Errorf("database %q: address must be host:port", d.Name)
	}
	if d.User == "" || d.CAFile == "" {
		return fmt.Errorf("database %q: needs user and ca_file", d.Name)
	}
	i := slices.IndexFunc(c.AWS, func(a AWSAccount) bool { return a.Name == d.AWS })
	if i < 0 || c.AWS[i].MFASerial == "" {
		return fmt.Errorf("database %q: aws must name an account with mfa_serial", d.Name)
	}
	return nil
}

func (c *Config) database(credential string) *Database {
	for i := range c.Databases {
		if c.Databases[i].grantName() == credential {
			return &c.Databases[i]
		}
	}
	return nil
}

// checkQuery says whether a client may ask for this query on a database.
func (d *Database) checkQuery(q Query) error {
	if strings.TrimSpace(q.SQL) == "" || len(q.SQL) > maxQuery || !utf8.ValidString(q.SQL) {
		return fmt.Errorf("the query for %s must be valid text of 1 to %d bytes", d.grantName(), maxQuery)
	}
	if q.Timeout <= 0 || time.Duration(q.Timeout) > d.maxTimeout() {
		return fmt.Errorf("the timeout of the query for %s must be between 1s and %s", d.grantName(), d.maxTimeout())
	}
	return nil
}

// sqlResult is what POST /sql/<name> answers. Rows are text; NULL is null.
type sqlResult struct {
	Columns   []string    `json:"columns,omitempty"`
	Rows      [][]*string `json:"rows,omitempty"`
	Truncated bool        `json:"truncated,omitempty"`
	Affected  *int64      `json:"affected,omitempty"`
}

// sql serves POST /sql/<name>: it runs, once, the query the approver
// granted to this client. The query is written to the audit log; the
// result is not.
func (s *Server) sql(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/sql/")
	ev := Event{Time: time.Now().UTC(), Method: "sql", Credential: grantName("sql", name)}
	deny := func(code int, reason string) {
		ev.Decision, ev.Reason, ev.Status = "denied", reason, code
		s.audit.Record(ev)
		http.Error(w, "secrets-broker: "+reason, code)
	}
	if r.Method != http.MethodPost {
		deny(http.StatusMethodNotAllowed, "use POST")
		return
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
	db := cfg.database(grantName("sql", name))
	if db == nil || !slices.ContainsFunc(db.Groups, func(g string) bool { return slices.Contains(p.Groups, g) }) {
		deny(http.StatusForbidden, "no such database for this client")
		return
	}
	user, ok := s.Approver.(interface {
		UseQuery(principal, credential string) (Query, error)
	})
	if !ok {
		deny(http.StatusNotImplemented, "approval is not configured")
		return
	}
	q, err := user.UseQuery(p.ID, db.grantName())
	if err != nil {
		deny(http.StatusForbidden, "no query granted; ask with POST /requests and \"queries\", then run it once")
		return
	}
	ev.Path = q.SQL
	s.cacheMu.Lock()
	creds, hit := s.awsCache[p.ID+"\x00"+db.AWS]
	s.cacheMu.Unlock()
	if !hit || !time.Now().Before(creds.Expiration) {
		deny(http.StatusForbidden, "the session opened with the one-time code is over; ask again")
		return
	}
	cfgAWS := cfg.awsAccount(db.AWS, p.Groups)
	region := "us-east-1"
	if cfgAWS != nil {
		region = cfgAWS.region()
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(q.Timeout)+10*time.Second)
	defer cancel()
	res, err := runQuery(ctx, db, q, creds, region, time.Now())
	if err != nil {
		deny(http.StatusBadGateway, "the query failed: "+err.Error())
		return
	}
	ev.Decision, ev.Status = "allowed", http.StatusOK
	if res.Affected != nil {
		ev.Reason = fmt.Sprintf("%d rows affected", *res.Affected)
	} else {
		ev.Reason = fmt.Sprintf("%d rows returned", len(res.Rows))
	}
	s.audit.Record(ev)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// runQuery connects with an IAM token and runs one statement: in a READ
// ONLY transaction unless the database allows writes, with the time the
// approver granted.
func runQuery(ctx context.Context, db *Database, q Query, creds awsCredentials, region string, now time.Time) (*sqlResult, error) {
	host, port, _ := net.SplitHostPort(db.Address)
	token := rdsAuthToken(host, port, db.User, region, creds, now)
	pem, err := os.ReadFile(db.CAFile)
	if err != nil {
		return nil, errors.New("cannot read the CA bundle")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("the CA bundle has no certificate")
	}
	mc := mysql.NewConfig()
	mc.User, mc.Passwd, mc.Net, mc.Addr = db.User, token, "tcp", db.Address
	mc.AllowCleartextPasswords = true // the IAM token goes over TLS only
	mc.TLS = &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}
	mc.Timeout = 10 * time.Second
	mc.MultiStatements = false
	conn, err := mysql.NewConnector(mc)
	if err != nil {
		return nil, err
	}
	sdb := sql.OpenDB(conn)
	defer sdb.Close()
	sdb.SetMaxOpenConns(1)
	c, err := sdb.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	ms := int64(time.Duration(q.Timeout) / time.Millisecond)
	if _, err := c.ExecContext(ctx, "SET SESSION max_execution_time = "+strconv.FormatInt(ms, 10)); err != nil {
		return nil, err
	}
	qctx, cancel := context.WithTimeout(ctx, time.Duration(q.Timeout))
	defer cancel()
	tx, err := c.BeginTx(qctx, &sql.TxOptions{ReadOnly: !db.Write})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	res := &sqlResult{}
	rows, err := tx.QueryContext(qctx, q.SQL)
	if err != nil {
		return nil, err
	}
	cols, _ := rows.Columns()
	res.Columns = cols
	for rows.Next() {
		if len(res.Rows) >= db.maxRows() {
			res.Truncated = true
			break
		}
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			rows.Close()
			return nil, err
		}
		row := make([]*string, len(cols))
		for i, v := range vals {
			if v.Valid {
				s := v.String
				row[i] = &s
			}
		}
		res.Rows = append(res.Rows, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		res.Columns = nil
	}
	if db.Write {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// rdsAuthToken is the IAM database authentication token: a presigned
// "connect" URL for the user, without the scheme, valid 15 minutes.
func rdsAuthToken(host, port, user, region string, creds awsCredentials, now time.Time) string {
	amzDate := now.UTC().Format("20060102T150405Z")
	date := amzDate[:8]
	scope := date + "/" + region + "/rds-db/aws4_request"
	q := url.Values{}
	q.Set("Action", "connect")
	q.Set("DBUser", user)
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", creds.AccessKeyID+"/"+scope)
	q.Set("X-Amz-Date", amzDate)
	q.Set("X-Amz-Expires", "900")
	q.Set("X-Amz-SignedHeaders", "host")
	if creds.SessionToken != "" {
		q.Set("X-Amz-Security-Token", creds.SessionToken)
	}
	query := strings.ReplaceAll(q.Encode(), "+", "%20")
	hostPort := host + ":" + port
	canonical := strings.Join([]string{"GET", "/", query, "host:" + hostPort, "", "host", sha256Hex("")}, "\n")
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex(canonical)
	key := hmacSHA256(hmacSHA256(hmacSHA256(hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), date), region), "rds-db"), "aws4_request")
	sig := fmt.Sprintf("%x", hmacSHA256(key, toSign))
	return hostPort + "/?" + query + "&X-Amz-Signature=" + sig
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}
