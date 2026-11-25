package broker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"sync"
	"time"
)

// authority is the certificate authority the broker uses to terminate the
// TLS of its clients. The key is generated at start-up and lives only in
// memory. The certificate carries name constraints, so the CA is useless for
// any host outside the configuration even to a client that trusts it.
type authority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	leafKey *ecdsa.PrivateKey
	pem     []byte

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// authorities is every CA created since the broker started. A reload that
// adds hosts creates one more CA, constrained to the hosts the older ones do
// not cover. The older CAs keep signing for their hosts, so a client that
// read the certificate file before the reload, such as a long-running
// process, keeps working for the hosts it already used.
type authorities struct {
	list  []*authority
	hosts []map[string]bool
	pem   []byte // every CA certificate, oldest first
}

// extend returns a set that also covers hosts. The receiver is not changed.
func (a *authorities) extend(hosts []string) (*authorities, error) {
	var missing []string
	for _, h := range hosts {
		if !slices.ContainsFunc(a.hosts, func(m map[string]bool) bool { return m[h] }) {
			missing = append(missing, h)
		}
	}
	if len(missing) == 0 && len(a.list) > 0 {
		return a, nil
	}
	ca, err := newAuthority(missing)
	if err != nil {
		return nil, err
	}
	covered := map[string]bool{}
	for _, h := range missing {
		covered[h] = true
	}
	return &authorities{
		list:  append(slices.Clone(a.list), ca),
		hosts: append(slices.Clone(a.hosts), covered),
		pem:   append(slices.Clone(a.pem), ca.pem...),
	}, nil
}

func (a *authorities) leaf(host string) (*tls.Certificate, error) {
	for i, m := range a.hosts {
		if m[host] {
			return a.list[i].leaf(host)
		}
	}
	return nil, errors.New("no CA for this host")
}

const (
	caLifetime   = 366 * 24 * time.Hour
	leafLifetime = 48 * time.Hour
	leafRenew    = 12 * time.Hour
)

func newAuthority(hosts []string) (*authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: "secrets-broker ephemeral CA"},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.Add(caLifetime),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         hosts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{
		cert:    cert,
		key:     key,
		leafKey: leafKey,
		pem:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leaves:  map[string]*tls.Certificate{},
	}, nil
}

// leaf returns a certificate for host, issuing a new one when needed.
func (a *authority) leaf(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if c := a.leaves[host]; c != nil && now.Before(c.Leaf.NotAfter.Add(-leafRenew)) {
		return c, nil
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: a.leafKey, Leaf: parsed}
	a.leaves[host] = c
	return c, nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err) // crypto/rand does not fail on supported systems
	}
	return n
}
