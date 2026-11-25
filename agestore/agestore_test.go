package agestore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/rpagliuca/secrets-broker/broker"
)

func write(t *testing.T, dir, name, plaintext string, to age.Recipient) {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, to)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte(plaintext))
	w.Close()
	if err := os.WriteFile(filepath.Join(dir, name+".age"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUnsealReloadSeal(t *testing.T) {
	vault, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	write(t, dir, "svc", `{"value":"hunter2-hunter2","hosts":["api.example.com"]}`, vault.Recipient())
	s := New(dir)

	if _, err := s.Get("svc"); !errors.Is(err, broker.ErrSealed) {
		t.Fatalf("before unseal: %v", err)
	}
	if _, err := s.Unseal([]byte(other.String())); err == nil {
		t.Fatal("unsealed with the wrong key")
	}
	if _, err := s.Get("svc"); !errors.Is(err, broker.ErrSealed) {
		t.Fatalf("a failed unseal must leave the store sealed: %v", err)
	}
	if n, err := s.Unseal([]byte("# comment\n" + vault.String() + "\n")); err != nil || n != 1 {
		t.Fatalf("unseal: n=%d err=%v", n, err)
	}
	sec, err := s.Get("svc")
	if err != nil || string(sec.Value) != "hunter2-hunter2" || len(sec.Hosts) != 1 || sec.Hosts[0] != "api.example.com" {
		t.Fatalf("get: %+v %v", sec, err)
	}
	if _, err := s.Get("missing"); !errors.Is(err, broker.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}

	write(t, dir, "new", `{"value":"another-secret","hosts":["b.example.com"]}`, vault.Recipient())
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("new"); err != nil {
		t.Fatalf("after reload: %v", err)
	}

	s.Seal()
	if _, err := s.Get("svc"); !errors.Is(err, broker.ErrSealed) {
		t.Fatalf("after seal: %v", err)
	}
	if err := s.Reload(); !errors.Is(err, broker.ErrSealed) {
		t.Fatalf("reload while sealed: %v", err)
	}
}

func TestRejectsMalformedSecrets(t *testing.T) {
	vault, _ := age.GenerateX25519Identity()
	for name, plaintext := range map[string]string{
		"raw value":   "just-the-token",
		"no hosts":    `{"value":"hunter2-hunter2"}`,
		"no value":    `{"hosts":["api.example.com"]}`,
		"extra field": `{"value":"hunter2-hunter2","hosts":["a.example.com"],"host":"b"}`,
	} {
		dir := t.TempDir()
		write(t, dir, "svc", plaintext, vault.Recipient())
		_, err := New(dir).Unseal([]byte(vault.String()))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if bytes.Contains([]byte(err.Error()), []byte("hunter2")) || bytes.Contains([]byte(err.Error()), []byte("just-the")) {
			t.Errorf("%s: error quotes the plaintext: %v", name, err)
		}
	}
}
