package main

import (
	"encoding/base32"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors (8 digits, SHA1/256/512).
func TestTOTPRFC6238(t *testing.T) {
	ascii := "12345678901234567890"
	seeds := map[string]string{
		"SHA1":   b32(ascii),
		"SHA256": b32(ascii + ascii[:12]),
		"SHA512": b32(ascii + ascii + ascii + ascii[:4]),
	}
	cases := []struct {
		algo string
		unix int64
		want string
	}{
		{"SHA1", 59, "94287082"},
		{"SHA1", 1111111109, "07081804"},
		{"SHA256", 59, "46119246"},
		{"SHA512", 59, "90693936"},
		{"SHA512", 20000000000, "47863826"},
	}
	for _, c := range cases {
		uri := "otpauth://totp/x?digits=8&algorithm=" + c.algo + "&secret=" + seeds[c.algo]
		p, err := parseOTP(uri)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := p.code(time.Unix(c.unix, 0))
		if got != c.want {
			t.Errorf("%s @%d: got %s want %s", c.algo, c.unix, got, c.want)
		}
	}
}

func TestParseOTPBare(t *testing.T) {
	p, err := parseOTP("gezd gndv-gy3t qojq")
	if err != nil || p.digits != 6 || p.period != 30 {
		t.Fatalf("bare parse failed: %v %+v", err, p)
	}
	if _, err := parseOTP("not base32!"); err == nil {
		t.Error("expected error for invalid secret")
	}
}

func TestVaultRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "vault.json")
	v := &Vault{Entries: map[string]Entry{"gh": {Username: "me", Password: "pw", OTP: "GEZDGNBV"}}}
	if err := Save(path, v, []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("vault perms = %v, want 0600", fi.Mode().Perm())
	}
	got, err := Load(path, []byte("correct horse"))
	if err != nil || got.Entries["gh"].Password != "pw" {
		t.Fatalf("load: %v %+v", err, got)
	}
	if _, err := Load(path, []byte("wrong")); !errors.Is(err, errBadPassword) {
		t.Errorf("wrong password: got %v", err)
	}
}

func TestGenerate(t *testing.T) {
	p, err := generate(32)
	if err != nil || len(p) != 32 {
		t.Fatalf("generate: %q %v", p, err)
	}
	if _, err := generate(4); err == nil {
		t.Error("expected error for short length")
	}
}

func b32(s string) string { return base32.StdEncoding.EncodeToString([]byte(s)) }

func TestPasswdReencrypts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	v := &Vault{Entries: map[string]Entry{"a": {Password: "x"}}}
	if err := Save(path, v, []byte("old-password")); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, v, []byte("new-password")); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, []byte("old-password")); err == nil {
		t.Error("old password still works")
	}
	if _, err := Load(path, []byte("new-password")); err != nil {
		t.Error(err)
	}
}
