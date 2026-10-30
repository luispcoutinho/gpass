package main

import (
	"encoding/base32"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestResolveChoice(t *testing.T) {
	names := []string{"github", "okta", "okta-fedramp", "42"}
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"2", "okta", false},
		{"okta", "okta", false}, // exact beats substring match with okta-fedramp
		{"fed", "okta-fedramp", false},
		{"GIT", "github", false},
		{"42", "42", false}, // exact name beats numeric index
		{"9", "", true},
		{"zzz", "", true},
		{"t", "", true}, // ambiguous
		{"", "", true},
	}
	for _, c := range cases {
		got, err := resolveChoice(names, c.in)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("resolveChoice(%q) = %q, %v; want %q (err=%v)", c.in, got, err, c.want, c.wantErr)
		}
	}
}

func TestFilterItems(t *testing.T) {
	items := []pickItem{{"fortinet-support", ""}, {"github", "lpcoutinho"}, {"okta", "okta"}, {"okta-fedramp", ""}}
	names := func(q string) []string {
		var out []string
		for _, i := range filterItems(items, q) {
			out = append(out, items[i].name)
		}
		return out
	}
	eq := func(got, want []string) bool { return strings.Join(got, ",") == strings.Join(want, ",") }
	if got := names(""); len(got) != 4 || got[0] != "fortinet-support" {
		t.Errorf("empty query: %v", got)
	}
	if got := names("ghb"); !eq(got, []string{"github"}) { // fuzzy subsequence
		t.Errorf("ghb: %v", got)
	}
	if got := names("okta fed"); !eq(got, []string{"okta-fedramp"}) { // all terms must match
		t.Errorf("okta fed: %v", got)
	}
	if got := names("lpc"); !eq(got, []string{"github"}) { // matches username
		t.Errorf("lpc: %v", got)
	}
	if got := names("OKTA"); !eq(got, []string{"okta", "okta-fedramp"}) { // case-insensitive, stable order
		t.Errorf("OKTA: %v", got)
	}
	if got := names("zzz"); len(got) != 0 {
		t.Errorf("zzz: %v", got)
	}
}

func TestParseKeys(t *testing.T) {
	kinds := func(b string) []keyKind {
		var out []keyKind
		for _, e := range parseKeys([]byte(b)) {
			out = append(out, e.k)
		}
		return out
	}
	cases := []struct {
		in   string
		want []keyKind
	}{
		{"\x1b[A\x1b[B", []keyKind{keyUp, keyDown}},
		{"\x1bOB", []keyKind{keyDown}},
		{"\x1b", []keyKind{keyCancel}},
		{"\x03", []keyKind{keyCancel}},
		{"a\r", []keyKind{keyRune, keyEnter}},
		{"\x7f", []keyKind{keyBackspace}},
		{"\x1b[3~", nil}, // unknown sequence dropped
		{"é", []keyKind{keyRune}},
	}
	for _, c := range cases {
		got := kinds(c.in)
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("parseKeys(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestClearIfUnchanged(t *testing.T) {
	var slept time.Duration
	sleep := func(d time.Duration) { slept = d }
	run := func(clip string) (cleared bool) {
		clearIfUnchanged("secret", 30*time.Second, sleep,
			func() (string, error) { return clip, nil },
			func(s string) error { cleared = s == ""; return nil })
		return
	}
	if !run("secret") || slept != 30*time.Second {
		t.Error("unchanged clipboard should be cleared after the wait")
	}
	if run("something else the user copied") {
		t.Error("a newer clipboard value must not be wiped")
	}
}
