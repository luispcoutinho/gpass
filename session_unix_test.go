//go:build unix

package main

import (
	"os"
	"testing"
)

func TestSessionSocket(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	a, err := sessionSocket("/vaults/a.json")
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := sessionSocket("/vaults/a.json")
	b, _ := sessionSocket("/vaults/b.json")
	if a != a2 || a == b {
		t.Errorf("socket path must be stable per vault and differ between vaults: %q %q %q", a, a2, b)
	}
	dir := a[:len(a)-len("/0123456789abcdef.sock")]
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("session dir must be 0700: %v %v", fi, err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := sessionSocket("/vaults/a.json"); err == nil {
		t.Error("a group/world-accessible session dir must be rejected")
	}
}
