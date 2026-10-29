//go:build darwin && cgo

package main

import "testing"

func TestKeychainRoundTrip(t *testing.T) {
	acct := "gpass-test-" + t.Name()
	t.Cleanup(func() { keychainDelete(acct) })
	if keychainExists(acct) {
		t.Fatal("item should not exist yet")
	}
	if err := keychainSet(acct, []byte("s3cret-pw")); err != nil {
		t.Skipf("keychain unavailable: %v", err)
	}
	if !keychainExists(acct) {
		t.Fatal("item should exist")
	}
	got, err := keychainGet(acct)
	if err != nil || string(got) != "s3cret-pw" {
		t.Fatalf("get: %q %v", got, err)
	}
	if err := keychainSet(acct, []byte("changed-pw")); err != nil {
		t.Fatal(err)
	}
	if got, _ := keychainGet(acct); string(got) != "changed-pw" {
		t.Fatalf("update: %q", got)
	}
	if err := keychainDelete(acct); err != nil || keychainExists(acct) {
		t.Fatalf("delete: %v", err)
	}
}
