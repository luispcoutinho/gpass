package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/term"
)

var (
	errBiometricCancelled   = errors.New("touch id cancelled")
	errBiometricUnsupported = errors.New("touch id is only supported on macOS builds with cgo")
)

// noBiometric forces a typed master password (used by enable and passwd).
var noBiometric bool

// keychainAccount identifies a vault in the Keychain by its absolute path.
func keychainAccount(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

// touchIDPassword returns the master password after a successful Touch ID check,
// or nil when the caller should fall back to the typed prompt.
func touchIDPassword(path string) []byte {
	if noBiometric || !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil
	}
	acct := keychainAccount(path)
	if !biometricAvailable() || !keychainExists(acct) {
		return nil
	}
	if err := biometricAuth("unlock your gpass vault"); err != nil {
		if !errors.Is(err, errBiometricCancelled) {
			fmt.Fprintln(os.Stderr, "gpass:", err)
		}
		return nil
	}
	pw, err := keychainGet(acct)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gpass:", err)
		return nil
	}
	return pw
}

func cmdTouchID(path string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: gpass touchid enable|disable|status")
	}
	acct := keychainAccount(path)
	switch args[0] {
	case "status":
		fmt.Printf("available: %t\nenabled for this vault: %t\n", biometricAvailable(), keychainExists(acct))
		return nil
	case "disable":
		if err := keychainDelete(acct); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "touch id disabled for", acct)
		return nil
	case "enable":
		if !biometricAvailable() {
			return errors.New("touch id is not available on this machine")
		}
		noBiometric = true
		_, pw, err := openVault(path, false) // typed password, verified against the vault
		if err != nil {
			return err
		}
		if err := biometricAuth("enable touch id unlock for gpass"); err != nil {
			return err
		}
		if err := keychainSet(acct, pw); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "touch id enabled for", acct)
		return nil
	}
	return errors.New("usage: gpass touchid enable|disable|status")
}
