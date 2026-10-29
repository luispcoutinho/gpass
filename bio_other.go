//go:build !(darwin && cgo)

package main

func biometricAvailable() bool           { return false }
func biometricAuth(string) error         { return errBiometricUnsupported }
func keychainSet(string, []byte) error   { return errBiometricUnsupported }
func keychainExists(string) bool         { return false }
func keychainGet(string) ([]byte, error) { return nil, errBiometricUnsupported }
func keychainDelete(string) error        { return errBiometricUnsupported }
