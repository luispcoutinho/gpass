//go:build !unix

package main

import "errors"

// Unlock sessions need unix sockets; on other platforms every run asks for the password.
func sessionPassword(string) []byte { return nil }
func sessionLock(string)            {}
func startSession(string, []byte)   {}
func cmdAgent([]string) error       { return errors.New("sessions are not supported on this platform") }
