package main

import (
	"os"
	"strconv"
	"time"
)

const defaultSessionTTL = 60 * time.Second

// sessionTTL is how long an unlocked vault stays unlocked after its last use.
// $GPASS_SESSION_SECONDS overrides it; 0 turns sessions off.
func sessionTTL() time.Duration {
	if v := os.Getenv("GPASS_SESSION_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Second
		}
	}
	return defaultSessionTTL
}

// sessionUsable reports whether this run may use or start an unlock session. Sessions
// are interactive-only (piped runs always read the password from stdin), and commands
// that force a typed password (passwd, touchid enable) bypass them.
func sessionUsable() bool {
	return !noBiometric && stdinTTY() && sessionTTL() > 0
}
