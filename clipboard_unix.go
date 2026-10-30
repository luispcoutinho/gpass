//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// detach lets the child outlive the terminal session that started it.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
