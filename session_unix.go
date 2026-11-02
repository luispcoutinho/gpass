//go:build unix

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// The unlock session is a small detached process that keeps the master password in
// memory and hands it to later gpass runs over a unix socket, until it has been idle
// for sessionTTL(). The socket lives in a private 0700 directory owned by this user.

// sessionSocket returns the per-vault socket path, creating and checking the private
// directory that holds it.
func sessionSocket(path string) (string, error) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("gpass-%d", os.Getuid()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != os.Getuid() || fi.Mode().Perm() != 0o700 {
		return "", errors.New("insecure session directory " + dir)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(dir, hex.EncodeToString(sum[:8])+".sock"), nil
}

func dialSession(sock string) (net.Conn, error) {
	c, err := net.DialTimeout("unix", sock, 300*time.Millisecond)
	if err == nil {
		c.SetDeadline(time.Now().Add(2 * time.Second))
	}
	return c, err
}

// sessionPassword returns the cached master password, or nil when no session is active.
func sessionPassword(path string) []byte {
	sock, err := sessionSocket(path)
	if err != nil {
		return nil
	}
	c, err := dialSession(sock)
	if err != nil {
		return nil
	}
	defer c.Close()
	if _, err := c.Write([]byte{'g'}); err != nil {
		return nil
	}
	pw, err := io.ReadAll(io.LimitReader(c, 4096))
	if err != nil || len(pw) == 0 {
		return nil
	}
	return pw
}

// sessionLock ends the session for this vault, if one is running.
func sessionLock(path string) {
	sock, err := sessionSocket(path)
	if err != nil {
		return
	}
	c, err := dialSession(sock)
	if err != nil {
		return
	}
	defer c.Close()
	c.Write([]byte{'x'})
	io.Copy(io.Discard, c) // returns once the agent has closed the connection
}

// startSession launches the agent holding pw. Best effort: failure just means the
// next run asks for the password again. The password goes over stdin, never argv.
func startSession(path string, pw []byte) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "_agent", strconv.Itoa(int(sessionTTL().Seconds())), abs)
	detach(cmd)
	in, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	in.Write(pw)
	in.Close()
	ready := make(chan struct{})
	go func() {
		bufio.NewReader(out).ReadString('\n')
		close(ready)
	}()
	select { // wait until the socket is listening so the very next run can use it
	case <-ready:
	case <-time.After(2 * time.Second):
	}
	cmd.Process.Release()
}

// cmdAgent is the hidden `gpass _agent <seconds> <vault>` server behind startSession.
func cmdAgent(args []string) error {
	if len(args) != 2 {
		return errors.New("internal command")
	}
	secs, err := strconv.Atoi(args[0])
	if err != nil || secs <= 0 {
		return errors.New("internal command")
	}
	ttl := time.Duration(secs) * time.Second
	pw, err := io.ReadAll(os.Stdin)
	if err != nil || len(pw) == 0 {
		return errors.New("no password supplied")
	}
	defer func() {
		for i := range pw {
			pw[i] = 0
		}
	}()
	sock, err := sessionSocket(args[1])
	if err != nil {
		return err
	}
	if c, err := net.DialTimeout("unix", sock, 200*time.Millisecond); err == nil {
		c.Close()
		return nil // a live agent already serves this vault
	}
	os.Remove(sock) // stale socket from a crashed agent
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	defer ln.Close() // also unlinks the socket
	os.Chmod(sock, 0o600)
	syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}) // no core dumps holding the password

	fmt.Println("1") // tell the parent we are listening
	os.Stdout.Close()

	ul := ln.(*net.UnixListener)
	deadline := time.Now().Add(ttl)
	for {
		ul.SetDeadline(deadline)
		c, err := ul.Accept()
		if err != nil {
			return nil // idle timeout
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		var op [1]byte
		if _, err := io.ReadFull(c, op[:]); err == nil {
			switch op[0] {
			case 'g':
				c.Write(pw)
				deadline = time.Now().Add(ttl) // each use extends the session
			case 'x':
				c.Close()
				return nil
			}
		}
		c.Close()
	}
}
