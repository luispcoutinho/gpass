package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const defaultClearAfter = 30 * time.Second

// clearAfter is how long a copied value stays on the clipboard. $GPASS_CLEAR_AFTER
// overrides it in seconds; 0 keeps the value until something else replaces it.
func clearAfter() time.Duration {
	if v := os.Getenv("GPASS_CLEAR_AFTER"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Second
		}
	}
	return defaultClearAfter
}

type clipTool struct{ copyCmd, pasteCmd []string }

func clipboardTool() (clipTool, error) {
	var candidates []clipTool
	switch runtime.GOOS {
	case "darwin":
		candidates = []clipTool{{[]string{"pbcopy"}, []string{"pbpaste"}}}
	default:
		candidates = []clipTool{
			{[]string{"wl-copy"}, []string{"wl-paste", "-n"}},
			{[]string{"xclip", "-selection", "clipboard"}, []string{"xclip", "-selection", "clipboard", "-o"}},
			{[]string{"xsel", "-ib"}, []string{"xsel", "-ob"}},
		}
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c.copyCmd[0]); err == nil {
			return c, nil
		}
	}
	return clipTool{}, errors.New("no clipboard tool found (pbcopy, wl-copy, xclip or xsel)")
}

func (t clipTool) write(s string) error {
	cmd := exec.Command(t.copyCmd[0], t.copyCmd[1:]...)
	cmd.Stdin = strings.NewReader(s)
	return cmd.Run()
}

func (t clipTool) read() (string, error) {
	out, err := exec.Command(t.pasteCmd[0], t.pasteCmd[1:]...).Output()
	return string(out), err
}

// emit prints value to stdout, or copies it to the clipboard when toClipboard is set.
// A copied value is cleared again after clearAfter() unless the clipboard changed.
func emit(value string, toClipboard bool) error {
	if !toClipboard {
		printValue(value)
		return nil
	}
	tool, err := clipboardTool()
	if err != nil {
		return err
	}
	if err := tool.write(value); err != nil {
		return fmt.Errorf("copy to clipboard: %w", err)
	}
	ttl := clearAfter()
	if ttl == 0 {
		fmt.Fprintln(os.Stderr, "copied to clipboard")
		return nil
	}
	if err := spawnClear(value, ttl); err != nil {
		fmt.Fprintln(os.Stderr, "gpass: warning: could not schedule clipboard clear:", err)
	}
	fmt.Fprintf(os.Stderr, "copied to clipboard, clears in %ds\n", int(ttl.Seconds()))
	return nil
}

// spawnClear starts a detached copy of this binary that clears the clipboard later.
// The value goes over its stdin, never argv, so it does not show up in `ps`.
func spawnClear(value string, ttl time.Duration) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "_clear", strconv.Itoa(int(ttl.Seconds())))
	detach(cmd)
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if _, err := io.WriteString(in, value); err != nil {
		return err
	}
	in.Close()
	return cmd.Process.Release()
}

// clearIfUnchanged empties the clipboard after wait, but only if it still holds
// value, so a later copy by the user is never wiped.
func clearIfUnchanged(value string, wait time.Duration, sleep func(time.Duration), read func() (string, error), write func(string) error) {
	sleep(wait)
	if cur, err := read(); err == nil && cur == value {
		write("")
	}
}

// cmdClear is the hidden helper behind spawnClear.
func cmdClear(args []string) error {
	if len(args) != 1 {
		return errors.New("internal command")
	}
	secs, err := strconv.Atoi(args[0])
	if err != nil || secs < 0 {
		return errors.New("internal command")
	}
	value, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	tool, err := clipboardTool()
	if err != nil {
		return err
	}
	clearIfUnchanged(string(value), time.Duration(secs)*time.Second, time.Sleep, tool.read, tool.write)
	return nil
}
