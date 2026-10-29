package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
)

const usage = `gpass - minimal password and OTP manager

usage:
  gpass init [folder]               create a vault in folder (asks; default: current folder)
  gpass add <name> [-u user] [-g] [-l len]
                                    add or update an entry (prompts for secrets)
  gpass edit <name> [-u user] [-n newname] [-p] [-g] [-l len] [-o] [-clear-otp]
                                    change fields of an existing entry
  gpass passwd                       change the master password
  gpass get <name> [-u]              print the password (or username with -u)
  gpass otp <name>                   print the current TOTP code
  gpass ls                           list entry names
  gpass rm <name>                    remove an entry
  gpass gen [-l len]                 generate a random password

  gpass git [repo-url] [dir]        keep the vault in a git repo; auto commit+push on changes
  gpass touchid enable|disable|status
                                    unlock with Touch ID instead of typing the master password (macOS)
  gpass sync                        pull then push the vault repo
  gpass where                       print the vault path in use

global flag (before the command):
  -f <path>                         use this vault file for this run

vault: -f, else $GPASS_VAULT, else the path in config (set by "gpass git"),
       else <user config dir>/gpass/vault.json
When stdin is not a terminal, secrets are read from stdin, one per line.`

var stdin = bufio.NewReader(os.Stdin)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gpass:", err)
		os.Exit(1)
	}
}

// prompt reads a secret without echo on a terminal, or a plain line otherwise.
func prompt(label string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, label+": ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return b, err
	}
	line, err := stdin.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

func openVault(path string, write bool) (*Vault, []byte, error) {
	if write {
		autoPull(path)
	}
	if pw := touchIDPassword(path); pw != nil {
		v, err := Load(path, pw)
		if err == nil {
			return v, pw, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, errors.New("no vault found, run `gpass init`")
		}
		fmt.Fprintln(os.Stderr, "gpass: stored password no longer works; re-run `gpass touchid enable`")
	}
	pw, err := prompt("Master password")
	if err != nil {
		return nil, nil, err
	}
	v, err := Load(path, pw)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, errors.New("no vault found, run `gpass init`")
	}
	return v, pw, err
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Println(usage)
		return nil
	}
	var flagPath string
	if args[0] == "-f" || args[0] == "--vault" {
		if len(args) < 3 {
			return errors.New("usage: gpass -f <path> <command>")
		}
		flagPath, args = args[1], args[2:]
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "gen":
		return cmdGen(rest)
	case "git":
		return cmdGit(rest)
	case "init":
		return cmdInit(flagPath, rest)
	}
	path, err := resolvePath(flagPath)
	if err != nil {
		return err
	}
	switch cmd {
	case "where":
		fmt.Println(path)
		return nil
	case "touchid":
		return cmdTouchID(path, rest)
	case "sync":
		return cmdSync(path)
	case "add":
		return cmdAdd(path, rest)
	case "edit":
		return cmdEdit(path, rest)
	case "passwd":
		return cmdPasswd(path)
	case "get":
		return cmdGet(path, rest)
	case "otp":
		return cmdOTP(path, rest)
	case "ls":
		return cmdLs(path)
	case "rm":
		return cmdRm(path, rest)
	}
	return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
}

// splitName takes the leading positional <name> so flags may follow it.
func splitName(fs *flag.FlagSet, args []string) (string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", fmt.Errorf("usage: gpass %s <name> [flags]", fs.Name())
	}
	return args[0], fs.Parse(args[1:])
}

// initTarget decides where a new vault goes. chosen is true when the user picked
// a folder, in which case it is remembered in the config for later commands.
func initTarget(flagPath string, args []string) (path string, chosen bool, err error) {
	if flagPath != "" || os.Getenv("GPASS_VAULT") != "" {
		if len(args) > 0 {
			return "", false, errors.New("a folder argument conflicts with -f / $GPASS_VAULT")
		}
		p, err := resolvePath(flagPath)
		return p, false, err
	}
	var dir string
	if len(args) > 0 {
		dir = args[0]
	} else {
		p, err := resolvePath("")
		if err != nil {
			return "", false, err
		}
		if _, ok := repoFor(p); ok {
			return p, false, nil // vault lives in the configured git repo
		}
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprint(os.Stderr, "Vault folder (empty = current folder): ")
			line, err := stdin.ReadString('\n')
			if err != nil && line == "" {
				return "", false, err
			}
			dir = strings.TrimSpace(line)
		}
	}
	if strings.HasPrefix(dir, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false, err
		}
		dir = filepath.Join(home, dir[2:])
	}
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", false, err
	}
	return filepath.Join(abs, "vault.json"), true, nil
}

func cmdInit(flagPath string, args []string) error {
	path, chosen, err := initTarget(flagPath, args)
	if err != nil {
		return err
	}
	autoPull(path)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("vault already exists at %s", path)
	}
	pw, err := prompt("New master password")
	if err != nil {
		return err
	}
	if len(pw) < 8 {
		return errors.New("master password must be at least 8 characters")
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		again, err := prompt("Confirm master password")
		if err != nil {
			return err
		}
		if string(again) != string(pw) {
			return errors.New("passwords do not match")
		}
	}
	if err := save(path, &Vault{Entries: map[string]Entry{}}, pw); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "vault created at", path)
	if chosen {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		cfg.Vault = path
		if err := cfg.save(); err != nil {
			return err
		}
	}
	return nil
}

func cmdAdd(path string, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	user := fs.String("u", "", "username")
	gen := fs.Bool("g", false, "generate a random password")
	length := fs.Int("l", 24, "generated password length")
	name, err := splitName(fs, args)
	if err != nil {
		return err
	}
	v, pw, err := openVault(path, true)
	if err != nil {
		return err
	}
	e := v.Entries[name]
	if *user != "" {
		e.Username = *user
	}
	if *gen {
		p, err := generate(*length)
		if err != nil {
			return err
		}
		e.Password = p
		fmt.Fprintln(os.Stderr, "generated password for", name)
	} else {
		p, err := prompt("Password (empty to keep/skip)")
		if err != nil {
			return err
		}
		if len(p) > 0 {
			e.Password = string(p)
		}
	}
	o, err := prompt("OTP secret or otpauth:// URI (empty to skip)")
	if err != nil {
		return err
	}
	if len(o) > 0 {
		if _, err := parseOTP(string(o)); err != nil {
			return err
		}
		e.OTP = string(o)
	}
	e.Updated = time.Now().UTC()
	v.Entries[name] = e
	return save(path, v, pw)
}

func cmdEdit(path string, args []string) error {
	fs := flag.NewFlagSet("edit", flag.ContinueOnError)
	user := fs.String("u", "", "new username")
	newName := fs.String("n", "", "rename entry")
	setPw := fs.Bool("p", false, "prompt for a new password")
	gen := fs.Bool("g", false, "generate a new random password")
	length := fs.Int("l", 24, "generated password length")
	setOTP := fs.Bool("o", false, "prompt for a new OTP secret or URI")
	clearOTP := fs.Bool("clear-otp", false, "remove the OTP secret")
	name, err := splitName(fs, args)
	if err != nil {
		return err
	}
	if *setPw && *gen {
		return errors.New("-p and -g are mutually exclusive")
	}
	if *setOTP && *clearOTP {
		return errors.New("-o and -clear-otp are mutually exclusive")
	}
	v, pw, err := openVault(path, true)
	if err != nil {
		return err
	}
	e, err := lookup(v, name)
	if err != nil {
		return err
	}
	if *user != "" {
		e.Username = *user
	}
	switch {
	case *gen:
		p, err := generate(*length)
		if err != nil {
			return err
		}
		e.Password = p
	case *setPw:
		p, err := prompt("New password")
		if err != nil {
			return err
		}
		e.Password = string(p)
	}
	switch {
	case *clearOTP:
		e.OTP = ""
	case *setOTP:
		o, err := prompt("OTP secret or otpauth:// URI")
		if err != nil {
			return err
		}
		if _, err := parseOTP(string(o)); err != nil {
			return err
		}
		e.OTP = string(o)
	}
	e.Updated = time.Now().UTC()
	if *newName != "" && *newName != name {
		if _, exists := v.Entries[*newName]; exists {
			return fmt.Errorf("entry %q already exists", *newName)
		}
		delete(v.Entries, name)
		name = *newName
	}
	v.Entries[name] = e
	return save(path, v, pw)
}

func cmdPasswd(path string) error {
	noBiometric = true // changing the master password always needs the typed one
	v, _, err := openVault(path, true)
	if err != nil {
		return err
	}
	pw, err := prompt("New master password")
	if err != nil {
		return err
	}
	if len(pw) < 8 {
		return errors.New("master password must be at least 8 characters")
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		again, err := prompt("Confirm new master password")
		if err != nil {
			return err
		}
		if string(again) != string(pw) {
			return errors.New("passwords do not match")
		}
	}
	if err := save(path, v, pw); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "master password changed")
	if acct := keychainAccount(path); keychainExists(acct) {
		if err := keychainSet(acct, pw); err != nil {
			fmt.Fprintln(os.Stderr, "gpass: warning: could not update Touch ID password:", err)
		}
	}
	return nil
}

// printValue writes a single value to stdout. The trailing newline is added only
// on a terminal, so `gpass otp x | pbcopy` copies the bare value.
func printValue(s string) {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Println(s)
		return
	}
	fmt.Print(s)
}

func lookup(v *Vault, name string) (Entry, error) {
	e, ok := v.Entries[name]
	if !ok {
		return e, fmt.Errorf("no entry %q", name)
	}
	return e, nil
}

func cmdGet(path string, args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	user := fs.Bool("u", false, "print username instead of password")
	name, err := splitName(fs, args)
	if err != nil {
		return err
	}
	v, _, err := openVault(path, false)
	if err != nil {
		return err
	}
	e, err := lookup(v, name)
	if err != nil {
		return err
	}
	if *user {
		printValue(e.Username)
	} else {
		printValue(e.Password)
	}
	return nil
}

func cmdOTP(path string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: gpass otp <name>")
	}
	v, _, err := openVault(path, false)
	if err != nil {
		return err
	}
	e, err := lookup(v, args[0])
	if err != nil {
		return err
	}
	if e.OTP == "" {
		return fmt.Errorf("entry %q has no OTP secret", args[0])
	}
	p, err := parseOTP(e.OTP)
	if err != nil {
		return err
	}
	code, left := p.code(time.Now())
	printValue(code)
	if left < 5 {
		fmt.Fprintf(os.Stderr, "expires in %ds\n", left)
	}
	return nil
}

func cmdLs(path string) error {
	v, _, err := openVault(path, false)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	if term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprintln(tw, "NAME\tUSERNAME\tOTP\tUPDATED")
	}
	for _, n := range v.Names() {
		e := v.Entries[n]
		otp, upd := "-", "-"
		if e.OTP != "" {
			otp = "yes"
		}
		if !e.Updated.IsZero() {
			upd = e.Updated.Local().Format("2006-01-02")
		}
		user := e.Username
		if user == "" {
			user = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", n, user, otp, upd)
	}
	return tw.Flush()
}

func cmdRm(path string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: gpass rm <name>")
	}
	v, pw, err := openVault(path, true)
	if err != nil {
		return err
	}
	if _, err := lookup(v, args[0]); err != nil {
		return err
	}
	delete(v.Entries, args[0])
	return save(path, v, pw)
}

func cmdGen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	length := fs.Int("l", 24, "password length")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := generate(*length)
	if err != nil {
		return err
	}
	printValue(p)
	return nil
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+"

func generate(n int) (string, error) {
	if n < 8 || n > 256 {
		return "", errors.New("length must be between 8 and 256")
	}
	max := big.NewInt(int64(len(charset)))
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = charset[idx.Int64()]
	}
	return string(b), nil
}
