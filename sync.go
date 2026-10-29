package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Config is persisted at <user config dir>/gpass/config.json.
type Config struct {
	Vault string `json:"vault,omitempty"` // vault file path
	Repo  string `json:"repo,omitempty"`  // git remote URL
	Dir   string `json:"dir,omitempty"`   // local clone of Repo
}

func configDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "gpass"), nil
}

func loadConfig() (Config, error) {
	var c Config
	dir, err := configDir()
	if err != nil {
		return c, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(raw, &c)
}

func (c Config) save() error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.json"), raw, 0o600)
}

// resolvePath picks the vault file: -f flag, $GPASS_VAULT, config, then default.
func resolvePath(flagPath string) (string, error) {
	if flagPath != "" {
		return flagPath, nil
	}
	if p := os.Getenv("GPASS_VAULT"); p != "" {
		return p, nil
	}
	c, err := loadConfig()
	if err != nil {
		return "", err
	}
	if c.Vault != "" {
		return c.Vault, nil
	}
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "vault.json"), nil
}

// repoFor returns the git clone dir when path lives inside the configured repo.
func repoFor(path string) (string, bool) {
	c, err := loadConfig()
	if err != nil || c.Dir == "" {
		return "", false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(c.Dir, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return c.Dir, true
}

// runGit runs git in dir; its stdout goes to stderr so secrets on stdout stay clean.
func runGit(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func gitQuiet(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	return cmd.Run()
}

func hasCommits(dir string) bool {
	return gitQuiet(dir, "rev-parse", "--verify", "-q", "HEAD") == nil
}

func pull(dir string) error {
	if !hasCommits(dir) {
		return nil // fresh empty repo, nothing to pull
	}
	return runGit(dir, "pull", "--ff-only")
}

// autoPull refreshes the clone before a write; failures only warn.
func autoPull(path string) {
	dir, ok := repoFor(path)
	if !ok {
		return
	}
	if err := pull(dir); err != nil {
		fmt.Fprintln(os.Stderr, "gpass: warning: git pull failed:", err)
	}
}

// push commits the vault file and pushes it.
func push(dir, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(dir, abs)
	if err != nil {
		return err
	}
	if err := runGit(dir, "add", "--", rel); err != nil {
		return err
	}
	if gitQuiet(dir, "diff", "--cached", "--quiet") == nil && hasCommits(dir) {
		return nil // nothing changed
	}
	if err := runGit(dir, "commit", "-q", "-m", "gpass: update vault"); err != nil {
		return err
	}
	return runGit(dir, "push", "-q", "-u", "origin", "HEAD")
}

// save writes the vault and, when git sync is configured, commits and pushes it.
func save(path string, v *Vault, pw []byte) error {
	if err := Save(path, v, pw); err != nil {
		return err
	}
	if dir, ok := repoFor(path); ok {
		if err := push(dir, path); err != nil {
			return fmt.Errorf("vault saved locally but git sync failed: %w", err)
		}
	}
	return nil
}

func cmdGit(args []string) error {
	var url, dir string
	if len(args) > 0 {
		url = args[0]
	}
	if len(args) > 1 {
		dir = args[1]
	}
	if len(args) > 2 {
		return errors.New("usage: gpass git [repo-url] [local-dir]")
	}
	if url == "" {
		fmt.Fprint(os.Stderr, "Git repo URL (use a PRIVATE repo): ")
		line, err := stdin.ReadString('\n')
		if err != nil && line == "" {
			return err
		}
		url = strings.TrimSpace(line)
	}
	if url == "" || strings.HasPrefix(url, "-") {
		return errors.New("invalid repo URL")
	}
	if dir == "" {
		cd, err := configDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(cd, "repo")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	prior, err := resolvePath("") // where the vault lives before switching
	if err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			return err
		}
		if err := runGit("", "clone", "--", url, dir); err != nil {
			return fmt.Errorf("git clone failed: %w", err)
		}
	}
	target := filepath.Join(dir, "vault.json")
	cfg := Config{Vault: target, Repo: url, Dir: dir}
	if err := cfg.save(); err != nil {
		return err
	}

	_, targetErr := os.Stat(target)
	switch {
	case targetErr == nil:
		fmt.Fprintln(os.Stderr, "existing vault found in repo; using", target)
	case prior != target && fileExists(prior):
		raw, err := os.ReadFile(prior)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, raw, 0o600); err != nil {
			return err
		}
		if err := push(dir, target); err != nil {
			return fmt.Errorf("vault copied but git push failed: %w", err)
		}
		fmt.Fprintln(os.Stderr, "copied existing vault into repo and pushed")
	default:
		fmt.Fprintln(os.Stderr, "repo ready; run `gpass init` to create the vault in it")
	}
	return nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func cmdSync(path string) error {
	dir, ok := repoFor(path)
	if !ok {
		return errors.New("vault is not in a git repo; run `gpass git <url>` first")
	}
	if err := pull(dir); err != nil {
		return err
	}
	if !fileExists(path) {
		return errors.New("no vault to push")
	}
	return push(dir, path)
}
