package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	vaultVersion = 1
	keyLen       = 32
	saltLen      = 16
	argonTime    = 3
	argonMemKiB  = 64 * 1024
	argonThreads = 4
)

var errBadPassword = errors.New("wrong master password or corrupted vault")

// Entry is a single credential. OTP holds a base32 secret or an otpauth:// URI.
type Entry struct {
	Username string    `json:"username,omitempty"`
	Password string    `json:"password,omitempty"`
	OTP      string    `json:"otp,omitempty"`
	Updated  time.Time `json:"updated"`
}

// Vault is the decrypted in-memory view.
type Vault struct {
	Entries map[string]Entry `json:"entries"`
}

// file is the on-disk, encrypted representation.
type file struct {
	Version int    `json:"version"`
	Time    uint32 `json:"argon_time"`
	MemKiB  uint32 `json:"argon_mem_kib"`
	Threads uint8  `json:"argon_threads"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Data    []byte `json:"data"`
}

func (v *Vault) Names() []string {
	names := make([]string, 0, len(v.Entries))
	for n := range v.Entries {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func deriveKey(pw []byte, salt []byte, t, mem uint32, threads uint8) []byte {
	return argon2.IDKey(pw, salt, t, mem, threads, keyLen)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// header is authenticated as additional data so KDF params can't be tampered with.
// The "motp" tag is the original format identifier; kept so existing vaults still open.
func (f *file) aad() []byte {
	return []byte(fmt.Sprintf("motp/%d/%d/%d/%d", f.Version, f.Time, f.MemKiB, f.Threads))
}

// Save encrypts v under pw and atomically writes it to path with 0600 perms.
// A fresh salt and nonce are generated on every save.
func Save(path string, v *Vault, pw []byte) error {
	plain, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f := &file{
		Version: vaultVersion,
		Time:    argonTime,
		MemKiB:  argonMemKiB,
		Threads: argonThreads,
		Salt:    make([]byte, saltLen),
	}
	if _, err := rand.Read(f.Salt); err != nil {
		return err
	}
	gcm, err := newGCM(deriveKey(pw, f.Salt, f.Time, f.MemKiB, f.Threads))
	if err != nil {
		return err
	}
	f.Nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(f.Nonce); err != nil {
		return err
	}
	f.Data = gcm.Seal(nil, f.Nonce, plain, f.aad())

	out, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vault-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Load reads and decrypts the vault at path.
func Load(path string, pw []byte) (*Vault, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("invalid vault file: %w", err)
	}
	if f.Version != vaultVersion {
		return nil, fmt.Errorf("unsupported vault version %d", f.Version)
	}
	// Bound KDF cost so a tampered header can't force huge allocations.
	if f.Time == 0 || f.Time > 10 || f.MemKiB == 0 || f.MemKiB > 1<<20 || f.Threads == 0 {
		return nil, errors.New("invalid vault KDF parameters")
	}
	gcm, err := newGCM(deriveKey(pw, f.Salt, f.Time, f.MemKiB, f.Threads))
	if err != nil {
		return nil, err
	}
	if len(f.Nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid vault nonce")
	}
	plain, err := gcm.Open(nil, f.Nonce, f.Data, f.aad())
	if err != nil {
		return nil, errBadPassword
	}
	v := &Vault{}
	if err := json.Unmarshal(plain, v); err != nil {
		return nil, err
	}
	if v.Entries == nil {
		v.Entries = map[string]Entry{}
	}
	return v, nil
}
