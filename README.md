# gpass

A minimalist command-line password manager written in Go. It stores usernames,
passwords and TOTP (OTP) secrets in a single encrypted vault file, with optional
git sync and Touch ID unlock on macOS.

> gpass has not been security reviewed or audited. Get a review before trusting
> it with real credentials.

## Install

Requires Go 1.21+. Touch ID support needs macOS with cgo (Xcode command line tools).

```bash
go build -o gpass .      # build ./gpass
go install .             # or install to $(go env GOPATH)/bin
```

## Quick start

```bash
gpass init                    # asks for a vault folder (Enter = current folder)
gpass add github -u me        # prompts for password, then OTP secret (Enter to skip)
gpass add bank -u me -g       # generate a random password instead
gpass ls
gpass get github              # print the password
gpass otp github | pbcopy     # copy the current TOTP code
```

Secrets are always prompted for (no echo), never passed as arguments, so they stay
out of shell history. When stdin is not a terminal, secrets are read from stdin,
one per line, which allows scripting.

## Commands

| Command | Description |
|---|---|
| `gpass init [folder]` | Create a vault in `folder` (asks if omitted; default: current folder) |
| `gpass add <name> [-u user] [-g] [-l len]` | Add or update an entry |
| `gpass edit <name> [-u user] [-n newname] [-p] [-g] [-l len] [-o] [-clear-otp]` | Change fields of an entry |
| `gpass get <name> [-u]` | Print the password, or the username with `-u` |
| `gpass otp <name>` | Print the current TOTP code |
| `gpass ls` | List entries (name, username, OTP, last updated) |
| `gpass rm <name>` | Remove an entry |
| `gpass passwd` | Change the master password |
| `gpass gen [-l len]` | Generate a random password (no vault needed) |
| `gpass git [repo-url] [dir]` | Keep the vault in a git repo |
| `gpass sync` | Pull then push the vault repo |
| `gpass touchid enable\|disable\|status` | Manage Touch ID unlock (macOS) |
| `gpass where` | Print the vault path in use |

Values from `get`, `otp` and `gen` are printed without a trailing newline when piped,
so `gpass otp x | pbcopy` copies just the code. `otp` prints a warning on stderr
only when the code expires in under 5 seconds.

OTP secrets can be a bare base32 secret or an `otpauth://totp/...` URI; digits (6-8),
period and algorithm (SHA1/SHA256/SHA512) are honoured.

## Vault location

Resolved in this order:

1. `gpass -f <path> <command>` (one run)
2. `$GPASS_VAULT`
3. The path saved in `<user config dir>/gpass/config.json` (set by `gpass init <folder>`
   or `gpass git`)
4. `<user config dir>/gpass/vault.json`

On macOS the user config dir is `~/Library/Application Support`.

## Security design

- The master password is stretched with argon2id (time 3, 64 MiB, 4 threads).
- The whole vault, including entry names, is encrypted with AES-256-GCM. Only the
  header (version, KDF parameters, salt, nonce) is plaintext, and it is authenticated.
- A fresh salt and nonce are generated on every save.
- The vault file is written atomically with `0600` permissions.
- Losing the vault file or the master password means there is no recovery.

## Git sync

```bash
gpass git git@github.com:me/vault.git     # or run without args to be asked
```

This clones the repo and points the vault at `vault.json` inside it. An existing local
vault is copied in and pushed. After that, every command that changes the vault
(`init`, `add`, `edit`, `rm`, `passwd`) pulls first, then commits and pushes. Reads
stay local. `gpass sync` does a manual pull and push.

- Use a **private** repository. The file is encrypted, but anyone who obtains it can
  try offline guesses at the master password.
- Git keeps every past version. After `gpass passwd`, old commits can still be opened
  with the old master password.
- Pulls are fast-forward only. Two machines editing at once need a manual resolve in
  git, because the vault is a single file.
- Git credentials and commit identity come from your own git setup.

## Touch ID (macOS)

```bash
gpass touchid enable     # typed master password once, then Touch ID, then stored in Keychain
gpass touchid status
gpass touchid disable
```

Afterwards, commands show a Touch ID prompt instead of asking for the master password.
Cancelling, a failed scan, missing hardware or piped stdin falls back to the typed
password. `gpass passwd` always asks for the typed password.

Touch ID is checked by gpass itself before it reads the master password from the login
Keychain; the Keychain item is not cryptographically bound to your fingerprint. The
item is keyed by the vault's absolute path, so re-run `touchid enable` after moving a
vault or rebuilding the binary if Touch ID stops working.

## Development

```bash
go vet ./... && go test ./...
```

Tests cover the RFC 6238 TOTP vectors, vault encryption round trips, password
generation and (on macOS) the Keychain bridge.

Layout: `main.go` (CLI), `vault.go` (crypto and storage), `totp.go`, `sync.go`
(config and git), `touchid.go` and `bio_*.go/.m/.h` (biometrics and Keychain).

Note: the encryption header authenticates the original format tag `motp`, kept so
vaults created before the rename still open.
