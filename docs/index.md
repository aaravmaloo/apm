# APM

APM is a zero-knowledge, Go-based password manager with multi-type secret storage, cloud sync, TOTP, autofill, and MCP tooling.

## Highlights

- Argon2id + AES-GCM encrypted vault
- 20+ entry types (passwords, notes, tokens, media, TOTP, infra secrets)
- Space-based organization
- `.apmignore` filtering for cloud uploads
- Background Windows autofill daemon with `CTRL+SHIFT+L`
- Personal notes vocabulary + autocomplete indexing
- Legacy `plugin.json` plugin model with runtime permission controls
- MCP integration for assistant workflows

## Quick start

```console
$ git clone https://github.com/aaravmaloo/apm.git
$ cd apm
$ go build -o pm.exe main.go
$ pm setup
$ pm unlock
$ pm add
$ pm get
```

## Core workflows

### Vault usage

- `pm add` adds entries
- `pm get [query]` searches entries and supports quicklook for notes/photos
- `pm get --show-pass` reveals sensitive values (otherwise hidden)

### TOTP usage

- `pm totp` shows all TOTP codes in an interactive list
- `pm totp <entry_name>` copies the matching code directly
- `Shift+Up/Down` reorders TOTP entries by usage priority

### Notes autocomplete and vocab

- `pm auth autocomplete true|false`
- `pm vocab`
- `pm vocab alias`
- `pm vocab rank <word> <delta>`

### Autofill on Windows

- `pm autofill start`
- `pm unlock` (also unlocks daemon vault state)
- `pm lock` (also locks daemon)
- `pm autocomplete link-totp`

See [Autofill Windows](./autofill_windows.md).

## Documentation map

- [Getting started](./getting-started/index.md)
- [Guides](./guides/index.md)
- [Concepts](./concepts/index.md)
- [Reference](./reference/index.md)
- [Team docs](./team/index.md)
