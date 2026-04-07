# APM

APM is a local-first password manager written in Go. The primary binary, `pm`, manages an encrypted personal vault with sessions, recovery, cloud sync, plugins, MCP access for AI tools, Windows autofill, shell injection, and an optional TUI. The repo also contains a separate `pm-team` binary for shared organizational vaults.

## What exists in this repo

- A versioned vault format (`APMVAULT`, current format v4) with profile-based encryption settings.
- 25 personal secret types, including passwords, TOTP, notes, API keys, SSH material, cloud credentials, documents, recovery codes, media, and legal or financial records.
- Session-based unlock with inactivity timeouts and delegated ephemeral sessions.
- Recovery setup with verified email, a recovery key, optional passkeys, one-time recovery codes, and trustee quorum shares.
- Cloud sync for Google Drive, GitHub, and Dropbox.
- A manifest-based plugin system with hooks, permissions, marketplace commands, and runtime-added commands.
- A built-in MCP server with permission-scoped tokens and transaction previews for mutations.
- Windows autofill and autocomplete tooling, plus `pm inject` for environment-variable injection.
- A separate team edition under [`team/`](team) with departments, RBAC, approvals, and shared entry types.

## Main CLI surface

Top-level `pm` commands from the current codebase include:

`add`, `get`, `gen`, `setup`, `unlock`, `lock`, `readonly`, `mode`, `session`, `profile`, `space`, `policy`, `cloud`, `plugins`, `mcp`, `auth`, `totp`, `vocab`, `autocomplete`, `autofill`, `inject`, `health`, `trust`, `audit`, `cinfo`, `info`, `loaded`, `update`, `brutetest`, `tui`, `compromise`

Plugin manifests can also register additional root-level commands at runtime.

## Personal secret types

The current `pm add` flow supports 25 entry types:

1. Password
2. TOTP
3. Token
4. Secure note
5. API key
6. SSH key
7. Wi-Fi
8. Recovery codes
9. Certificate
10. Banking item
11. Document
12. Government ID
13. Medical record
14. Travel document
15. Contact
16. Cloud credential
17. Kubernetes secret
18. Docker registry
19. SSH config
20. CI/CD secret
21. Software license
22. Legal contract
23. Audio
24. Video
25. Photo

## Quick start

```bash
go build -o pm .
pm setup
pm unlock
pm add
pm get github
pm lock
```

To build the team edition:

```bash
cd team
go build -o pm-team .
```

## Security model summary

- Personal vaults use profile metadata plus authenticated encryption and integrity checks.
- Built-in profiles are `standard`, `hardened`, `paranoid`, and `legacy`.
- The current code supports both `aes-gcm` and `xchacha20-poly1305`.
- Normal unlock sessions are encrypted on disk; delegated ephemeral sessions are stored separately for short-lived agent or automation use.
- Recovery metadata is stored in the v4 vault header so recovery checks can run before the main vault body is decrypted.

## Docs

The MkDocs site lives in [`docs/`](docs). Start with:

- [`docs/index.md`](docs/index.md)
- [`docs/getting-started/first-steps.md`](docs/getting-started/first-steps.md)
- [`docs/reference/cli.md`](docs/reference/cli.md)
- [`docs/concepts/recovery.md`](docs/concepts/recovery.md)

## Development notes

- Root module: Go CLI for `pm`
- Team module: separate Go module in [`team/`](team)
- Install scripts: [`scripts/install.sh`](scripts/install.sh), [`scripts/install.ps1`](scripts/install.ps1)
- Example plugins: [`examples/plugins/`](examples/plugins)

## License

## 14. Version System For Contributors
(from pre-dev to release stages) (with examples)
the stages correspond to the ultimate release.
Suppose releasing a v8 of an app.
All releases except stable release are released in builds/ folder.
Canary --> can-8 
Beta --> beta-8 
Pre-release --> pre-8 
Release --> v8
