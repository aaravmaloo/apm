# APM Documentation

APM is a zero-knowledge, Go-based CLI password manager with multi-type secret storage, cloud sync, TOTP, system autofill, notes vocabulary, plugins, and MCP tooling. This page is the comprehensive reference and user guide for the entire system. It covers how to install, how to operate the CLI day-to-day, and how the internals behave so you can make safe operational decisions.

## What APM is

APM is a local-first vault with encrypted-at-rest storage and explicit session-based unlock behavior. You do not “stay logged in” in the background. You open a session, perform work, and lock the vault. Optional features like autofill or MCP integrate with that session boundary rather than bypassing it.

The platform has three major user personas:

- Personal users who want a secure CLI vault with automation and notes.
- Power users who want cloud sync, plugins, and policy enforcement.
- Developers who want to integrate APM into tooling via MCP or plugins.

## One-line install

macOS and Linux:

```console
curl -sSL https://raw.githubusercontent.com/aaravmaloo/apm/master/scripts/install.sh | bash
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -Command "iwr https://raw.githubusercontent.com/aaravmaloo/apm/master/scripts/install.ps1 -UseBasicParsing | iex"
```

## Quickstart

1. Initialize a vault with `pm init` and set a strong master password.
2. Unlock the vault with `pm unlock` and confirm you are in an active session.
3. Add entries with `pm add` and find them with `pm get`.
4. Lock the vault with `pm lock` when you are done.
5. If you are on Windows, start the autofill daemon with `pm autofill start` and use `CTRL+SHIFT+L` in login contexts.
6. If you use cloud sync, configure with `pm cloud init` and run `pm cloud sync`.

## Vault lifecycle and sessions

APM uses explicit sessions to gate access to decrypted data. This is a security boundary and also a mental model:

- The vault is encrypted at rest on disk.
- `pm unlock` decrypts it in memory and starts a session.
- All sensitive commands require an active session.
- `pm lock` ends the session and wipes in-memory secrets.
- Session timeouts and inactivity timeouts auto-lock to reduce exposure.

This model also applies to the autofill daemon and MCP server. They do not operate unless the vault is unlocked or unless you provide a delegated session token.
## Entry model and secret types

APM supports a broad range of entry types so that you can keep sensitive data in one encrypted vault. Common categories include passwords, TOTP secrets, secure notes, tokens, API keys, SSH keys, Wi-Fi credentials, certificates, recovery codes, and documents. Each entry type has a structured schema and validated fields rather than untyped blobs, which allows APM to provide safer UI workflows and stronger automation.

The `pm add` command walks you through the available entry types. `pm get` is a fuzzy search interface with quicklook for notes and photos, and a safe-by-default display mode that hides sensitive values unless explicitly requested.

## Notes and vocabulary

Secure notes in APM are not just text blobs. When vocabulary indexing is enabled, APM builds a compressed vocabulary from notes and uses it to offer autocomplete suggestions, alias normalization, and ranking. This makes note writing faster and more consistent over time.

Key commands:

- `pm vocab enable|disable|status` controls whether vocabulary indexing is active.
- `pm vocab` lists words and alias state.
- `pm vocab alias` creates or updates an alias so terms normalize during writing.
- `pm vocab rank` adjusts ranking to promote frequently used terms.
- `pm vocab reindex` rebuilds the vocabulary from current notes.

The vocabulary is stored inside the encrypted vault in a compressed form. You can strip it from cloud uploads with `.apmignore` if you want to reduce metadata exposure.

## Spaces

Spaces provide a lightweight organization layer so you can separate Work, Personal, or Project-specific entries. Commands such as `pm space create`, `pm space list`, and `pm space switch` let you segment vault content without splitting into multiple vault files. `.apmignore` can filter whole spaces during cloud sync.
## TOTP and OTP linking

APM supports time-based one-time passwords for 2FA.

- `pm totp` opens an interactive list with copy and ordering controls.
- `pm totp <entry>` copies a specific code directly.

Autofill-aware OTP flows are supported by linking a TOTP entry to a domain. Use `pm autocomplete link-totp` so the autofill engine can select the correct OTP for a website or desktop app.

## Autofill daemon on Windows

APM autofill is implemented as a local Windows daemon. It runs without a browser extension and listens for a global hotkey, defaulting to `CTRL+SHIFT+L`.

Core behaviors:

- The daemon watches active window context and detects credential-like forms.
- It surfaces transient popup hints indicating a possible match or a detection event.
- When the hotkey is pressed, it resolves the best match and injects keystrokes.
- It never uses the clipboard for core typing flows.
- It rejects requests if the vault is locked.

Daemon control:

- `pm autofill start|stop|status|list-profiles` manages the daemon.
- `pm autocomplete enable` registers autostart on login and starts the daemon.
- `pm autocomplete start|stop` handles manual lifecycle control.
- `pm autocomplete window enable|disable|status` toggles popup hints.

The daemon uses loopback IPC and bearer-token state to keep local communications protected.
## Cloud sync

APM syncs encrypted vault blobs to supported providers. Your master password never leaves the machine, and the providers never see plaintext. The upload is an encrypted file, optionally filtered via `.apmignore`.

Typical flow:

1. `pm cloud init` to configure provider credentials.
2. `pm cloud sync` to upload or download as needed.
3. `pm cloud autosync` to run periodic sync loops.

### .apmignore

`.apmignore` is read before upload and can remove entries from the payload. It supports:

- Space-level ignores.
- Entry-level ignores with `space:type:name` patterns.
- Provider-specific ignores using `provider:space:type:name`.
- Vocabulary stripping with `ignore:vocab`.

This lets you maintain local-only data while still using cloud backups for the rest of your vault.
## Auth and recovery

APM recovery is designed for zero-knowledge environments. A recovery flow can verify identity without exposing secret data to a server.

Key elements:

- Email verification tokens are time-limited and stored hashed.
- A recovery key gates access to the Data Encryption Key (DEK).
- Optional recovery factors such as passkeys or recovery codes add safety.
- A recovery attempt re-encrypts the vault with a new master password.

If you do not configure a recovery key, losing the master password means the vault cannot be recovered. This is an intentional property of the zero-knowledge design.
## Plugins and PACs

APM plugins are manifest-based (`plugin.json`). Each plugin declares required permissions and commands it exposes. Runtime permission overrides are enforced by the engine and stored in the vault so policy travels with your data.

Relevant commands:

- `pm plugins market`, `pm plugins install`, `pm plugins installed`
- `pm plugins access` to view permissions
- `pm plugins access <plugin> <permission> on|off` to toggle overrides

Treat plugins as executable code. The permission model is designed to reduce blast radius if a plugin should not access certain capabilities.

## MCP server

APM exposes a Model Context Protocol server for AI assistants and automation. MCP access is token-scoped and permissioned, and it requires an active session.

- `pm mcp token` creates a token with specified permissions.
- `pm mcp serve` starts the server.
- `pm mcp config` helps with client configuration.

Write tools use transaction guardrails, requiring explicit commit steps for modifications.

## Policies

Policies are YAML files that enforce password complexity and compliance requirements. They are loaded with `pm policy load` and applied at entry creation time.
## Where to look next

- Getting Started for install and first workflows.
- Guides for cloud sync, sessions, plugins, and MCP.
- Concepts for architecture, encryption, recovery, and vault format.
- Reference for exact CLI command definitions.
- Plugin API for developer reference.
