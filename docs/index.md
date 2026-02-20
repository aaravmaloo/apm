# APM

A professional-grade, zero-knowledge command-line password manager, written in Go.

## Highlights

- A single tool to manage passwords, API keys, SSH keys, TOTP codes, certificates, and
  [20+ other secret types](./concepts/secret-types.md).
- **Zero-knowledge encryption** with [Argon2id](./concepts/encryption.md) key derivation and
  [AES-256-GCM](./concepts/encryption.md) authenticated encryption.
- Native [cloud synchronization](./guides/cloud-sync.md) across Google Drive, GitHub, and Dropbox.
- Built-in [MCP server](./guides/mcp-integration.md) for AI assistant integration (Claude, Cursor,
  etc.).
- Extensible via a declarative [plugin architecture](./concepts/plugins.md) with 150+ granular
  permissions.
- [Team edition](./team/index.md) with RBAC, departments, and approval workflows.
- [TOTP generation](./guides/totp.md) with real-time countdowns directly in the terminal.
- YAML-based [policy engine](./concepts/policy-engine.md) for organizational compliance.
- Configurable [security profiles](./concepts/security-profiles.md) from Standard to Paranoid.
- Supports Windows, macOS, and Linux.

APM is created and maintained by [Aarav Maloo](https://github.com/aaravmaloo).

## Installation

Install APM by building from source:

```console
$ git clone https://github.com/aaravmaloo/apm.git
$ cd apm
$ go build -o pm.exe main.go
```

Then, check out the [first steps](./getting-started/first-steps.md) or read on for a brief overview.

!!! tip

    See all available installation methods on the
    [installation page](./getting-started/installation.md).

## Vault Management

APM manages an encrypted vault of credentials with support for 22 secret types, fuzzy search, and
interactive editing:

```console
$ pm init
Vault initialized successfully at ~/.apm/vault.dat

$ pm add
? Select category: Password
? Account name: GitHub
? Username: aarav@example.com
? Password: ********
Entry added successfully.

$ pm get github
+----------+----------------------+
| Account  | GitHub               |
| Username | aarav@example.com    |
| Category | Password             |
+----------+----------------------+
```

See the [vault management guide](./guides/vault-management.md) to get started.

## Cloud Synchronization

APM provides native multi-cloud synchronization to keep your vault available across all your
trusted devices:

```console
$ pm cloud init gdrive
Launching browser for Google OAuth...
Google Drive sync initialized successfully.

$ pm cloud push
Vault uploaded to Google Drive.

$ pm cloud pull
Vault downloaded and merged.
```

See the [cloud sync guide](./guides/cloud-sync.md) to get started.

## TOTP Codes

APM generates time-based one-time passwords with live countdowns:

```console
$ pm totp show
? Select entry: GitHub

  Code: 482 913
  Expires in: 18s [==================------]
```

See the [TOTP guide](./guides/totp.md) to get started.

## Sessions

APM uses shell-scoped sessions with inactivity timeouts:

```console
$ pm unlock
Master password: ********
Session started (timeout: 1 hour).

$ pm lock
Session terminated. Memory wiped.
```

See the [sessions guide](./guides/sessions.md) to get started.

## MCP Server

APM includes a native MCP server for integration with AI assistants:

```console
$ pm mcp token
? Select permissions: read, secrets, totp
Token generated: POXXXXXX...

$ pm mcp serve --token POXXXXXX...
MCP server listening on stdio...
```

See the [MCP integration guide](./guides/mcp-integration.md) to get started.

## The Team Interface

APM provides a dedicated team edition for organizations, with RBAC, departments, and
approval workflows:

```console
$ pm-team init "Acme Corp"
Organization initialized.

$ pm-team dept create Engineering
Department created with isolated encryption domain.

$ pm-team user add alice --role admin
User onboarded successfully.
```

See the [team edition documentation](./team/index.md) to get started.

## Learn more

See the [first steps](./getting-started/first-steps.md) or jump straight to the
[guides](./guides/index.md) to start using APM.
