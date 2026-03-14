# APM Documentation

**APM** (Advanced Password Manager) is a professional-grade, zero-knowledge command-line password manager built in Go. It provides encrypted-at-rest vault storage, multi-cloud synchronization, AI-agent integration via MCP, a Windows autofill daemon, a manifest-based plugin system, and organizational team support — all driven from a single CLI binary.

---

## Why APM?

- **Zero-Knowledge Architecture** — Your master password never leaves your machine. The vault is encrypted with Argon2id + AES-256-GCM and protected by HMAC-SHA256 integrity signatures.
- **25+ Secret Types** — Passwords, TOTP, API keys, SSH keys, certificates, banking, medical records, legal contracts, documents with file attachments, and more — each with a structured schema.
- **Multi-Cloud Sync** — Native support for Google Drive, GitHub, and Dropbox. Your vault is uploaded as an encrypted blob; providers never see plaintext.
- **AI-Agent Integration** — Built-in MCP (Model Context Protocol) server lets AI assistants like Claude, Cursor, and Windsurf read and manage vault entries with permission-scoped, token-based access.
- **Windows Autofill** — A local daemon that detects credential forms and injects keystrokes via hotkey — no browser extension required.
- **Face ID Unlock (Optional)** — Biometric unlock powered by local face recognition. Available when built with the `faceid` build tag.
- **Plugin Ecosystem** — Manifest-based plugins with 100+ granular permissions, a marketplace, and hook-based lifecycle integration.
- **Team Edition** — Multi-user credential sharing with RBAC, departments, and approval workflows.

---

## Quick Install

=== "macOS / Linux"

    ```bash
    curl -sSL https://raw.githubusercontent.com/aaravmaloo/apm/master/scripts/install.sh | bash
    ```

=== "Windows PowerShell"

    ```powershell
    Set-ExecutionPolicy Bypass -Scope Process -Force
    iwr https://raw.githubusercontent.com/aaravmaloo/apm/master/scripts/install.ps1 -UseBasicParsing | iex
    ```

=== "Build from Source"

    ```bash
    git clone https://github.com/aaravmaloo/apm.git
    cd apm
    go build -o pm main.go
    ```

For full installation details, see [Installation](getting-started/installation.md).

---

## Quickstart

```bash
# 1. Initialize a new vault (choose a security profile)
pm init

# 2. Unlock the vault to start a session
pm unlock

# 3. Add your first entry
pm add

# 4. Search and retrieve entries
pm get github

# 5. Generate a strong password
pm gen

# 6. Lock when done
pm lock
```

For a detailed walkthrough, see [First Steps](getting-started/first-steps.md).

---

## How the Documentation Is Organized

### [Getting Started](getting-started/index.md)

Installation, first steps, and a feature overview to get productive quickly.

### [Guides](guides/index.md)

Practical how-to guides for day-to-day tasks:

- [Managing your vault](guides/vault-management.md) — Adding, searching, editing, and organizing entries
- [Cloud synchronization](guides/cloud-sync.md) — Setting up GDrive, GitHub, and Dropbox sync
- [Using .apmignore](guides/apmignore.md) — Controlling what gets uploaded to cloud providers
- [Autofill on Windows](autofill_windows.md) — The autofill daemon and hotkey injection
- [Generating TOTP codes](guides/totp.md) — 2FA management and autofill linking
- [Managing sessions](guides/sessions.md) — Unlock, lock, ephemeral sessions, and delegation
- [Using plugins](guides/plugins.md) — Installing, managing, and creating plugins
- [MCP integration](guides/mcp-integration.md) — Connecting AI assistants to your vault
- [Team edition](guides/team-edition.md) — Organizational credential sharing
- [Importing and exporting](guides/import-export.md) — JSON, CSV, and TXT import/export

### [Concepts](concepts/index.md)

Deep technical explanations of how APM works:

- [Architecture](concepts/architecture.md) — The four-layer design
- [Encryption](concepts/encryption.md) — Argon2id, AES-256-GCM, HMAC-SHA256
- [Vault format](concepts/vault-format.md) — The V4 binary format specification
- [Secret types](concepts/secret-types.md) — All 25+ structured entry types
- [Security profiles](concepts/security-profiles.md) — Standard, Hardened, Paranoid, Legacy
- [Policy engine](concepts/policy-engine.md) — YAML-based password and rotation policies
- [Sessions](concepts/sessions.md) — Shell-scoped and ephemeral delegated sessions
- [Cloud synchronization](concepts/cloud-sync.md) — Provider comparison and sync mechanics
- [Plugins](concepts/plugins.md) — Plugin architecture and permission model
- [MCP server](concepts/mcp.md) — Model Context Protocol server internals
- [Recovery](concepts/recovery.md) — Multi-factor recovery, quorum shares, passkeys

### [Reference](reference/index.md)

Precise technical specifications:

- [CLI reference](reference/cli.md) — Every command, subcommand, and flag
- [.apmignore reference](reference/apmignore.md) — Format specification
- [Storage reference](reference/storage.md) — File locations and data layout
- [Environment variables](reference/environment-variables.md) — All supported env vars
- [Plugin API](reference/plugin-api.md) — Manifest schema and permissions catalog
- [MCP tools](reference/mcp-tools.md) — Tool schemas and permission requirements
- [Policies](reference/policies.md) — YAML policy schema and examples

### [Team](team/index.md)

Team edition documentation for organizational deployments:

- [RBAC and roles](team/rbac.md)
- [Departments](team/departments.md)
- [Approval workflows](team/approvals.md)

---

## Threat Model

| Vector              | Status        | Mitigation                                                               |
| :------------------ | :------------ | :----------------------------------------------------------------------- |
| Offline Brute-Force | Protected     | Argon2id high-cost derivation (up to 512 MB, 6 iterations)               |
| Vault Tampering     | Protected     | HMAC-SHA256 integrity signature across all metadata                      |
| Credential Theft    | Protected     | Cloud tokens are encrypted inside the vault                              |
| Identity Spoofing   | Protected     | Multi-factor recovery (Email → Recovery Key → OTP → Optional 2nd factor) |
| Session Hijacking   | Protected     | Shell-scoped sessions (`APM_SESSION_ID`) and inactivity timeouts         |
| Weak Passwords      | Controlled    | Enforceable password policies via YAML Policy Engine                     |
| Compromised Host    | Not Protected | Outside security boundary (keyloggers, malware)                          |

---

## Contact & Support

- **Primary Maintainer**: Aarav Maloo
- **Security Alerts**: aaravmaloo06@gmail.com
- **GitHub Issues**: [aaravmaloo/apm/issues](https://github.com/aaravmaloo/apm/issues)

---

*APM is open-source software licensed under the [MIT License](https://github.com/aaravmaloo/apm/blob/master/LICENSE). Copyright © 2025–2026 Aarav Maloo.*
