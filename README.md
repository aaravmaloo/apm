<h1 style="text-align: center;">
  APM<br>
  <span style="font-size: 0.82em;">
    Advanced Password Manager
  </span>
</h1>

APM is a professional-grade, zero-knowledge command-line interface (CLI) for managing high-sensitivity credentials. Engineered for cryptographic performance and organizational scalability, it features a dual-engine architecture supporting both individual privacy and team-based collaboration.

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/aaravmaloo/apm/actions)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE.md)
[![Version](https://img.shields.io/badge/apm-v9.2-purple.svg)](#)
[![Commits](https://img.shields.io/github/commit-activity/m/aaravmaloo/apm)](https://github.com/aaravmaloo/apm/commits)
[![Last Commit](https://img.shields.io/github/last-commit/aaravmaloo/apm)](https://github.com/aaravmaloo/apm/commits)
[![Issues](https://img.shields.io/github/issues/aaravmaloo/apm)](https://github.com/aaravmaloo/apm/issues)
[![PRs](https://img.shields.io/github/issues-pr/aaravmaloo/apm)](https://github.com/aaravmaloo/apm/pulls)

---

## Table of Contents
- [1. Security Architecture](#1-security-architecture)
- [2. Core Technical Specifications](#2-core-technical-specifications)
- [3. Comprehensive Command Glossary](#3-comprehensive-command-glossary)
- [4. MCP Server (Model Context Protocol)](#4-mcp-server-model-context-protocol)
- [5. Team Edition (pm-team)](#5-team-edition-pm-team)
- [6. Supported Secret Types](#6-supported-secret-types)
- [7. Plugin Architecture and SDK Reference](#7-plugin-architecture-and-sdk-reference)
- [8. Policy Engine & Compliance](#8-policy-engine--compliance)
- [9. Installation and Deployment](#9-installation-and-deployment)
- [10. Contact & Support](#10-contact--support)
- [11. Development & Contributing](#11-development--contributing)
- [12. AI Usage](#12-ai-usage)

---

## 1. Security Architecture

APM uses industry-standard, high-performance cryptographic primitives designed to withstand modern attack vectors, including high-end GPU clusters and dictionary attacks.

### 1.1 Key Derivation: Argon2id
The master password is never stored. Keys are derived using **Argon2id**, the winner of the Password Hashing Competition.
- **Memory-Hard**: Resistant to GPU/ASIC cracking by requiring significant RAM (Default: 64MB, configurable up to 512MB).
- **Three-Layer Derivation**: Derives 96 bytes of key material, split into distinct 32-byte keys for Encryption, Authentication, and internal Validation.

### 1.2 Authenticated Encryption: AES-256-GCM
Confidentiality and integrity are provided by **AES-256** in **GCM (Galois/Counter Mode)**.
- **Authenticated Encryption**: GCM ensures data hasn't been modified.
- **Encrypt-then-MAC**: Extra protection with an HMAC-SHA256 signature over the entire vault file.
- **Nonce Integrity**: Every save operation generates a unique nonce to prevent replay attacks and pattern analysis.

### 1.3 Threat Model Summary
| Vector | Status | Mitigation |
|--------|--------|------------|
| Offline Brute-Force | Protected | Argon2id high-cost derivation. |
| Vault Tampering | Protected | HMAC-SHA256 integrity signature. |
| Credential Theft | Protected | Cloud tokens are encrypted inside the vault. |
| Session Hijacking| Protected | Shell-scoped sessions (`APM_SESSION_ID`) and inactivity timeouts. |
| Weak Passwords | Controlled | Enforceable password policies via YAML Policy Engine. |
| Compromised Host | Not Protected | Outside the security boundary (Keyloggers/Malware). |

## 2. Core Technical Specifications

### 2.1 Performance Profiles
Users can select from pre-defined encryption profiles via `pm profile set` to balance security and latency.

| Profile | Memory | Time | Parallelism | Nonce Size |
|---------|--------|------|-------------|------------|
| Standard | 64 MB | 3 | 2 | 12 bytes |
| Hardened | 256 MB | 5 | 4 | 12 bytes |
| Paranoid | 512 MB | 6 | 4 | 24 bytes |
| Legacy | 0 (PBKDF2) | 600k | 1 | 12 bytes |

---

## 3. Comprehensive Command Glossary

### 3.1 Personal Edition (pm)

The personal edition focuses on local-first security and privacy with native multi-cloud synchronization.

| Command | Category | Description |
|:---|:---|:---|
| `init` | Lifecycle | Initializes a new zero-knowledge encrypted vault. |
| `add` | Mutation | Interactive menu to store any of the 22 supported secret types. |
| `get [q]` | Retrieval | Fuzzy search and display entry details. Use `--show-pass` for secrets. |
| `edit [n]` | Mutation | Interactive modification of existing entry metadata. |
| `del [n]` | Mutation | Permanent deletion of an entry from the vault. |
| `gen` | Utility | High-entropy password generator. |
| `totp show`| Security | Real-time generation of 2FA codes with live countdowns. |
| `unlock` | Session | Starts a session-scoped unlock instance with inactivity timeout. |
| `lock` | Session | Immediately terminates and wipes the active session. |
| `auth` | Account | Consistently manage `email`, `reset`, `change`, and `recover`. |
| `cloud` | Sync | Google Drive & GitHub integration for cross-device syncing. |
| `space` | Org | Manage isolated compartments (e.g., Work, Personal, DevOps). |
| `mcp` | Agentic | Connect AI agents to your vault via Model Context Protocol. |
| `health` | Audit | Dashboard with security scoring and vulnerability reporting. |
| `audit` | History | Tamper-evident log of every vault interaction. |
| `import` | IO | Ingest data from external files (JSON, CSV, KDBX). |
| `export` | IO | Securely dump vault data to encrypted or plaintext formats. |
| `policy` | Compliance | Load and enforce YAML-based password requirement policies. |
| `plugins` | Extension | Extend APM via the declarative plugin SDK. |
| `info` | System | Display version, install path, and environment details. |
| `cinfo` | Crypto | Inspection of current vault cryptographic parameters. |
| `update` | System | Automated self-update engine to fetch the latest builds. |

---

## 4. MCP Server (Model Context Protocol)

APM includes a native MCP server for integration with AI assistants (Claude Desktop, Cursor, etc.). This allows AI agents to read your vault entries, search for credentials, and even retrieve TOTP codes securely if granted permission.

### 4.1 Configuration Guide

To use the APM MCP server, you must first generate a dedicated access token:

```bash
pm mcp token
```

Follow the prompts to select permissions (`read`, `secrets`, etc.). Once generated, manually add the following configuration to your MCP client.

#### For Claude Desktop
Add this to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "apm": {
      "command": "C:\\path\\to\\pm.exe",
      "args": ["mcp", "serve", "--token", "YOUR_TOKEN_HERE"]
    }
  }
}
```

#### For Cursor / Windsurf / Others
Add the following manual configuration:
```json
{
  "mcpServers": {
    "apm": {
      "command": "C:\\path\\to\\pm.exe",
      "args": ["mcp", "serve", "--token", "YOUR_TOKEN_HERE"],
      "capabilities": ["tools"],
      "env": {
        "APM_VAULT_PATH": "C:\\path\\to\\vault.dat"
      }
    }
  }
}
```

> [!IMPORTANT]
> The MCP server requires an active APM session. You MUST run `pm unlock` in your terminal before the AI agent can access the vault.

---

## 5. Team Edition (pm-team)

Designed for organizations, the Team Edition facilitates secure credential sharing via a multi-layered RBAC model.

| Command | Usage | Result |
|---------|-------|--------|
| `init` | `pm-team init "Corp"` | Sets up organization root environment. |
| `dept` | `pm-team dept create Engineering`| Creates a new isolated encryption domain. |
| `user` | `pm-team user add alice` | Onboards a new member with specific roles. |
| `approvals` | `pm-team approvals list` | Manage pending sensitive entry requests. |

---

## 6. Supported Secret Types

APM supports 22 distinct data structures:
1. **Passwords** | 2. **TOTP** | 3. **Gov IDs** | 4. **Medical** | 5. **Travel** | 6. **Contacts** | 7. **Wi-Fi** | 8. **API Keys** | 9. **Tokens** | 10. **SSH Keys** | 11. **SSH Configs** | 12. **Cloud Creds** | 13. **K8s** | 14. **Docker** | 15. **CI/CD** | 16. **Notes** | 17. **Recovery** | 18. **Certs** | 19. **Banking** | 20. **Docs** | 21. **Software Licenses** | 22. **Legal**

---

## 7. Plugin Architecture and SDK Reference

APM features a declarative, JSON-driven plugin architecture.
- **Hook Execution**: Plugins can intercept standard events (e.g., `pre:add`) or register commands.
- **Capabilities**: Explicitly defined permissions: `vault.read`, `vault.write`, `system.write`, `network.outbound`, `cloud.sync`.

---

## 8. Policy Engine & Compliance

APM enforces security standards through a flexible, YAML-based policy engine.
- **Password Complexity**: Validated during `pm add`.
- **Rotation**: Tracked via `pm health`.

---

## 9. Installation and Deployment

### 9.1 Build from Source
```bash
git clone https://github.com/aaravmaloo/apm.git
cd apm
go build -o pm.exe main.go
./pm.exe init
```

### 9.2 Build Requirements
- Go 1.21+
- Windows, macOS, or Linux

---

## 10. Contact & Support
- **Primary Maintainer**: Aarav Maloo
- **Security Alerts**: aaravmaloo06@gmail.com
- **GitHub Issues**: aaravmaloo/apm/issues

---

## 11. Development & Contributing
APM is open-source. All PRs must pass the test suite in `/tests`.

---

## 12. AI Usage

The code written for APM is completely hand-written by me. Some exceptions include the `examples/` folder, which was generated by AI; keep in mind that the plugins parser was completely human-written. AI was used to refactor the code for better naming schemes and readability. Each change made by the AI is monitored. 

I acknowledge that AI is a great tool for productivity and I am not against it; however, I feel AI is not perfect at security, nor is a human. Though a human is much preferred for security tools. Hence, I write code by myself, which makes development slower but keeps APM secure.

Copyright (c) 2025-2026 Aarav Maloo. Licensed under the MIT License.