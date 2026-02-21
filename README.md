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
[![Current Preview](https://img.shields.io/badge/apm-canary-yellow.svg)](https://github.com/aaravmaloo/apm/releases/latest)

---

## Table of Contents
- [Table of Contents](#table-of-contents)
- [1. Security Architecture](#1-security-architecture)
  - [1.1 Key Derivation: Argon2id](#11-key-derivation-argon2id)
  - [1.2 Authenticated Encryption: AES-256-GCM](#12-authenticated-encryption-aes-256-gcm)
  - [1.3 Secure Recovery \& Identity Verification](#13-secure-recovery--identity-verification)
  - [1.4 Threat Model Summary](#14-threat-model-summary)
- [2. Core Technical Specifications](#2-core-technical-specifications)
  - [2.1 Performance Profiles](#21-performance-profiles)
- [3. Comprehensive Command Glossary](#3-comprehensive-command-glossary)
  - [3.1 Personal Edition (pm)](#31-personal-edition-pm)
- [4. MCP Server (Model Context Protocol)](#4-mcp-server-model-context-protocol)
  - [4.1 Configuration Guide](#41-configuration-guide)
    - [For Claude Desktop](#for-claude-desktop)
    - [For Cursor / Windsurf / Others](#for-cursor--windsurf--others)
- [5. Team Edition (pm-team)](#5-team-edition-pm-team)
- [6. Supported Secret Types](#6-supported-secret-types)
- [7. Plugin Architecture and SDK Reference](#7-plugin-architecture-and-sdk-reference)
- [8. Policy Engine \& Compliance](#8-policy-engine--compliance)
- [9. Installation and Deployment](#9-installation-and-deployment)
  - [9.1 Build from Source](#91-build-from-source)
  - [9.2 Build Requirements](#92-build-requirements)
- [10. Contact \& Support](#10-contact--support)
- [11. Development \& Contributing](#11-development--contributing)
- [12. Cloud Synchronization Matrix](#12-cloud-synchronization-matrix)
  - [12.1 Cloud Initialization](#121-cloud-initialization)
- [13. AI Usage](#13-ai-usage)

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
- **Double-Layer Integrity**: Extra protection with an HMAC-SHA256 signature over the entire vault file, derived from the master password.
- **Vault V4 Format**: Includes an unencrypted (but signed) metadata header for identity verification and recovery coordination.
- **Nonce Integrity**: Every save operation generates a unique nonce to prevent replay attacks and pattern analysis.

### 1.3 Secure Recovery & Identity Verification
APM features a robust recovery engine designed for zero-knowledge environments.
- **Secure Tokens**: 32-byte cryptographically secure hex tokens for identity verification.
- **Hashed Validation**: Tokens are stored only in hashed form (SHA-256) with strict 15-minute expirations.
- **Recovery Key Obfuscation**: XOR-obfuscation for recovery keys stored in the vault, preventing simple memory dumps from exposing them.
- **DEK Unlocking**: Successful identity verification and recovery key entry unlocks the Data Encryption Key (DEK), allowing master password resets without data loss.

### 1.4 Threat Model Summary
| Vector              | Status        | Mitigation                                                        |
| ------------------- | ------------- | ----------------------------------------------------------------- |
| Offline Brute-Force | Protected     | Argon2id high-cost derivation.                                    |
| Vault Tampering     | Protected     | HMAC-SHA256 integrity signature across all metadata.              |
| Credential Theft    | Protected     | Cloud tokens are encrypted inside the vault.                      |
| Identity Spoofing   | Protected     | Multi-factor recovery (Email -> Secure Token -> Recovery Key).    |
| Session Hijacking   | Protected     | Shell-scoped sessions (`APM_SESSION_ID`) and inactivity timeouts. |
| Weak Passwords      | Controlled    | Enforceable password policies via YAML Policy Engine.             |
| Compromised Host    | Not Protected | Outside the security boundary (Keyloggers/Malware).               |

## 2. Core Technical Specifications

### 2.1 Performance Profiles
Users can select from pre-defined encryption profiles via `pm profile set` to balance security and latency.

| Profile  | Memory     | Time | Parallelism | Nonce Size |
| -------- | ---------- | ---- | ----------- | ---------- |
| Standard | 64 MB      | 3    | 2           | 12 bytes   |
| Hardened | 256 MB     | 5    | 4           | 12 bytes   |
| Paranoid | 512 MB     | 6    | 4           | 24 bytes   |
| Legacy   | 0 (PBKDF2) | 600k | 1           | 12 bytes   |

---

## 3. Comprehensive Command Glossary

### 3.1 Personal Edition (pm)

The personal edition focuses on local-first security and privacy with native multi-cloud synchronization.

| Command     | Category   | Description                                                            |
| :---------- | :--------- | :--------------------------------------------------------------------- |
| `init`      | Lifecycle  | Initializes a new zero-knowledge encrypted vault.                      |
| `add`       | Mutation   | Interactive menu to store any of the 22 supported secret types.        |
| `get [q]`   | Retrieval  | Fuzzy search and display entry details. Use `--show-pass` for secrets. |
| `edit [n]`  | Mutation   | Interactive modification of existing entry metadata.                   |
| `del [n]`   | Mutation   | Permanent deletion of an entry from the vault.                         |
| `gen`       | Utility    | High-entropy password generator.                                       |
| `totp show` | Security   | Real-time generation of 2FA codes with live countdowns.                |
| `unlock`    | Session    | Starts a session-scoped unlock instance with inactivity timeout.       |
| `lock`      | Session    | Immediately terminates and wipes the active session.                   |
| `auth`      | Account    | Consistently manage `email`, `reset`, `change`, and `recover`.         |
| `cloud`     | Sync       | Google Drive, GitHub, & Dropbox integration for cross-device syncing.  |
| `space`     | Org        | Manage isolated compartments (e.g., Work, Personal, DevOps).           |
| `mcp`       | Agentic    | Connect AI agents to your vault via Model Context Protocol.            |
| `health`    | Audit      | Dashboard with security scoring and vulnerability reporting.           |
| `audit`     | History    | Tamper-evident log of every vault interaction.                         |
| `import`    | IO         | Ingest data from external files (JSON, CSV, KDBX).                     |
| `export`    | IO         | Securely dump vault data to encrypted or plaintext formats.            |
| `policy`    | Compliance | Load and enforce YAML-based password requirement policies.             |
| `plugins`   | Extension  | Extend APM via the declarative plugin SDK.                             |
| `info`      | System     | Display version, install path, and environment details.                |
| `cinfo`     | Crypto     | Inspection of current vault cryptographic parameters.                  |
| `update`    | System     | Automated self-update engine to fetch the latest builds.               |

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

| Command     | Usage                             | Result                                     |
| ----------- | --------------------------------- | ------------------------------------------ |
| `init`      | `pm-team init "Corp"`             | Sets up organization root environment.     |
| `dept`      | `pm-team dept create Engineering` | Creates a new isolated encryption domain.  |
| `user`      | `pm-team user add alice`          | Onboards a new member with specific roles. |
| `approvals` | `pm-team approvals list`          | Manage pending sensitive entry requests.   |

---

## 6. Supported Secret Types

APM supports 22 distinct data structures:
1. **Passwords** | 2. **TOTP** | 3. **Gov IDs** | 4. **Medical** | 5. **Travel** | 6. **Contacts** | 7. **Wi-Fi** | 8. **API Keys** | 9. **Tokens** | 10. **SSH Keys** | 11. **SSH Configs** | 12. **Cloud Creds** | 13. **K8s** | 14. **Docker** | 15. **CI/CD** | 16. **Notes** | 17. **Recovery** | 18. **Certs** | 19. **Banking** | 20. **Docs** | 21. **Software Licenses** | 22. **Legal**

---

## 7. Plugin Architecture and SDK Reference

APM features a declarative, JSON-driven plugin architecture.
- **Hook Execution**: Plugins can intercept standard events (e.g., `pre:add`) or register commands.
- **Capabilities**: Over 150 granular permissions including vault access (`vault.item.*`), network protocols (`network.ssh`, `network.http`), system integration (`system.exec`, `system.env`), and UI control (`ui.prompt`, `ui.window`).
- **Wildcards**: Supports hierarchical permission matching (e.g., `vault.*` grants all vault-related access).

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

## 12. Cloud Synchronization Matrix

APM provides native support for multiple cloud storage providers to ensure your vault is available across all your trusted devices.

| Feature             | Google Drive (GDrive)      | GitHub (GH)                 | Dropbox (DBX)              |
| :------------------ | :------------------------- | :-------------------------- | :------------------------- |
| **Authentication**  | OAuth2 (PKCE)              | Personal Access Token       | OAuth2 (PKCE)              |
| **Storage Type**    | Application Data Folder    | Private Repository          | Application Folder         |
| **Setup Speed**     | Instant (APM_PUBLIC)       | Manual (Token required)     | Instant (APM_PUBLIC)       |
| **Privacy Level**   | High (Isolated from files) | Exceptional (Git History)   | High (Isolated from files) |
| **Version History** | Limited (Drive native)     | Comprehensive (Git Commits) | Limited (Dropbox native)   |
| **Recommended For** | Mobile users & Fast sync   | Developers & Power users    | Cross-platform persistence |

### 12.1 Cloud Initialization
To set up synchronization, use the following commands:
- `pm cloud init gdrive`: Setup Google Drive sync.
- `pm cloud init github`: Setup GitHub sync (requires token and repo).
- `pm cloud init dropbox`: Setup Dropbox sync.
- `pm cloud init all`: Initialize all supported providers simultaneously.

---

## 13. AI Usage

The code written for APM is completely hand-written by me. Some exceptions include the `examples/` folder, which was generated by AI; keep in mind that the plugins parser was completely human-written. AI was used to refactor the code for better naming schemes and readability. Each change made by the AI is monitored. 

I acknowledge that AI is a great tool for productivity and I am not against it; however, I feel AI is not perfect at security, nor is a human. Though a human is much preferred for security tools. Hence, I write code by myself, which makes development slower but keeps APM secure. Due to this reason APM releases take upto a month. 
Releases also may take around two to three weeks when minor changes are made and when bugs are to be fixed. 

Copyright (c) 2025-2026 Aarav Maloo. Licensed under the MIT License.