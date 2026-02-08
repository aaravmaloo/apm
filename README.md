<h1 style="text-align: center;">
  APM<br>
  <span style="font-size: 0.82em;">
    Advanced Password Manager
  </span>
</h1>

APM is a professional-grade, zero-knowledge command-line interface (CLI) for managing high-sensitivity credentials. Engineered for cryptographic performance and organizational scalability, it features a dual-engine architecture supporting both individual privacy and team-based collaboration.

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/aaravmaloo/apm/actions)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE.md)
[![Version](https://img.shields.io/badge/apm-v9.5-purple.svg)](#)

---

## 1. Security & Compliance Matrix

APM utilizes a defense-in-depth approach to secret management.

| Feature                   | Specification                 | Security Benefit                                    |
| :------------------------ | :---------------------------- | :-------------------------------------------------- |
| **Key Derivation**        | Argon2id (64MB-512MB)         | Defeats GPU/ASIC brute-force attacks.               |
| **Encryption**            | AES-256-GCM (Authenticated)   | Ensures confidentiality and tamper-detection.       |
| **Identity Verification** | Secure Tokens + Recovery Keys | Zero-knowledge recovery path without vendor access. |
| **Paranoia Levels**       | Levels 1-3 (Configurable)     | Tunable security posture (Standard to Paranoid).    |
| **Integrity Checks**      | HMAC-SHA256 (File-level)      | Detects unauthorized offline modifications.         |
| **Audit Logging**         | Tamper-evident Local Logs     | Immutable record of all cryptographic operations.   |

---

## 2. Cryptographic Profiles

| Profile      | Memory | Time | Parallel | Security Posture                        |
| :----------- | :----- | :--- | :------- | :-------------------------------------- |
| **Standard** | 64 MB  | 3    | 2        | Default protection for daily use.       |
| **Hardened** | 256 MB | 5    | 4        | Enhanced resistance for high-risk data. |
| **Paranoid** | 512 MB | 6    | 4        | Maximum protection (Slower unlock).     |

---

## 3. Security Alert Levels

APM monitors vault activity and sends email alerts based on the configured security level (`pm auth level`).

| Level | Name         | Description                         | Triggers                                                           |
| :---- | :----------- | :---------------------------------- | :----------------------------------------------------------------- |
| **1** | **Critical** | Minimal noise, maximum importance.  | Failed Unlocks, Breaches, Vault Recovery                           |
| **2** | **Settings** | Audit configuration changes.        | Level 1 + Password Change, Alert Toggle, Level Change, Email Reset |
| **3** | **Paranoid** | Full transparency for every action. | Level 2 + Entry Add/Edit/Delete, Data Export                       |

---

## 3. Command Reference

### 3.1 Authentication & Recovery
Commands under `pm auth` manage your identity and emergency access.

| Command | Subcommand     | Flags                  | Description                                           |
| :------ | :------------- | :--------------------- | :---------------------------------------------------- |
| `auth`  | `email [addr]` | -                      | Registers recovery email (Alert only, key in CLI).    |
| `auth`  | `alerts`       | `--enable / --disable` | Toggles global security alerts (Email-based).         |
| `auth`  | `level [1-3]`  | -                      | Sets security paranoia level.                         |
| `auth`  | `recover`      | -                      | Initiates cryptographic vault recovery.               |
| `auth`  | `change`       | -                      | Rotates the master password (re-encrypts everything). |
| `auth`  | `reset`        | -                      | Wipes all recovery metadata from the vault.           |

### 3.2 Core Operations

| Category    | Commands                                        |
| :---------- | :---------------------------------------------- |
| **Data**    | `add`, `get`, `edit`, `del`, `gen`, `totp show` |
| **Session** | `unlock`, `lock`, `status`                      |
| **Sync**    | `cloud init`, `cloud sync`, `cloud auto-sync`   |
| **Audit**   | `health`, `audit`, `cinfo`, `info`              |
| **Org**     | `space create`, `space switch`, `space list`    |

---

## 4. MCP Integration (AI Agent Support)

APM allows secure integration with AI Assistants (Claude, Cursor, v0) via the Model Context Protocol.

1. **Authorize**: `pm mcp token`
2. **Details**: See [mcp.md](./mcp.md) for full setup instructions.

---

## 5. Usage & Development

### Installation
```bash
git clone https://github.com/aaravmaloo/apm.git
go build -o pm.exe main.go
./pm.exe init
```

### Security Policy
Copyright (c) 2025-2026 Aarav Maloo. Licensed under the MIT License.
AI was used selectively for code refactoring and naming; all core cryptographic logic is hand-written and audited.
