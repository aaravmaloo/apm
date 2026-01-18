# APM - Advanced Password Manager

APM is a professional-grade, zero-knowledge command-line interface (CLI) for managing high-sensitivity credentials. Engineered for cryptographic performance and organizational scalability, it features a dual-engine architecture supporting both individual privacy and team-based collaboration.

[![Tests Status](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/aaravmaloo/apm/actions)
[![Vault Version](https://img.shields.io/badge/vault-v3-blue.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)

---

## Table of Contents
- [1. Security Architecture](#1-security-architecture)
  - [1.1 Key Derivation: Argon2id](#11-key-derivation-argon2id)
  - [1.2 Authenticated Encryption: AES-256-GCM](#12-authenticated-encryption-aes-256-gcm)
  - [1.3 Threat Model Summary](#13-threat-model-summary)
- [2. Core Technical Specifications](#2-core-technical-specifications)
  - [2.1 Performance Profiles](#21-performance-profiles)
- [3. Comprehensive Command Glossary](#3-comprehensive-command-glossary)
  - [3.1 Personal Edition (pm)](#31-personal-edition-pm)
- [4. Team Edition (pm-team)](#4-team-edition-pm-team)
  - [4.1 Permission Matrix](#41-permission-matrix)
  - [4.2 Key Team Commands](#42-key-team-commands)
- [5. Supported Secret Types](#5-supported-secret-types)
- [6. Plugin Architecture and SDK Reference](#6-plugin-architecture-and-sdk-reference)
  - [6.1 Plugin Lifecycle](#61-plugin-lifecycle)
  - [6.2 Exhaustive Capability Reference](#62-exhaustive-capability-reference)
  - [6.3 Action Glossary (Keywords)](#63-action-glossary-keywords)
  - [6.4 Variable Substitution Engine](#64-variable-substitution-engine)
- [7. Installation and Deployment](#7-installation-and-deployment)
  - [7.1 Requirements](#71-requirements)
  - [7.2 Build Process](#72-build-process)
- [8. Contact & Support](#8-contact--support)
- [9. Development & Contributing](#9-development--contributing)

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
- **Nonce Integrity**: Every save operation generates a unique 12 or 24-byte nonce to prevent replay attacks and pattern analysis.

### 1.3 Threat Model Summary
| Vector | Status | Mitigation |
|--------|--------|------------|
| Offline Brute-Force | Protected | Argon2id high-cost derivation. |
| Vault Tampering | Protected | HMAC-SHA256 integrity signature. |
| Credential Theft | Protected | Cloud tokens are encrypted inside the vault. |
| Compromised Host | Not Protected | Outside the security boundary (Keyloggers/Malware). |
| Weak Passwords | Not Protected | User responsibility; use high-entropy passphrases. |

## 2. Core Technical Specifications

### 2.1 Performance Profiles

Users can select from pre-defined profiles via `pm profile set` to balance security and latency.

| Profile | Memory | Time | Parallelism | Nonce Size |
|---------|--------|------|-------------|------------|
| Standard | 64 MB | 3 | 2 | 12 bytes |
| Hardened | 256 MB | 5 | 4 | 12 bytes |
| Paranoid | 512 MB | 6 | 4 | 24 bytes |
| Legacy | 0 (PBKDF2) | 600k | 1 | 12 bytes |

---

## 3. Comprehensive Command Glossary

### 3.1 Personal Edition (pm)

The personal edition focuses on local-first security and privacy.
The best feature of APM, to my belief is security of multi-cloud sync and how easily it is to maintain a portable vault. 
The users' whole vault is stored in a single encrypted .dat file and remains fully opaque to unauthorized viewers. 
The user can sync their vault to Google Drive or Dropbox. For maximum privacy, cloud vaults use randomized filenames (e.g., `v_1h2k3j.bin`) instead of the retrieval key. Retrieving a vault requires a two-word retrieval key (now hidden during input) and the master password.
For those preferring air-gapped security, the `vault.dat` file can be manually carried on a physical hardware key.
| Command | Subcommands | Flag Examples | Description |
|---------|-------------|---------------|-------------|
| **init** | N/A | N/A | Initializes a new encrypted vault file (`vault.dat`). |
| **add** | N/A | N/A | Launches an interactive menu to store one of the 22 secret types. |
| **get** | [query] | `--show-pass` | Fuzzy searches and retrieves secret details. |
| **edit** | [name] | N/A | Interactive modification of existing entry metadata. |
| **del** | [name] | N/A | Permanent deletion of an entry from the vault. |
| **gen** | N/A | `--length 24` | High-entropy password generator. |
| **totp** | `show [acc]`| N/A | Real-time generation of 2FA codes. |
| **scan** | N/A | N/A | Offline diagnostic for weak/reused passwords. |
| **audit** | N/A | N/A | View an encrypted history of every vault interaction. |
| **adup** | N/A | N/A | Anomaly Detection: Checks for suspicious access patterns. |
| **health**| N/A | N/A | Security dashboard with vulnerability scoring. |
| **mode** | `unlock`, `lock` | `--min 15` | Session duration and access control management. |
| **cloud** | `init`, `sync`, `get` | `dropbox`, `gdrive` | Multi-cloud integration (Dropbox/GDrive) with randomized naming. |
| **plugins**| `list`, `add`, `push` | N/A | Multi-cloud Marketplace with failover-capable plugin storage. |

---

## 4. Team Edition (pm-team)

Designed for organizations, the Team Edition facilitates secure credential sharing via a multi-layered Role-Based Access Control (RBAC) model.

### 4.1 Permission Matrix

| Action | ADMIN | MANAGER | USER | AUDITOR | SECURITY |
|--------|-------|---------|------|---------|----------|
| Create Departments | Full | Own | None | None | None |
| Manage Users | Full | Dept | None | None | None |
| Add Secrets | Yes | Yes | Yes | No | No |
| View Shared Secrets| All | Dept | Dept | None | Security |
| View Audit Logs | Full | View | None | Full | Full |

### 4.2 Key Team Commands

| Command | Usage | Result |
|---------|-------|--------|
| `init` | `pm-team init "Corp" admin` | Sets up organization root environment. |
| `dept create` | `pm-team dept create Engineering`| Creates a new isolated encryption domain. |
| `user add` | `pm-team user add alice --role MANAGER`| Onboards a new member with specific permissions. |
| `audit` | `pm-team audit` | Visualizes the hashed, tamper-evident organization log. |

---

## 5. Supported Secret Types

APM supports 22 distinct data structures, each encrypted with unique nonces.

#### Personal & Lifestyle
1. **Passwords**: Account, Username, Password, URL string.
2. **TOTP**: Account mapping and Base32 secrets.
3. **Government IDs**: Passport, Driver's License, and Voter ID templates with ID Numbers and Expiry.
4. **Medical Records**: Insurance IDs, Prescriptions, and Allergies.
5. **Travel Docs**: Ticket Numbers, Booking Codes, and Loyalty Programs.
6. **Contacts**: Encrypted address book with Emergency contact flags.
7. **Wi-Fi**: SSID, Password, Security Type, and **Router IP**.

#### Developer & DevOps
8. **API Keys**: Service name, Label, and Key material.
9. **Tokens**: Bearer/Auth tokens with Type classification.
10. **SSH Keys**: Private key blocks for remote server access.
11. **SSH Configs**: Host Alias, Key Path, User, Port, and Fingerprints.
12. **Cloud Credentials**: Access/Secret Keys, Region, Account, and Roles.
13. **Kubernetes Secrets**: Cluster URL, Namespace, and Expiration.
14. **Docker Registry**: Registry URL with associated credentials.
15. **CI/CD Secrets**: Webhook URLs and environment variable groups.

#### Documents & Licenses
16. **Secure Notes**: Multi-line markdown-capable notes.
17. **Recovery Codes**: Array-based storage for backup codes.
18. **Certificates**: X.509/SSL data, Issuers, and Expiry tracking.
19. **Banking**: Card/IBAN details including CVV and Expiry dates.
20. **Documents**: Encrypted binary storage with **Tags** and **Expiry Dates**.
21. **Software Licenses**: Serial Keys, Product Name, and Activation Info.
22. **Legal Contracts**: Summary, Involved Parties, and Signed Dates.

---

## 6. Plugin Architecture and SDK Reference

APM features a declarative, JSON-driven plugin architecture. This allows for extensive customization and automation without requiring the compilation of Go code.

### 6.1 Plugin Lifecycle
- **Discovery**: Plugins are located in the `/plugins_cache` directory.
- **Manifest Validation**: On startup, `plugin.json` is verified for syntax and capability requirements.
- **Hook Execution**: Plugins can intercept standard CLI events (e.g., `pre:add`) or register new top-level commands.
- **Redundancy**: Pushed plugins are simultaneously mirrored to both Google Drive and Dropbox to ensure maximum availability.

### 6.2 Exhaustive Capability Reference
Permissions are explicitly defined in the manifest. Requests for unlisted permissions will result in a runtime error.

| Capability | Scope | Description |
|------------|-------|-------------|
| `vault.read` | Reads | Access to `vault.get`, `vault.list`, and `vault.get_totp`. |
| `vault.write`| Mutations | Access to `vault.add`, `vault.edit`, and `vault.delete`. |
| `system.read`| Environment| Access to `system.env` (Reading OS environment variables). |
| `system.write`| IO | Access to `system.copy` (Unified OS Clipboard integration). |
| `network.outbound`| Network | Access to `network.get` and `network.post` (RESTful integrations). |
| `crypto.use` | Cryptography| Access to `crypto.hash` (SHA-256) and RNG utilities. |
| `file.storage`| Local Disk | Private sandboxed storage within the plugin's home directory. |

### 6.3 Action Glossary (Keywords)

| Keyword | Target | Description | Variable Mapping |
|---------|--------|-------------|------------------|
| `print` | Console | Outputs a string to the terminal. | `message` |
| `prompt.input`| User | Requests interactive input from the user. | `message` -> `assign_to` |
| `vault.get` | Entry | Retrieves a secret by account name. | `key` -> `assign_to` |
| `vault.add` | Entry | Creates a new entry with provided credentials. | `key`, `message` |
| `vault.delete`| Entry | Irreversibly removes a specific account entry. | `key` |
| `network.get` | URL | Performs an HTTP GET request to a remote endpoint. | `key` -> `assign_to` |
| `network.post`| URL | Performs an HTTP POST with a specific payload. | `key`, `message` -> `assign_to` |
| `system.copy` | Clipboard| Places the specified text into the system clipboard. | `message` |
| `system.env` | Variable | Reads an environment variable into memory. | `key` -> `assign_to` |
| `crypto.hash` | Data | Computes a SHA-256 hex-encoded hash of the input. | `message` -> `assign_to` |

### 6.4 Variable Substitution Engine
APM uses a high-performance templating engine for action fields.
- **System Reserved**: `{{USER}}`, `{{OS}}`, `{{TIMESTAMP}}`, `{{VAULT_VERSION}}`.
- **User Defined**: Any variable mapped via `assign_to` (e.g., `{{my_secret_key}}`).

---

## 7. Installation and Deployment

### 7.1 Requirements
- Go 1.21+
- Secure Terminal (Supports Password Hiding)

### 7.2 Build Process
You can either compile it from source, or use the releases page to download a pre-compiled binary/exe, for Windows, macOS, and Linux.
 
Steps to build from source:
```bash
git clone https://github.com/aaravmaloo/apm.git
cd apm
go build -o pm.exe main.go
./pm.exe init
```
It is highly recommended to add environment vairables so that you can access APM from anywhere. Rename the binary to `pm` or the name you would like to call for APM and move it to the below specified locations for each opearting system.
Windows: `C:\Users\<user_name>\Appdata\Local\apm`
(You will need to create the apm folder manually)

Linux: `~/.apm/`
(Make sure to add execute permissions to the binary)

macOS: `/usr/local/bin/apm`
(Make sure to add execute permissions to the binary)

---

## 8. Contact & Support

For security disclosures, technical support, or enterprise licensing inquiries, please use the following channels:

| Channel | Identifier |
|---------|------------|
| **Primary Maintainer** | Aarav Maloo |
| **GitHub Issues** | [Report Bug / Request Feature](https://github.com/aaravmaloo/apm/issues) |
| **Security Alerts** | aaravmaloo06@gmail.com |
| **Support Email** | aaravmaloo06@gmail.com |

---

## 9. Development & Contributing

APM is open-source and welcomes contributions. All PRs must pass the exhaustive E2E test suite located in `/tests`.

---

Copyright (c) 2025-2026 Aarav Maloo. Licensed under the MIT License.
