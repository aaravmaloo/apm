# Features

APM packs a professional-grade feature set into a single CLI binary. This page provides a comprehensive overview of every capability, organized by category.

---

## :material-shield-lock: Security & Encryption

### Zero-Knowledge Vault

Your master password is **never stored** anywhere. APM derives three separate 32-byte keys (encryption, authentication, and validation) from your password using **Argon2id** — the winner of the Password Hashing Competition.

### Dual AEAD Encryption

Vaults can use **AES-256-GCM** or **XChaCha20-Poly1305** for authenticated encryption. The active cipher is stored in the profile metadata, and each save generates a fresh nonce for the selected method.

### Double-Layer Integrity

Beyond GCM's built-in authentication, APM adds an **HMAC-SHA256 signature** computed from your master password's authentication key over the entire vault file. Tampering with any byte produces a verification failure.

### Four Security Profiles

| Profile      | Argon2 Memory | Iterations | Parallelism | Use Case                 |
| :----------- | :------------ | :--------- | :---------- | :----------------------- |
| **Standard** | 64 MB         | 3          | 2           | Most machines            |
| **Hardened** | 256 MB        | 5          | 4           | Workstations (≥8 GB RAM) |
| **Paranoid** | 512 MB        | 6          | 4           | Servers (≥16 GB RAM)     |
| **Legacy**   | PBKDF2        | 600,000    | 1           | Backward compatibility   |

APM auto-detects your system's CPU cores and RAM to recommend the optimal profile during `pm setup`.

### Brute-Force Testing

Validate your vault's resistance to attacks with the built-in brute-force simulator:

```bash
pm brutetest 5   # Run for 5 minutes
```

This stress-tests your vault using multi-threaded dictionary and character-set attacks, then reports whether your password survived.

---

## :material-key-variant: Secret Types

APM supports **25+ structured secret types**, each with validated fields and type-specific display logic:

| #   | Type             | Key Fields                                          |
| --- | :--------------- | :-------------------------------------------------- |
| 1   | Password         | Account, Username, Password, Space                  |
| 2   | TOTP             | Account, Secret, Space                              |
| 3   | Government ID    | Type, ID Number, Name, Expiry                       |
| 4   | Medical Record   | Label, Insurance ID, Prescriptions, Allergies       |
| 5   | Travel Info      | Label, Ticket Number, Booking Code, Loyalty Program |
| 6   | Contact          | Name, Phone, Email, Address, Emergency flag         |
| 7   | Wi-Fi            | SSID, Password, Security Type, Router IP            |
| 8   | API Key          | Name, Service, Key                                  |
| 9   | Token            | Name, Token, Type                                   |
| 10  | SSH Key          | Name, Private Key                                   |
| 11  | SSH Config       | Alias, Host, User, Port, Key Path, Fingerprint      |
| 12  | Cloud Creds      | Label, Access Key, Secret Key, Region, Role, Expiry |
| 13  | Kubernetes       | Name, Cluster URL, Namespace, Expiration            |
| 14  | Docker Registry  | Name, Registry URL, Username, Token                 |
| 15  | CI/CD Secret     | Name, Webhook, Environment Variables                |
| 16  | Secure Note      | Name, Content (with vocabulary autocomplete)        |
| 17  | Recovery Codes   | Service, Codes[]                                    |
| 18  | Certificate      | Label, Cert Data, Private Key, Issuer, Expiry       |
| 19  | Banking          | Label, Type, Details, CVV, Expiry                   |
| 20  | Document         | Name, FileName, Content (binary), Password, Tags    |
| 21  | Software License | Product Name, Serial Key, Activation Info, Expiry   |
| 22  | Legal Contract   | Name, Summary, Parties Involved, Signed Date        |
| 23  | Photo            | Name, FileName, Content (binary)                    |
| 24  | Audio            | Name, FileName, Content (binary)                    |
| 25  | Video            | Name, FileName, Content (binary)                    |

---

## :material-text-search: Search & Navigation

- **Fuzzy search** across all entry types with `pm get [query]`
- **Interactive entry browser** with keyboard navigation
- **Quicklook** for notes and photo entries (ASCII art rendering for photos)
- **Metadata inspector** showing creation date, last access, access count, trust score, and creator
- **Space-aware filtering** when a space is active

---

## :material-folder-multiple: Spaces

Spaces provide logical compartments for your entries — like folders but within a single encrypted vault:

```bash
pm space create Work
pm space create Personal
pm space switch Work
pm space list
pm space remove Archive
```

Entries inherit the active space when created. You can filter searches and ignore whole spaces during cloud sync.

---

## :material-note-edit: Notes & Vocabulary

Secure notes in APM have a built-in **vocabulary engine** that provides:

- **Autocomplete suggestions** while writing notes
- **Alias normalization** for consistent terminology
- **Scoring and ranking** to promote frequently used terms
- **Compressed storage** (gzip) inside the encrypted vault

```bash
pm vocab enable           # Enable vocabulary indexing
pm vocab                  # List words and stats
pm vocab alias k8s kubernetes  # Create alias
pm vocab rank deploy +5   # Boost term ranking
pm vocab reindex          # Rebuild from current notes
```

---

## :material-two-factor-authentication: TOTP (Two-Factor Authentication)

- Interactive TOTP list with **live countdown timers**
- **Persistent ordering** — drag your most-used codes to the top
- **Direct copy** — `pm totp github` copies the current code
- **Autofill linking** — bind TOTP entries to domains for the autofill daemon

---

## :material-cloud-sync: Cloud Synchronization

Sync your encrypted vault to **three cloud providers**:

| Provider     | Auth Method   | Storage Type            | Best For                |
| :----------- | :------------ | :---------------------- | :---------------------- |
| Google Drive | OAuth2 (PKCE) | Application Data Folder | Mobile, fast sync       |
| GitHub       | PAT           | Private Repository      | Developers, git history |
| Dropbox      | OAuth2 (PKCE) | Application Folder      | Cross-platform          |

Features:

- **End-to-end encryption** — providers never see plaintext
- **Retrieval keys** — optional key-hash metadata for lookup
- **Metadata consent** — explicit opt-in for provider metadata
- **Conflict resolution** — overwrite, keep local copy, or cancel
- **`.apmignore`** — filter what gets uploaded per-provider
- **Auto-sync** — periodic background synchronization

---

## :material-robot: MCP Server (AI Integration)

APM includes a native **Model Context Protocol** server that lets AI assistants access your vault:

- **Permission scopes**: `read`, `secrets`, `write`, `admin`
- **Token-based auth** with expiry and usage tracking
- **Transaction guardrails** for write operations (preview → approve → receipt)
- **Works with**: Claude Desktop, Cursor, Windsurf, and any MCP-compatible client

---

## :material-puzzle: Plugin System

A manifest-based plugin architecture with:

- **100+ granular permissions** across vault, network, system, crypto, UI, and cloud categories
- **Plugin marketplace** — install, publish, and discover plugins via cloud providers
- **Hook system** — plugins can listen to vault lifecycle events
- **Runtime permission overrides** — toggle individual permissions per plugin
- **Step executor** — plugins define command pipelines with conditional logic

---

## :material-form-textbox-password: Autofill Daemon (Windows)

A Windows-only autofill daemon that works **system-wide without a browser extension**:

- **Hotkey driven** — press ++ctrl+shift+l++ to fill credentials
- **Context-aware** — detects window titles, process names, and focused form fields
- **Popup hints** — shows notifications when matches are detected
- **Keystroke injection** — never uses the clipboard for core typing
- **TOTP injection** — linked TOTP entries auto-fill 2FA codes
- **Loopback IPC** — local only, bearer-token protected

---

## :material-face-recognition: Face ID Unlock (Optional)

Face ID provides biometric unlock using local face recognition. It is **optional** and only available when APM is built with the `faceid` build tag because it depends on native OpenCV and dlib libraries.

```bash
# Standard build (no Face ID)
go build -o pm.exe

# Face ID build
go build -tags faceid -o pm.exe
```

Once built with `faceid`:

```bash
pm faceid enroll
pm faceid status
pm faceid test
pm faceid remove
```

Notes:
- Models are downloaded automatically to your user config directory under `apm/faceid/models`.
- Enrollment metadata is stored next to the vault at `faceid/enrollment.json`.

---

## :material-shield-check: Health, Trust & Audit

### Vault Health Dashboard

```bash
pm health
```

Scores your vault on encryption profile strength, alert configuration, weak passwords, and risk-level secrets.

### Per-Secret Trust Scoring

```bash
pm trust
```

Computes a 0–100 trust score for each secret based on:

- Exposure status
- Rotation age (penalizes >90 / >180 / >365 days)
- Access frequency
- Privilege level (critical, root, admin, elevated)

### Tamper-Evident Audit Log

```bash
pm audit
```

Every vault interaction is logged with a timestamp, action type, user, and hostname. The audit log is stored outside the vault for independent integrity checking.

---

## :material-account-key: Recovery System

Multiple recovery mechanisms for zero-knowledge environments:

| Factor           | Command                    | Description                              |
| :--------------- | :------------------------- | :--------------------------------------- |
| Email OTP        | `pm auth email`            | 6-digit time-limited verification code   |
| Recovery Key     | `pm auth recover`          | Gates DEK access for vault re-encryption |
| Quorum Shares    | `pm auth quorum-setup`     | Shamir secret sharing (threshold-based)  |
| WebAuthn Passkey | `pm auth passkey register` | Browser-based passkey ceremony           |
| Recovery Codes   | `pm auth codes generate`   | One-time use codes                       |

---

## :material-file-import: Import & Export

| Format | Import           | Export           | Notes                          |
| :----- | :--------------- | :--------------- | :----------------------------- |
| JSON   | `pm import json` | `pm export json` | Optional encryption            |
| CSV    | `pm import csv`  | `pm export csv`  | Passwords only                 |
| TXT    | `pm import txt`  | `pm export txt`  | Human-readable, with redaction |

---

## :material-gavel: Policy Engine

YAML-based policies enforce security standards:

```yaml
name: corporate-standard
password_policy:
  min_length: 14
  require_uppercase: true
  require_numbers: true
  require_symbols: true
rotation_policy:
  rotate_every_days: 90
  notify_before_days: 14
```

```bash
pm policy load ./policies/
```

---

## :material-account-group: Team Edition

For organizations, the **Team Edition** (`pm-team`) adds:

- **RBAC** — Role-based access control with multiple roles
- **Departments** — Isolated encryption domains
- **Approval workflows** — Gated access to sensitive entries
- **Shared vaults** — Multi-user credential sharing

---

## Next Steps

- **[Vault Management Guide](../guides/vault-management.md)** — Deep dive into day-to-day usage
- **[CLI Reference](../reference/cli.md)** — Every command documented
- **[Architecture](../concepts/architecture.md)** — How it all fits together
