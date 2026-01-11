# APM - Advanced Password Manager

APM is a secure, modern, and transparent CLI password manager built for professionals who value cryptography and usability.

## Core Features

- **Robust Cryptography**: Uses **Argon2id** for key derivation, **AES-256-GCM** for encryption, and **HMAC-SHA256** for tamper detection.
- **Secure Cloud Sync**: Sync your encrypted vault to Google Drive with custom retrieval keys and public sharing capabilities.
- **Encrypted Credentials**: Cloud API credentials (JSON) are stored securely inside your encrypted vault, not in plain text on disk.
- **Deterministic Security**: Locked-down crypto parameters ensure consistent, verifiable security.
- **Diverse Secret Types**: Support for Passwords, TOTP, Tokens (API/Service), Secure Notes, API Keys, SSH Keys, Wi-Fi, and Recovery Codes.
- **Health Scanning**: Offline analysis of your password strength, reuse, and entropy (`apm scan`).
- **Audit Logging**: Secure, encrypted history of all vault access (`apm audit`).
- **Read-Only / Unlock Sessions**: Manage access durations via the `pm mode` command group.

## Getting Started

### Initialization
Initialize a new vault. You will be prompted to create a strong Master Password.
```bash
pm init
```

### Retrieval
Add passwords, TOTP secrets, API keys, SSH keys, notes, and more.
```bash
pm add
```

Search and retrieve entries.
```bash
pm get                 # Interactive type selection
pm get github          # Fuzzy search across all entries
```

### OTP Generation
Generate TOTP codes live.
```bash
pm totp show <account>
# or show all
pm totp show all
```

### Cloud Synchronization
Connect your vault to Google Drive for portability.

1.  **Init Cloud**:
    ```bash
    pm cloud init
    ```
    Choose a custom **Retrieval Key** (e.g., `MySecretKey-2024`) or let the program generate one. This key allows you to pull your vault on any device WITHOUT logging in.

2.  **Sync**:
    ```bash
    pm cloud sync        # Manual sync
    pm cloud auto-sync   # Start background watcher
    ```

3.  **Retrieve on New Device**:
    ```bash
    pm cloud get <your-key>
    ```

## Security & Modes

### Access Control (`pm mode`)
APM supports specific modes for secure usage:
- `pm mode unlock <minutes>`: Temporary read-write access.
- `pm mode readonly <minutes>`: Temporary read-only access for untrusted environments.
- `pm mode lock`: Immediately terminate all active sessions.

### Crypto Health (`pm scan` / `pm audit`)
- **Scan**: Find weak/reused passwords offline.
- **Audit**: View the timestamped history of vault interactions.

## Advanced Usage

### Import / Export
Move your data in and out securely.
```bash
pm export --output backup.json --encrypt-pass <backup-password>
pm import backup.json --encrypt-pass <backup-password>
```

## Technical Details

**Vault Format (v2)**:
`Header (8B) | Version (1B) | Salt (16B) | Validator (32B) | IV (12B) | AES-GCM Ciphertext | HMAC (32B)`

- **KDF**: Argon2id (Time=3, Memory=128MB, Parallelism=4)
- **Encryption**: AES-256-GCM
- **Integrity**: HMAC-SHA256 (Encrypt-then-MAC)
- **Validation**: Constant-time key validation (Hash-based)

## Zero Trust
APM prioritizes local-first security. Network connection is only used for explicit cloud sync operations. All source code is minimal, comment-free, and transparent.
