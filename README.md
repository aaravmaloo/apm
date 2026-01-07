# APM - Advanced Password Manager

APM is a secure, modern, and transparent CLI password manager built for professionals who value cryptography and usability.

## Core Features

- **Robust Cryptography**: Uses **Argon2id** for key derivation, **AES-256-GCM** for encryption, and **HMAC-SHA256** for tamper detection.
- **Deterministic Security**: Locked-down crypto parameters ensure consistent, verifiable security.
- **Tamper Evident**: Relentless integrity checks prevent corrupted or malicious file modifications.
- **Improved Get Flow**: Use interactive type selection (`pm get`) or instant fuzzy search (`pm get <query>`).
- **Diverse Secret Types**: Support for Passwords, TOTP, Tokens (API/Service), Secure Notes, API Keys, SSH Keys, Wi-Fi, and Recovery Codes.
- **Health Scanning**: Offline analysis of your password strength, reuse, and entropy (`apm scan`).
- **Audit Logging**: Secure, encrypted history of all vault access (`apm audit`).
- **Clipboard Hygiene**: Auto-clears your clipboard after 20 seconds to prevent leaks.
- **Read-Only Mode**: Open your vault safely in untrusted environments (`apm readonly 5`).

## Getting Started

### Initialization
Initialize a new vault. You will be prompted to create a strong Master Password.
```bash
pm init
```

### Adding Entries
Add passwords, TOTP secrets, API keys, SSH keys, notes, and more.
```bash
pm add
```

Search and retrieve entries.

**Interactive Mode**:
Run without arguments to select by type:
```bash
pm get
```
This shows a menu (Password, TOTP, Token, etc.) and lists all available entries for that category.

**Fuzzy Search**:
Provide a query to search across all entries instantly:
```bash
pm get git      # Matches 'github', 'digitalocean', 'git'
pm get --show-pass github
```
If only one match is found, it is displayed immediately. Otherwise, a ranked list is shown for selection.

### OTP Generation
Generate TOTP codes live.
```bash
pm totp show <account>
# or show all
pm totp show all
```

## Security Commands

### Crypto Info (`cinfo`)
View the exact cryptographic parameters used by APM.
```bash
pm cinfo
```

### Health Scan (`scan`)
Run a local, offline analysis of your vault to find weak or reused passwords.
```bash
pm scan
```

### Audit Log (`audit`)
View the encrypted access history of your vault.
```bash
pm audit
```

## Advanced Usage

### Sessions (`unlock` / `readonly`)
Unlock the vault for a specific duration to avoid repeated password prompts.

**Read-Write Access:**
```bash
pm unlock 15         # Unlock for 15 minutes
```

**Read-Only Access:**
```bash
pm readonly 15       # Unlock in Read-Only mode (safety)
```
In Read-Only mode, any attempt to modify the vault will be blocked.

### Import / Export
Move your data in and out securely.
```bash
pm export --output backup.json --encrypt-pass <backup-password>
pm import backup.json --encrypt-pass <backup-password>
```

## Technical Details

**Vault Format (v1)**:
`Header (8B) | Version (1B) | Salt (16B) | Validator (32B) | IV (12B) | AES-GCM Ciphertext | HMAC (32B)`

- **KDF**: Argon2id (Time=3, Memory=128MB, Parallelism=4)
- **Encryption**: AES-256-GCM
- **Integrity**: HMAC-SHA256 (Encrypt-then-MAC)
- **Validation**: Constant-time key validation (Hash-based)

## Zero Trust
APM never connects to the network. All operations are local. Memory buffers are wiped after use.
