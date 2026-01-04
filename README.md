# Go Password Manager (APM)

APM is a secure, simple, and fast command-line password manager written in Go.

## Features

- **Multi-Type Vault**: Store Passwords, TOTPs, API Keys, SSH Keys, Wi-Fi Credentials, Recovery Codes, and Secure Notes.
- **Interactive CLI**: Easy-to-use interactive prompts for adding and editing entries.
- **Encryption**: Uses AES-256-GCM and Argon2id for state-of-the-art security.
- **Session Management**: Keep your vault unlocked temporarily with `pm mode open`.
- **Emergency Lockdown**: Instantly secure your data with `pm mode lock` or `pm mode compromise`.
- **Import/Export**: Move your data easily with JSON, CSV, and TXT support.

## Installation

### Windows
1. Download `pm.exe`.
2. (Optional) Add the directory containing `pm.exe` to your system `PATH`.
3. Initialize your vault:
   ```powershell
   pm init
   ```

### Build from Source
```bash
go build -o pm .
```

## Usage

### 1. Initialize
```bash
pm init
```
Sets up your encrypted vault with a Master Password.

### 2. Add Entry
```bash
pm add
```
Launch an interactive prompt to select the entry type and fill in details.

### 3. Retrieve Entry
```bash
pm get [name]
```
Retrieves an entry. Passwords, Tokens, API Keys, and SSH Private Keys are automatically copied to your clipboard.
- **Show Secret**: Use `--show-pass` to display the secret in the console:
  ```bash
  pm get google.com --show-pass
  ```

### 4. Edit Entry
```bash
pm edit [name]
```
Interactively edit all fields of an entry, including its name/identifier.

### 5. Delete Entry
```bash
pm del [name]
```
Permanently remove an entry from the vault.

### 6. Vault History
```bash
pm vhistory
```
View a chronological log of all changes (ADD, UPDATE, DELETE) made to your vault.

### 7. Operational Modes
- **Open Session**: Unlock your vault for a specified duration (to avoid re-entering your master password).
  ```bash
  pm mode open 15
  ```
- **Lock**: Immediately terminates any active session.
  ```bash
  pm mode lock
  ```
- **Compromise (Emergency)**: Securely erase the vault file and all traces from the disk. **IRREVERSIBLE.**
  ```bash
  pm mode compromise
  ```

### 8. Import & Export
- **Export**:
  ```bash
  pm export -o my_backup.json
  ```
- **Import**:
  ```bash
  pm import my_backup.json
  ```

### 9. Generation
```bash
pm gen --length 32
```

## Security Design
- **Key Derivation**: Argon2id ensures your master password remains resilient to brute-force attacks.
- **Encryption**: AES-256-GCM provides top-tier confidentiality and integrity.
- **Secure Erase**: The `compromise` command overwrites the vault file with random data multiple times before deletion.

## Version Info
```bash
pm info
```
Shows installation paths and project information.
