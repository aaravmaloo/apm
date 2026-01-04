# Go Password Manager

A secure, simple, and fast command-line password manager written in Go.

## Features

- **Encryption Layers**:
  - **AES-GCM Encryption**: Uses 256-bit AES-GCM to ensure your data is secure.
  - **Argon2id Key Derivation**: Protects your master password against brute-force attacks.
- **3-Attempt Limit**: Prevents accidental lockouts or local brute-force attempts.
- **Sudo Mode**: Temporarily store a session for passwordless access using `pm mode sudo <mins>`.
- **CLI Commands**: Manage your passwords easily with `add`, `get`, `list`, and `del`.
- **Password Generator**: Generate strong, random passwords on the fly.
- **Local Storage**: Data is stored encrypted on your disk in `vault.dat`.

## Installation

### Windows

1. **Download the Executable**: You can find the `pm.exe` in the releases tab and then move it to program files by create pm/pm.exe and then add an environment variable to use it globally.

2. **Add to PATH (Optional)**: Move `pm.exe` to a folder in your system PATH to use it from anywhere.
3. **Run**:
   ```powershell
   pm.exe init
   ```

### Linux / macOS

1. **Prerequisites**: Ensure you have [Go](https://go.dev/doc/install) installed.
2. **Build from Source**:
   ```bash
   cd src
   go build -o pm .
   ```
3. **Move to Bin**:
   ```bash
   sudo mv pm /usr/local/bin/
   ```
4. **Run**:
   ```bash
   pm init
   ```

## Usage

### Initialize Vault
```bash
pm init
```
This will prompt you to create a **Master Password**. This password is the ONLY way to access your vault. **Do not lose it!**

### Add an Account
```bash
pm add --account "GitHub" --user "yourname" --password "yourpassword"
```
Or leave the password blank to generate a strong one:
```bash
pm add --account "Google" --user "email@gmail.com"
```

### Retrieve a Password
```bash
pm get --account "GitHub"
```

### List All Accounts
```bash
pm list
```

### Search/Filter
```bash
pm list --filter "git"
```

### Generate a Random Password
```bash
pm gen --length 24
```

### Delete an Account
```bash
pm del --account "GitHub"
```

### Advanced: Sudo Mode
If you need to run multiple commands without entering your password every time, use sudo mode:
```bash
pm mode sudo 15
```
This activates a session for 15 minutes. All subsequent commands will skip the password prompt.

## Security Design

- **Encryption**: `AES-256-GCM` for confidentiality and integrity.
- **Key Derivation**: `Argon2id` (1 iteration, 64MB memory, 4 threads).
- **Session Security**: Sudo mode sessions are stored in your OS temporary directory with `0600` permissions and automatically deleted after the specified duration.
- **Attempt Limit**: Users get 3 attempts to enter the master password before the command aborts.

## Development

To build the project locally:
```bash
go mod tidy
go build -o pm .
```
