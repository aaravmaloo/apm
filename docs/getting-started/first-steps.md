# First Steps

This walkthrough takes you from a fresh install to a fully operational encrypted vault in under five minutes. By the end you'll know how to create, search, and manage secrets with APM.

---

## Step 1: Run Setup

Run the `setup` command to create and configure your vault:

```bash
pm setup
```

You'll be prompted for:

1. **Master Password** — Choose a strong passphrase (12+ characters recommended). This password is **never stored** — it's used to derive encryption keys via Argon2id.

2. **Security Profile** — APM detects your system hardware and recommends a profile:

    | Profile      | Memory | Iterations | Parallelism | Best For             |
    | :----------- | :----- | :--------- | :---------- | :------------------- |
    | **Standard** | 64 MB  | 3          | 2           | Most systems         |
    | **Hardened** | 256 MB | 5          | 4           | ≥8 GB RAM, ≥4 cores  |
    | **Paranoid** | 512 MB | 6          | 4           | ≥16 GB RAM, ≥8 cores |
    | **Legacy**   | PBKDF2 | 600k       | 1           | Compatibility only   |

3. **Encryption Method** — For new vaults, APM asks which AEAD cipher to use:

    | Method                  | Notes                                           |
    | :---------------------- | :---------------------------------------------- |
    | **aes-gcm**             | Default compatibility-oriented choice           |
    | **xchacha20-poly1305**  | Requires a 24-byte nonce; selectable in setup   |

4. **Optional setup tasks** — Spaces, plugins, and cloud sync can all be configured in the same guided flow.

!!! success "What just happened?"
    APM created an encrypted vault file (default: `vault.dat` beside the binary unless `APM_VAULT_PATH` is set). The file uses the **Vault V4 format** — an `APMVAULT` header followed by encrypted JSON, protected by the selected AEAD cipher and HMAC-SHA256.

---

## Step 2: Unlock Your Vault

APM uses **explicit sessions** — the vault is encrypted at rest and must be unlocked before any sensitive operation:

```bash
pm unlock
```

You'll enter your master password and choose:

- **Session duration** (default: 30 minutes)
- **Inactivity timeout** (default: 10 minutes)
- **Read-only mode** (optional — prevents writes)

!!! info "How Sessions Work"
    `pm unlock` decrypts the vault in memory and creates a session file tied to your terminal. All sensitive commands check for an active session. The session auto-expires after the configured duration or inactivity timeout.

    Sessions are **shell-scoped** — each terminal can have its own independent session via the `APM_SESSION_ID` environment variable.

---

## Step 3: Add Your First Entry

```bash
pm add
```

APM presents an interactive menu of **25+ secret types**:

```
 1. Password          8. API Key         15. CI/CD Secret
 2. TOTP              9. Token           16. Secure Note
 3. Government ID    10. SSH Key         17. Recovery Codes
 4. Medical Record   11. SSH Config      18. Certificate
 5. Travel Info      12. Cloud Creds     19. Banking
 6. Contact          13. Kubernetes      20. Document
 7. Wi-Fi            14. Docker          21. Software License
                                         22. Legal Contract
```

Select a type and fill in the structured fields. For example, adding a password:

```
Type: 1 (Password)
Account: github.com
Username: aarav
Password: ********** (hidden input)
Space: Work (optional)
```

!!! tip "Password Generation"
    Use `pm gen` to generate a high-entropy password before adding it:

    ```bash
    pm gen
    # Output: K$7mP!2qX#9nL@4vR  (copied to clipboard)
    ```

---

## Step 4: Search and Retrieve Entries

```bash
pm get github
```

APM uses **fuzzy search** to find matching entries across all types. Results are displayed in an interactive browser where you can:

- Press ++enter++ to view full details
- Press ++c++ to copy the password to clipboard
- Press ++e++ to edit the entry
- Press ++d++ to delete the entry
- Press ++q++ for quicklook (preview notes, photos)
- Press ++m++ to view metadata (created, last accessed, trust score)

!!! note "Safe by Default"
    Sensitive fields like passwords are **hidden by default**. Use the `--show-pass` flag or press ++s++ in the interactive view to reveal them:

    ```bash
    pm get github --show-pass
    ```

---

## Step 5: Set Up TOTP (Two-Factor Authentication)

Add a TOTP entry with `pm add`, then access your 2FA codes:

```bash
# Interactive TOTP list with live countdown
pm totp

# Copy a specific code directly
pm totp github
```

The interactive TOTP view shows live codes with countdown timers and supports drag-to-reorder for your most-used accounts.

---

## Step 6: Lock Your Vault

When you're done working, lock the vault to wipe all decrypted data from memory:

```bash
pm lock
```

!!! warning
    Always lock your vault when stepping away. While sessions auto-expire, explicitly locking is the safest practice.

---

## Step 7: Set Up Cloud Sync (Optional)

Sync your encrypted vault across devices using any supported provider:

=== "Google Drive"

    ```bash
    pm cloud init gdrive
    # Opens browser for OAuth consent
    ```

=== "GitHub"

    ```bash
    pm cloud init github
    # Enter your Personal Access Token and repo name
    ```

=== "Dropbox"

    ```bash
    pm cloud init dropbox
    # Opens browser for OAuth consent
    ```

Then sync:

```bash
pm cloud sync
```

!!! info
    Your master password **never leaves your machine**. Only the encrypted vault blob is uploaded. Cloud providers cannot see your entries.

---

## Step 8: Enable Autofill (Windows Only)

If you're on Windows, start the autofill daemon:

```bash
pm autocomplete enable   # Register autostart + start daemon
pm unlock                # Unlock the daemon's vault state
```

Now press ++ctrl+shift+l++ on any login form and APM will detect the context and inject your credentials — no browser extension needed.

---

## Quick Reference Card

| Task               | Command          |
| :----------------- | :--------------- |
| Run setup          | `pm setup`       |
| Unlock vault       | `pm unlock`      |
| Lock vault         | `pm lock`        |
| Add an entry       | `pm add`         |
| Search entries     | `pm get [query]` |
| Edit an entry      | `pm get [query]` then press `e` |
| Delete an entry    | `pm get [query]` then press `d` |
| Generate password  | `pm gen`         |
| View TOTP codes    | `pm totp`        |
| Sync to cloud      | `pm cloud sync`  |
| Check vault health | `pm health`      |
| View trust scores  | `pm trust`       |
| View audit log     | `pm audit`       |
| System info        | `pm info`        |
| Crypto info        | `pm cinfo`       |
| Self-update        | `pm update`      |

---

## Next Steps

- **[Features](features.md)** — Explore everything APM can do
- **[Vault Management](../guides/vault-management.md)** — Deep dive into entries, spaces, and vocabulary
- **[Cloud Sync](../guides/cloud-sync.md)** — Set up multi-provider synchronization
- **[Sessions](../guides/sessions.md)** — Understand ephemeral and delegated sessions
