# Cloud Synchronization

APM syncs your encrypted vault to cloud providers so you can access credentials across all your trusted devices. Your master password **never leaves your machine** — only encrypted vault blobs are uploaded.

---

## Supported Providers

| Feature              | Google Drive               | GitHub                      | Dropbox                    |
| :------------------- | :------------------------- | :-------------------------- | :------------------------- |
| **Authentication**   | OAuth2 (PKCE)              | Personal Access Token       | OAuth2 (PKCE)              |
| **Storage Location** | Application Data Folder    | Private Repository          | Application Folder         |
| **Setup Speed**      | Instant (browser OAuth)    | Manual (token + repo)       | Instant (browser OAuth)    |
| **Privacy**          | High (isolated from files) | Exceptional (git history)   | High (isolated from files) |
| **Version History**  | Limited (native)           | Comprehensive (git commits) | Limited (native)           |
| **Best For**         | Mobile, fast sync          | Developers, power users     | Cross-platform             |

---

## Initial Setup

### Google Drive

```bash
pm cloud init gdrive
```

This opens your browser for Google OAuth consent. APM uses the **Application Data** folder, which is isolated from your regular Drive files — you won't see the vault blob in your Drive UI.

### GitHub

```bash
pm cloud init github
```

You'll need to provide:

1. A **Personal Access Token** (PAT) with `repo` scope
2. A **private repository** name (e.g., `my-vault-backup`)

GitHub sync stores the vault as a file in the repo, giving you comprehensive version history via git commits.

### Dropbox

```bash
pm cloud init dropbox
```

This opens your browser for Dropbox OAuth consent. APM uses the **Application folder**, isolated from your regular Dropbox files.

### All Providers At Once

```bash
pm cloud init all
```

Initializes Google Drive, GitHub, and Dropbox in sequence.

---

## Syncing

### Manual Sync

```bash
pm cloud sync
```

This uploads your current vault to all configured providers. The vault is filtered through `.apmignore` before encryption and upload.

### Downloading

```bash
pm cloud get
```

Downloads the remote vault blob. You'll be prompted to choose how to handle it:

1. **Overwrite local** — Replace your local vault with the remote one
2. **Keep local + conflict copy** — Save the remote vault as a separate file
3. **Cancel** — Abort the download

### Auto-Sync

```bash
pm cloud autosync
```

Runs periodic sync loops in the foreground. Useful for keeping vaults synchronized across active machines.

### Provider-Specific Sync

```bash
pm cloud sync gdrive
pm cloud sync github
pm cloud sync dropbox
pm cloud get gdrive
pm cloud get github
```

### Resetting Cloud Configuration

```bash
pm cloud reset
```

Clears all cloud provider credentials and configuration from the vault.

---

## Retrieval Keys

When you first upload your vault, APM generates a **retrieval key** — a unique identifier that can be used to locate your vault on the provider. This is useful when setting up on a new device.

### Metadata Consent

For Google Drive and Dropbox, APM can store a **one-way hash** of your retrieval key in provider metadata. This enables vault lookup by key hash. You'll be asked for explicit consent:

- **If you consent**: The vault can be found using the retrieval key hash
- **If you decline**: The vault is identified by its provider-specific ID (Drive file ID, Dropbox path) instead

This ensures no identifying information is stored without your permission.

---

## Security Guarantees

!!! success "What Is Uploaded"
    The cloud receives an **encrypted binary blob** — the same `APMVAULT` format stored on disk. It includes:

    - Encrypted vault data (AES-256-GCM)
    - HMAC-SHA256 integrity signature
    - Salt and profile metadata (in the unencrypted header)

!!! failure "What Is Never Uploaded"
    - Your master password
    - Plaintext entries
    - Decrypted vault contents
    - Session data

---

## Using .apmignore with Cloud Sync

The `.apmignore` file is processed **before** encryption and upload. You can:

- Exclude entire spaces
- Exclude specific entries by `space:type:name` pattern
- Use provider-specific rules
- Strip vocabulary data

See the [.apmignore Guide](apmignore.md) for full details.

---

## Conflict Resolution

When `pm cloud get` finds that the remote vault differs from your local vault:

1. **Overwrite local** — The remote vault replaces your local vault entirely
2. **Keep local + save conflict copy** — The remote vault is saved alongside your vault as a timestamped copy
3. **Cancel** — No changes are made

!!! info
    Conflict handling is **whole-vault only**. APM does not perform entry-level merge. This is intentional — merging encrypted data safely requires entry-level conflict detection, which could leak metadata about vault contents.

---

## Troubleshooting

### "OAuth token expired"

Re-run `pm cloud init [provider]` to re-authenticate.

### "Vault not found on provider"

Either the vault was never uploaded, or the retrieval key/file ID has changed. Try uploading again with `pm cloud sync`.

### "HMAC verification failed after download"

The downloaded vault may have been corrupted during transfer. Try downloading again. If the problem persists, the remote vault may have been tampered with.

---

## Next Steps

- **[Using .apmignore](apmignore.md)** — Filter what gets uploaded
- **[Sessions](sessions.md)** — Session management for sync workflows
- **[Cloud Sync Concepts](../concepts/cloud-sync.md)** — Deep technical details