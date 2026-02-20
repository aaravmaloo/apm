# Cloud synchronization

APM provides native multi-cloud synchronization to keep your vault available across all your trusted
devices. The vault is always encrypted before transmission — cloud providers never see your
plaintext data.

!!! note

    See the [cloud sync guide](../guides/cloud-sync.md) for an introduction to setting up cloud
    providers — this document discusses the synchronization architecture.

## Architecture

Cloud sync in APM follows a simple push/pull model:

```text
[Local Vault] --encrypt--> [Encrypted Blob] --upload--> [Cloud Provider]
[Cloud Provider] --download--> [Encrypted Blob] --decrypt--> [Local Vault]
```

The encrypted vault file is transmitted as an opaque binary blob. No metadata, entry names, or
structural information is visible to the cloud provider.

## Supported providers

### Google Drive

| Property             | Value                                      |
| :------------------- | :----------------------------------------- |
| **Authentication**   | OAuth2 with PKCE flow                      |
| **Storage location** | Application Data Folder (hidden from user) |
| **Version history**  | Limited (Drive's built-in versioning)      |
| **Setup**            | `pm cloud init gdrive`                     |

APM uses an embedded OAuth flow — no external `credentials.json` or `token.json` files are
required. Authentication is handled through an obfuscated internal layer.

### GitHub

| Property             | Value                                  |
| :------------------- | :------------------------------------- |
| **Authentication**   | Personal Access Token                  |
| **Storage location** | Private repository (configurable name) |
| **Version history**  | Comprehensive (full Git history)       |
| **Setup**            | `pm cloud init github`                 |

GitHub sync stores the vault as a file in a private repository, providing full version history
through Git commits. This makes it ideal for developers who want granular rollback capability.

### Dropbox

| Property             | Value                                   |
| :------------------- | :-------------------------------------- |
| **Authentication**   | OAuth2 with PKCE flow                   |
| **Storage location** | Application Folder (isolated)           |
| **Version history**  | Limited (Dropbox's built-in versioning) |
| **Setup**            | `pm cloud init dropbox`                 |

## Conflict resolution

When pulling from a cloud provider, APM detects if the remote vault is newer than the local copy:

- If the remote vault is newer, it replaces the local vault.
- If the local vault is newer, the pull is skipped with a warning.
- If both have been modified, APM prompts the user to choose which version to keep.

!!! important

    APM does not perform entry-level merging. Conflict resolution operates on the entire vault
    file. For collaborative use cases, see the [team edition](../team/index.md).

## Token security

OAuth tokens and Personal Access Tokens are encrypted inside the vault itself using the same
AES-256-GCM encryption as your secrets. They are never stored in plaintext on disk.

## Next steps

See the [cloud sync guide](../guides/cloud-sync.md) for setup instructions, or learn about the
[plugin architecture](./plugins.md).
