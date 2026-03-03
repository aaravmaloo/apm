# Cloud synchronization

APM provides native multi-cloud synchronization to keep your vault available across trusted
devices. The vault blob is encrypted before transmission, so cloud providers do not see plaintext
entries.

!!! note

    See the [cloud sync guide](../guides/cloud-sync.md) for setup instructions. This page focuses
    on architecture and safeguards.

## Architecture

Cloud sync uses whole-vault upload and download:

```text
[Local Vault] --encrypt--> [Encrypted Blob] --upload--> [Cloud Provider]
[Cloud Provider] --download--> [Encrypted Blob] --decrypt--> [Local Vault]
```

Providers store an opaque encrypted blob, plus provider-managed object metadata such as file ID,
repository/path, and optional retrieval-key hash metadata when user consent is granted.

## Encryption guarantees

- Vault payload remains encrypted end-to-end using APM vault encryption.
- Master password is never sent to cloud providers.
- OAuth/PAT credentials are stored inside the encrypted vault, not plaintext files.

## Retrieval-key metadata consent

Google Drive and Dropbox support retrieval-key indexing.

- With consent: APM stores only `SHA-256(retrieval_key)` in provider metadata.
- Without consent: no retrieval-key hash is written to cloud metadata.
- Without metadata hashing, recovery still works via direct identifiers:
  Google Drive `file_id` or Dropbox full file path.

## Conflict resolution behavior

Conflict handling is whole-vault and user-mediated during `pm cloud get`.

- If cloud and local vault bytes differ, APM prompts to overwrite local, save a conflict copy, or
  cancel.
- Conflict copies are written as `vault.dat.conflict.<provider>.<timestamp>`.
- Entry-level/field-level merges are out of scope for personal cloud sync.

For concurrent collaborative edits, use the [team edition](../team/index.md).

## Supported providers

### Google Drive

| Property             | Value                                      |
| :------------------- | :----------------------------------------- |
| **Authentication**   | OAuth2 with PKCE flow                      |
| **Storage location** | App Data folder or user drive (mode-based) |
| **Setup**            | `pm cloud init gdrive`                     |

### GitHub

| Property             | Value                                  |
| :------------------- | :------------------------------------- |
| **Authentication**   | Personal Access Token / OAuth2 token   |
| **Storage location** | Private repository file (`vault.dat`)  |
| **Setup**            | `pm cloud init github`                 |

### Dropbox

| Property             | Value                                   |
| :------------------- | :-------------------------------------- |
| **Authentication**   | OAuth2 flow                             |
| **Storage location** | App folder / self-hosted app            |
| **Setup**            | `pm cloud init dropbox`                 |

## Next steps

See the [cloud sync guide](../guides/cloud-sync.md) for operational commands.
