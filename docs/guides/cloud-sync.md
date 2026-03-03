---
title: Cloud synchronization
description:
  A guide to syncing your APM vault across devices using Google Drive, GitHub, and Dropbox.
---

# Cloud synchronization

APM provides native multi-cloud synchronization to keep your vault available across all your trusted
devices. Three providers are supported: Google Drive, GitHub, and Dropbox.

## Provider comparison

| Feature             | Google Drive               | GitHub                      | Dropbox                    |
| :------------------ | :------------------------- | :-------------------------- | :------------------------- |
| **Authentication**  | OAuth2 (PKCE)              | Personal Access Token       | OAuth2 (PKCE)              |
| **Storage Type**    | Application Data Folder    | Private Repository          | Application Folder         |
| **Setup Speed**     | Instant                    | Manual (Token required)     | Instant                    |
| **Privacy Level**   | High (Isolated from files) | Exceptional (Git History)   | High (Isolated from files) |
| **Version History** | Limited (Drive native)     | Comprehensive (Git Commits) | Limited (Dropbox native)   |
| **Recommended For** | Mobile users and fast sync | Developers and power users  | Cross-platform persistence |

## Setting up Google Drive

Initialize Google Drive synchronization:

```console
$ pm cloud init gdrive
Launching browser for Google OAuth...
Authorization successful.
Google Drive sync initialized.
```

APM stores your vault in an isolated Application Data Folder that is not visible in your regular
Google Drive files.

## Setting up GitHub

Initialize GitHub synchronization:

```console
$ pm cloud init github
? GitHub Personal Access Token: ghp_xxxxxxxxxxxx
? Repository name: vault-backup

GitHub sync initialized.
```

!!! tip

    Use a dedicated private repository for vault storage. The vault file is always encrypted, but
    using a private repository adds an additional layer of access control.

## Setting up Dropbox

Initialize Dropbox synchronization:

```console
$ pm cloud init dropbox
Launching browser for Dropbox OAuth...
Authorization successful.
Dropbox sync initialized.
```

## Setting up all providers

Initialize all providers simultaneously:

```console
$ pm cloud init all
```

This runs the setup flow for each provider in sequence.

## Custom retrieval keys

During Google Drive and Dropbox setup, APM asks for explicit consent before storing a one-way hash
of a retrieval key in cloud metadata.

- If you consent, APM stores only `SHA-256(retrieval_key)` in provider metadata.
- If you decline, no retrieval-key hash is stored in cloud metadata. Recovery uses direct file
  identifiers (`file_id` for Drive, full Dropbox path for Dropbox).

## Sync and retrieval

Once a provider is configured, sync your vault with:

```console
$ pm cloud sync [gdrive|github|dropbox]
```

Retrieve from cloud with:

```console
$ pm cloud get [gdrive|github|dropbox] [retrieval_key|file_id|repo|path]
```

!!! important

    Cloud synchronization uploads the encrypted vault blob as-is. Your master password and plaintext
    entries are never sent to cloud providers.

## Conflict handling for offline edits

`pm cloud get` performs whole-vault conflict handling:

- If downloaded data matches local vault bytes, APM writes normally.
- If they differ, APM prompts you to:
  1. overwrite local vault with cloud copy,
  2. keep local vault and save cloud data as `vault.dat.conflict.<provider>.<timestamp>`,
  3. cancel.

APM does not perform entry-level merges.

## Next steps

See the [cloud sync concept](../concepts/cloud-sync.md) for details on the synchronization
architecture. Or, learn about [TOTP code generation](./totp.md).
