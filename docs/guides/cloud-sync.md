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

You can set a custom retrieval key during initialization:

```console
$ pm cloud init gdrive --key my-vault-key
```

Or provide one interactively when prompted.

## Pushing and pulling

Once a provider is configured, sync your vault:

```console
$ pm cloud push
Vault uploaded to Google Drive.
```

```console
$ pm cloud pull
Vault downloaded and merged.
```

!!! important

    Cloud synchronization uploads your encrypted vault file. Your master password and decryption
    keys are never transmitted. The cloud provider only ever sees encrypted data.

## Next steps

See the [cloud sync concept](../concepts/cloud-sync.md) for details on the synchronization
architecture. Or, learn about [TOTP code generation](./totp.md).
