---
title: Managing your vault
description:
  A guide to creating, storing, searching, editing, and deleting secrets in your APM vault.
---

# Managing your vault

APM manages an encrypted vault that stores all your credentials locally with zero-knowledge
encryption.

## Initializing a vault

Create a new encrypted vault with `pm init`:

```console
$ pm init
? Set a Master Password: ********
? Confirm Master Password: ********
? Set a Recovery Key (optional): ********

Vault initialized successfully.
```

This creates a new vault file encrypted with your master password using Argon2id key derivation and
AES-256-GCM authenticated encryption. See the [encryption concept](../concepts/encryption.md) for
details on the cryptographic architecture.

!!! important

    Your master password is never stored anywhere. APM uses a zero-knowledge architecture — if you
    lose your master password and recovery key, your data cannot be recovered.

## Adding entries

Store a new secret using `pm add`:

```console
$ pm add
? Select category: Password
? Account name: GitHub
? Username: aarav@example.com
? Password: ********

Entry added successfully.
```

APM supports [22 different secret types](../concepts/secret-types.md), including passwords, API
keys, SSH keys, TOTP seeds, certificates, and more. The interactive menu guides you through the
fields specific to each category.

## Searching and retrieving entries

Use `pm get` with a fuzzy search query to find entries:

```console
$ pm get github
+----------+----------------------+
| Account  | GitHub               |
| Username | aarav@example.com    |
| Category | Password             |
+----------+----------------------+
```

By default, secrets are hidden. Use the `--show-pass` flag to reveal them:

```console
$ pm get github --show-pass
+----------+----------------------+
| Account  | GitHub               |
| Username | aarav@example.com    |
| Password | s3cureP@ssw0rd!      |
| Category | Password             |
+----------+----------------------+
```

## Editing entries

Modify an existing entry using `pm edit`:

```console
$ pm edit GitHub
? Which field to edit: Username
? New value: newuser@example.com

Entry updated successfully.
```

## Deleting entries

Permanently remove an entry using `pm del`:

```console
$ pm del GitHub
? Confirm deletion of "GitHub"? Yes

Entry deleted.
```

!!! important

    Deletion is permanent. Consider using `pm export` to create a backup before deleting entries.

## Generating passwords

APM includes a high-entropy password generator:

```console
$ pm gen
Generated: x#9Kp!mR2$vL@nQ7

Copied to clipboard.
```

The generator produces cryptographically secure passwords suitable for any service.

## Using namespaces

APM supports namespaces (spaces) to organize secrets into isolated compartments:

```console
$ pm space create Work
Namespace "Work" created.

$ pm space switch Work
Switched to namespace "Work".

$ pm space list
  Personal (default)
> Work
  DevOps
```

Namespaces allow you to separate Work, Personal, and Project-specific secrets within a single
encrypted vault.

## Using the setup wizard

For first-time users, APM provides a guided setup wizard:

```console
$ pm setup
Welcome to APM Setup Wizard!

Step 1/3: Vault Initialization
? Set a Master Password: ********
...

Step 2/3: Cloud Sync (optional)
? Enable cloud sync? Yes
...

Step 3/3: Profile Creation
? Create a namespace? Yes
...

Setup complete!
```

## Next steps

To learn more about vault management, see the [vault format concept](../concepts/vault-format.md)
and the [command reference](../reference/cli.md).

Or, read on to learn how to [sync your vault across devices](./cloud-sync.md).
