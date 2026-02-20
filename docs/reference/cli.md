# CLI reference

APM provides a comprehensive set of commands for managing secrets, sessions, cloud sync, plugins,
and more.

## Core commands

### pm init

Initialize a new encrypted vault.

```console
$ pm init
```

Creates the vault file, prompts for a master password, and optionally sets a recovery key. If a
vault already exists, the command exits with an error.

### pm add

Add a new entry to the vault.

```console
$ pm add
```

Launches an interactive prompt to select a category, fill in fields, and encrypt the entry. The
active [policy](../concepts/policy-engine.md) is enforced during entry creation.

### pm get

Search and retrieve an entry.

```console
$ pm get <query> [--show-pass]
```

| Flag          | Description                                    |
| :------------ | :--------------------------------------------- |
| `<query>`     | Fuzzy search term to match against entry names |
| `--show-pass` | Reveal secret fields in the output             |

### pm edit

Modify an existing entry.

```console
$ pm edit <name>
```

Opens an interactive editor to change individual fields of the matched entry.

### pm del

Delete an entry permanently.

```console
$ pm del <name>
```

Prompts for confirmation before removing the entry from the vault.

### pm gen

Generate a high-entropy random password.

```console
$ pm gen
```

Produces a cryptographically secure password and copies it to the clipboard.

## Session commands

### pm unlock

Start a new session by entering the master password.

```console
$ pm unlock
```

Derives encryption keys, validates them, and caches the session for subsequent commands.

### pm lock

Terminate the active session and wipe keys from memory.

```console
$ pm lock
```

### pm readonly

Toggle read-only mode for the current session.

```console
$ pm readonly
```

## Cloud commands

### pm cloud init

Initialize a cloud sync provider.

```console
$ pm cloud init <provider> [--key <retrieval-key>]
```

| Argument     | Description                             |
| :----------- | :-------------------------------------- |
| `<provider>` | `gdrive`, `github`, `dropbox`, or `all` |
| `--key`      | Optional custom retrieval key           |

### pm cloud push

Upload the encrypted vault to the configured provider(s).

```console
$ pm cloud push
```

### pm cloud pull

Download the vault from the configured provider(s).

```console
$ pm cloud pull
```

## TOTP commands

### pm totp show

Generate and display a TOTP code with a live countdown.

```console
$ pm totp show
```

## Namespace commands

### pm space create

Create a new namespace.

```console
$ pm space create <name>
```

### pm space switch

Switch to a different namespace.

```console
$ pm space switch <name>
```

### pm space list

List all available namespaces.

```console
$ pm space list
```

## Security commands

### pm health

Run a vault health audit against the active policy.

```console
$ pm health
```

### pm cinfo

Display cryptographic parameters for the current vault.

```console
$ pm cinfo
```

### pm profile set

Switch the security profile.

```console
$ pm profile set <profile>
```

### pm profile list

List available security profiles.

```console
$ pm profile list
```

### pm sec_profile create

Create a custom security profile with specific Argon2id parameters.

```console
$ pm sec_profile create
```

## Policy commands

### pm policy load

Load a YAML policy file.

```console
$ pm policy load <path>
```

### pm policy show

Display the active policy.

```console
$ pm policy show
```

### pm policy clear

Remove the active policy.

```console
$ pm policy clear
```

## Auth commands

### pm auth email

Update the registered recovery email address.

```console
$ pm auth email
```

### pm auth reset

Reset the master password (requires the current password).

```console
$ pm auth reset
```

### pm auth change

Change the master password.

```console
$ pm auth change
```

### pm auth recover

Initiate the recovery flow.

```console
$ pm auth recover
```

## MCP commands

### pm mcp serve

Start the MCP server.

```console
$ pm mcp serve --token <token>
```

### pm mcp token

Generate a new MCP access token with selected permission scopes.

```console
$ pm mcp token
```

### pm mcp config

Display a copy-pasteable MCP client configuration snippet.

```console
$ pm mcp config
```

## Plugin commands

### pm plugins add

Install a plugin from the marketplace.

```console
$ pm plugins add <name>
```

### pm plugins local

Load a plugin from a local directory.

```console
$ pm plugins local <path>
```

### pm plugins list

List installed plugins.

```console
$ pm plugins list
```

### pm plugins remove

Uninstall a plugin.

```console
$ pm plugins remove <name>
```

## Import / Export commands

### pm import

Import entries from an external file.

```console
$ pm import <path>
```

### pm export

Export vault entries.

```console
$ pm export [--format <format>] [--encrypted]
```

| Flag          | Description                        |
| :------------ | :--------------------------------- |
| `--format`    | Output format: `json` or `csv`     |
| `--encrypted` | Export as an encrypted APM archive |

## Utility commands

### pm setup

Launch the interactive first-time setup wizard.

```console
$ pm setup
```

### pm audit

View the tamper-evident audit log.

```console
$ pm audit
```

### pm version

Display the installed APM version.

```console
$ pm version
```

### pm help

Display help for any command.

```console
$ pm help [command]
```
