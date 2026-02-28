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

Interactive `pm get` actions:
- `v` / Enter: View entry details
- `i`: Show entry metadata (created/accessed timestamps, actor/source, trust factors, history totals)
- `e`: Edit
- `d`: Delete
- `space`: Multi-select mode for bulk actions

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

### pm session issue

Issue an ephemeral, context-bound session token for delegated access.

```console
$ pm session issue --ttl 15m --scope read --agent mcp
```

### pm session list

List active ephemeral sessions.

```console
$ pm session list
```

### pm session revoke

Revoke an ephemeral session immediately.

```console
$ pm session revoke <id>
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

### pm trust

Show per-secret trust scores and risk reasons.

```console
$ pm trust
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

Register or update the recovery email address with inbox ownership verification.

```console
$ pm auth email user@example.com
```

Flow:
- Sends a 6-digit verification code to the target email.
- Requires the code in-terminal before the address is stored.
- Generates and displays a new recovery key after successful verification.
- Sends styled HTML emails (with plaintext fallback) for verification and security alerts.

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

Recovery sequence:
- Confirm registered recovery email.
- Receive a 6-digit verification code by email.
- Verify recovery key first.
- Enter the email code.
- If configured, complete passkey or one-time recovery code challenge.
- All recovery email notifications use the unified APM HTML template (plus plaintext fallback).

If configured, recovery now supports additional factors:
- WebAuthn passkey verification
- One-time recovery codes

### pm auth quorum-setup

Configure threshold recovery shares for multi-party recovery.

```console
$ pm auth quorum-setup --threshold 2 --shares 3
```

If your vault cannot auto-resolve the recovery key, provide it explicitly:

```console
$ pm auth quorum-setup --threshold 2 --shares 3 --key "R9H4-R8F6-JSPC-6749"
```

### pm auth quorum-recover

Recover using trustee shares instead of a single recovery key holder.

```console
$ pm auth quorum-recover
```

### pm auth passkey register

Register a WebAuthn passkey for recovery.

```console
$ pm auth passkey register
```

Requires:
- A browser on the same machine
- A platform authenticator (e.g., Windows Hello / Touch ID) or security key

### pm auth passkey verify

Verify the configured recovery passkey.

```console
$ pm auth passkey verify
```

### pm auth passkey disable

Disable passkey recovery factor.

```console
$ pm auth passkey disable
```

### pm auth codes generate

Generate one-time recovery codes.

```console
$ pm auth codes generate --count 10
```

### pm auth codes status

Show remaining one-time recovery codes.

```console
$ pm auth codes status
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

### pm plugins push

Push a local or installed plugin to the Google Drive marketplace.

```console
$ pm plugins push <name> [--path <local-plugin-dir>]
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
