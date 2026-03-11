# CLI Reference

Complete reference for every `pm` command. For flags and options, run `pm <command> --help`.

---

## Vault Lifecycle

### `pm init`

Initialize a new encrypted vault file.

```bash
pm init
```

Prompts for master password, security profile, and optional recovery email. Creates `vault.dat` in the current directory.

**Variant:**

```bash
pm init all
```

Initializes vault + cloud setup (all providers) in one flow.

---

### `pm unlock`

Start a session and decrypt the vault.

```bash
pm unlock
```

Prompts for master password, session duration, inactivity timeout, and optional read-only mode. Also unlocks the autofill daemon if running.

---

### `pm lock`

End the active session and wipe decrypted data.

```bash
pm lock
```

Destroys the session file and locks the autofill daemon.

---

## Entry Operations

### `pm add`

Add a new entry via the interactive type selector.

```bash
pm add
```

Presents a menu of 25+ entry types. Each type has a structured form with validated fields. Entries inherit the active space.

---

### `pm get [query]`

Search the vault with fuzzy matching.

```bash
pm get github
pm get "aws root"
pm get --show-pass
```

Returns an interactive browser with keyboard controls for viewing, copying, editing, and deleting.

---

### `pm edit [name]`

Edit an existing entry.

```bash
pm edit github
```

Opens an interactive editor showing current field values.

---

### `pm del [name]`

Delete an entry after confirmation.

```bash
pm del github
```

---

### `pm gen`

Generate a high-entropy password.

```bash
pm gen
```

Displays and copies the generated password to clipboard.

---

## Spaces

### `pm space create <name>`

```bash
pm space create Work
```

### `pm space list`

```bash
pm space list
```

### `pm space switch <name>`

```bash
pm space switch Work
```

### `pm space current`

```bash
pm space current
```

### `pm space remove <name>`

```bash
pm space remove Archive
```

---

## TOTP

### `pm totp`

Open the interactive TOTP list with live codes and countdown timers.

```bash
pm totp
```

### `pm totp <entry>`

Copy a specific TOTP code.

```bash
pm totp github
```

### `pm autocomplete link-totp`

Link a TOTP entry to a domain for autofill.

```bash
pm autocomplete link-totp
```

---

## Cloud Sync

### `pm cloud init [provider]`

Configure a cloud provider.

```bash
pm cloud init gdrive
pm cloud init github
pm cloud init dropbox
pm cloud init all
```

### `pm cloud sync [provider]`

Upload the vault to configured providers.

```bash
pm cloud sync
pm cloud sync gdrive
pm cloud sync github
pm cloud sync dropbox
```

### `pm cloud get [provider]`

Download the remote vault blob.

```bash
pm cloud get
pm cloud get gdrive
pm cloud get github
```

### `pm cloud autosync`

Run periodic sync loops.

```bash
pm cloud autosync
```

### `pm cloud reset`

Clear all cloud provider configuration.

```bash
pm cloud reset
```

---

## Notes & Vocabulary

### `pm vocab enable|disable|status`

Toggle vocabulary indexing.

```bash
pm vocab enable
pm vocab disable
pm vocab status
```

### `pm vocab`

List all indexed words with scores.

### `pm vocab alias <alias> <value>`

Create or update an alias.

```bash
pm vocab alias k8s kubernetes
```

### `pm vocab alias-list`

List all aliases.

### `pm vocab alias-remove <alias>`

Remove an alias.

```bash
pm vocab alias-remove k8s
```

### `pm vocab rank <word> <delta>`

Adjust a word's ranking score.

```bash
pm vocab rank deploy +5
pm vocab rank temp -3
```

### `pm vocab remove <word>`

Remove a word from the vocabulary.

```bash
pm vocab remove obsolete
```

### `pm vocab reindex`

Rebuild the vocabulary from current notes.

```bash
pm vocab reindex
```

---

## Autofill (Windows)

### `pm autofill start|stop|status`

```bash
pm autofill start
pm autofill start --hotkey "ctrl+alt+p"
pm autofill stop
pm autofill status
```

### `pm autofill list-profiles`

List all autofill profiles derived from vault entries.

### `pm autocomplete enable|disable`

Register or remove autostart.

```bash
pm autocomplete enable
pm autocomplete disable
```

### `pm autocomplete start|stop|status`

Manual daemon control.

### `pm autocomplete window enable|disable|status`

Toggle popup hints.

---

## Sessions

### `pm session issue`

Issue an ephemeral delegated session.

```bash
pm session issue --label "CI" --scope read --ttl 15m --bind-host
```

### `pm session list`

List active ephemeral sessions.

### `pm session revoke <id>`

Revoke an ephemeral session.

---

## Authentication & Recovery

### `pm auth email [address]`

Set recovery email.

```bash
pm auth email user@example.com
```

### `pm auth alerts`

Toggle security alerts.

### `pm auth level [1-3]`

Set security level.

```bash
pm auth level 2
```

### `pm auth recover`

Initiate account recovery.

### `pm auth reset`

Reset authentication configuration.

### `pm auth change`

Change master password.

---

## MCP

### `pm mcp token`

Generate a new MCP token with permission scopes.

### `pm mcp serve`

Start the MCP server (spawned by AI clients).

```bash
pm mcp serve --token TOKEN
```

### `pm mcp list`

List all MCP tokens.

### `pm mcp revoke [name_or_token]`

Revoke an MCP token.

### `pm mcp config`

Output configuration hints for known AI clients.

---

## Plugins

### `pm plugins market`

Browse the plugin marketplace.

### `pm plugins search <query>`

Search the marketplace.

### `pm plugins install <name>`

Install a plugin from the marketplace.

### `pm plugins installed`

List locally installed plugins.

### `pm plugins local <path>`

Install a plugin from a local directory.

### `pm plugins push <name>`

Publish a plugin to the marketplace.

### `pm plugins access`

Show permission overrides for all plugins. Interactive space-key toggle list for enabling/disabling permissions.

### `pm plugins access <plugin> <permission> on|off`

Toggle a specific permission.

---

## Security & Profiles

### `pm profile`

Interactive profile management for changing encryption parameters.

### `pm cinfo`

Display cryptographic information (profile, parameters, vault version).

---

## Health & Trust

### `pm health`

Run vault health checks and display a score.

### `pm trust`

Show per-secret trust/risk scoring.

---

## Audit

### `pm audit`

View the audit log.

---

## Brute Force Testing

### `pm brutetest [minutes]`

Run a brute-force simulation against the vault.

```bash
pm brutetest 5
```

---

## Import & Export

### `pm import <format> [file]`

```bash
pm import json backup.json
pm import csv passwords.csv
pm import txt vault.txt
```

### `pm export <format>`

```bash
pm export json
pm export json --encrypt
pm export csv
pm export txt
pm export txt --no-password
```

---

## Utility

### `pm info`

Display version and environment info.

### `pm update`

Self-update the binary.

### `pm policy load <dir>`

Load YAML policy files from a directory.

```bash
pm policy load ./policies/
```
