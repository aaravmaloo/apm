# CLI reference

This page documents primary APM commands for the current CLI behavior.

## Global usage

```console
$ pm [command] [flags]
```

Global flag:

- `--vault, -v <path>`: override vault file path

## Core vault commands

### `pm add`

Interactive add flow for supported entry categories.

### `pm get [query]`

Interactive search and management.

Key behavior:

- hides sensitive values by default
- reveals sensitive values only with `--show-pass`
- quicklook on `Space` for notes/photos
- multi-select toggle on `s`

Flags:

```console
$ pm get --show-pass
```

### `pm gen`

Generate passwords.

### `pm unlock`

Unlock vault session and unlock autofill daemon state.

Flags:

- `--timeout` (default `1h`)
- `--inactivity` (default `15m`)

### `pm lock`

Lock vault session and autofill daemon state.

## TOTP commands

### `pm totp`

Interactive TOTP list with copy support.

Controls:

- `Enter`: copy selected code
- `1-9`: quick copy by index
- `Shift+Up/Shift+Down`: reorder entries

### `pm totp <entry_name>`

Copy matching TOTP code directly.

## Spaces

- `pm space list`
- `pm space create <name>`
- `pm space switch <name>`
- `pm space remove <name>`

## Cloud sync

- `pm cloud init`
- `pm cloud sync`
- `pm cloud autosync`
- `pm cloud get`
- `pm cloud reset`

Cloud upload payloads are filtered by `.apmignore` if present.

## Autofill and autocomplete

### `pm autofill start`

Start Windows/system autofill daemon.

### `pm autocomplete enable`

Register autocomplete daemon autostart on Windows and start it immediately.

### `pm autocomplete disable`

Disable autocomplete daemon autostart and stop the daemon.

### `pm autocomplete start`

Start the autocomplete daemon manually.

### `pm autocomplete stop`

Stop the autocomplete daemon manually.

### `pm autocomplete status`

Show autocomplete daemon status and autostart state.

### `pm autocomplete window enable|disable|status`

Enable/disable the Windows popup hints for autocomplete availability.

### `pm autofill stop`

Stop daemon.

### `pm autofill status`

Show daemon status.

### `pm autofill list-profiles`

List profiles known by daemon.

### `pm autocomplete link-totp`

Link domain to existing TOTP entry id for intelligent OTP autofill.

## Notes autocomplete and vocab

### `pm vocab enable|disable|status`

Enable/disable notes autocomplete indexing and show status.

### `pm vocab`

Show vocabulary words and alias state.

### `pm vocab alias`

Create/update an alias.

### `pm vocab alias-list`

List aliases.

### `pm vocab alias-remove <alias>`

Remove alias.

### `pm vocab rank <word> <delta>`

Adjust rank manually.

### `pm vocab remove <word>`

Delete vocab word.

### `pm vocab reindex`

Rebuild vocabulary index from notes.

## Plugin commands

APM plugins use legacy `plugin.json` manifests.

### `pm plugins market`

List marketplace plugins.

### `pm plugins install <name>`

Install plugin from marketplace.

### `pm plugins push <name> [--path <dir>]`

Publish local `plugin.json` plugin directory to marketplace.

### `pm plugins installed`

List locally loaded plugins.

### `pm plugins access`

Show plugin permissions and ON/OFF states.

### `pm plugins access <plugin> <permission> <on|off>`

Toggle one permission override.

## Policy commands

- `pm policy load <file>`
- `pm policy show`
- `pm policy clear`

## Session delegation

- `pm session issue`
- `pm session list`
- `pm session revoke <id>`

## MCP commands

- `pm mcp token`
- `pm mcp serve`
- `pm mcp config`

## Utility

- `pm info`
- `pm health`
- `pm trust`
- `pm update`
- `pm setup`
