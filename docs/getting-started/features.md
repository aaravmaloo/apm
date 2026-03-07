# Features

APM combines secure vaulting, context-aware retrieval, and automation tooling for personal and team workflows.

## Vault management

- `pm add`
- `pm get [query]`
- `pm get --show-pass`
- `pm gen`

`pm get` now hides sensitive values by default and supports quicklook for notes and photos.

## Sessions and lock model

- `pm unlock`
- `pm lock`
- `pm session issue`

Unlock/lock also synchronizes the autofill daemon lock state.

## TOTP

- `pm totp` interactive list + copy
- `pm totp <entry_name>` direct copy
- `Shift+Up/Down` reorder entries in the interactive list

## Cloud sync

- `pm cloud init`
- `pm cloud sync`
- `pm cloud autosync`

Cloud uploads honor `.apmignore` rules.

## `.apmignore` support

- ignore complete spaces
- ignore space/type/name patterns (wildcards supported)
- per-provider ignore rules
- vocab-only ignore or strip via `[misc]`

See [APM ignore guide](../guides/apmignore.md).

## Notes autocomplete and vocab

- `pm auth autocomplete true|false`
- `pm vocab`
- `pm vocab alias`
- `pm vocab rank`
- `pm vocab remove`
- `pm vocab reindex`

Vocab is stored in the vault in compressed form.

## Autofill daemon

- `pm autofill start|stop|status|list-profiles`
- background context hints + popup notifications on Windows
- default hotkey: `CTRL+SHIFT+L`

## Plugins

- legacy `plugin.json` plugin architecture
- examples under `examples/plugins/`
- permission toggles via `pm plugins access`

## MCP

- `pm mcp token`
- `pm mcp serve`
- `pm mcp config`

## Team edition

- organization, department, role, and approval workflows in `pm-team`
