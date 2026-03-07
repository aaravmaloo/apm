# APM architecture

This page describes APM internals at a system level.

## High-level layers

1. CLI layer (`main.go`)
2. Domain layer (`src/` vault, crypto, entries, policies, sync)
3. Integration layer (cloud providers, autofill daemon, MCP server)
4. Extension layer (manifest plugins)

## Vault data flow

1. Unlock: encrypted vault bytes are loaded from disk.
2. KDF: Argon2id derives encryption/auth keys.
3. Decrypt: AES-GCM decrypts serialized vault payload.
4. In-memory operations: add/get/edit/search/reindex.
5. Save: vault re-encrypted and persisted.

## Security boundaries

- Encrypted-at-rest vault file
- Session-scoped unlock state
- Read-only session mode
- Memory wipe on lock for primary secret fields
- Local-only daemon IPC (loopback + bearer token)

## Space model

Entries are partitioned by `space` labels.

- `CurrentSpace` drives most interactive operations
- `.apmignore` can exclude full spaces from cloud payloads

## Cloud sync path

On upload:

1. Load active vault object
2. Load `.apmignore`
3. Clone + filter vault for provider
4. Re-encrypt filtered vault to temporary file
5. Upload to provider API

This ensures ignored entries are never serialized into cloud payloads.

## Autofill architecture (Windows)

- `pm autofill start` launches daemon
- daemon listens on local HTTP endpoint
- hotkey engine captures `CTRL+SHIFT+L`
- active-window context + UI hints feed intelligent candidate scoring
- sequence renderer emits actions (`{USERNAME}`, `{PASSWORD}`, `{TOTP}`, `{TAB}`, `{ENTER}`)
- system engine sends keystrokes

Background context watcher triggers user popup hints for entry detection and autocomplete availability.

## Notes autocomplete architecture

- vocab stored in `Vault.VocabCompressed` (gzip-compressed JSON)
- enabling autocomplete triggers full reindex from secure notes
- note edits/additions/deletions trigger reindex when enabled
- suggestion ranking updates from accept/dismiss feedback
- alias replacement can run on space while editing notes

## TOTP architecture

- `Vault.TOTPEntries` stores TOTP secrets
- `Vault.TOTPOrder` stores interactive ordering
- `Vault.TOTPDomainLinks` maps domains to preferred TOTP account names
- `pm totp` interactive list supports copy and reordering
- `pm totp <entry_name>` performs fast lookup + copy

## Plugin architecture

APM plugins are manifest-driven (`plugin.json`) and loaded from local plugin folders.

Permissions are declared per plugin and governed by runtime toggles in `pm plugins access`.

## MCP architecture

- Token-scoped tool access
- Vault operations exposed as MCP tools
- Optional plugin listing/install endpoints (depending on plugin manager availability)

## Major directories

- `src/` core implementation
- `src/autofill` daemon + matching + system engine
- `src/tui` terminal UI
- `plugins/` installed plugin directories (manifest-based)
- `examples/` sample plugin and policy files
- `docs/` documentation
