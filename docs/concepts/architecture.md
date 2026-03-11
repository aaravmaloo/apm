# Architecture

APM is layered to separate CLI interaction, domain logic, and integrations.

## Layers

1. CLI layer in `main.go` provides the user-facing command tree.
2. Domain layer in `src/` implements vault, entries, crypto, policy, and sync.
3. Integration layer contains cloud providers, autofill daemon, and MCP server.
4. Extension layer supports manifest-based plugins.

## Vault flow

- Encrypted vault bytes are loaded from disk.
- Argon2id derives encryption and authentication keys.
- AES-GCM decrypts the vault payload.
- Operations run in memory within a session.
- The vault is re-encrypted and persisted on save.

## Autofill subsystem

- Windows daemon runs locally on loopback.
- Active window context is captured and analyzed.
- Popup hints notify users when matches exist.
- Hotkey triggers sequence injection.

## Notes vocabulary subsystem

- Vocabulary is stored in `Vault.VocabCompressed`.
- Indexing runs on note changes if enabled.
- Alias and ranking influence suggestion output.

## Plugin subsystem

- `plugin.json` declares metadata, permissions, commands, and hooks.
- Runtime permission overrides are enforced for every step.