# Storage

APM stores encrypted and runtime data in a few key locations.

## Vault file

The primary encrypted vault path is controlled by `APM_VAULT_PATH`.

If not set, `vault.dat` is resolved next to the `pm` executable.

## Vault internals

The vault contains:

- secret entries by type
- spaces and current space pointer
- TOTP ordering and domain links
- autocomplete settings (`autocomplete_enabled`, `autocomplete_window_disabled`) and compressed vocab
- cloud metadata and provider tokens (encrypted within vault)
- plugin permission overrides

## Local project paths

Common directories near runtime root:

| Path | Purpose |
| :-- | :-- |
| `vault.dat` | Encrypted vault blob |
| `.apmignore` | Cloud-upload filtering rules |
| `policies/` | YAML policies |
| `plugins/` | Installed plugin directories (`plugin.json`) |
| `examples/` | Sample configs and plugins |

## Session artifacts

Session state is temporary and cleared on lock/expiry.

## Autofill daemon state

The autofill daemon keeps ephemeral local IPC state (loopback endpoint + token), and decrypted secrets remain memory-only while unlocked.

## Team storage

Team edition data is isolated from personal vault storage under `.apm-team`-style paths.
