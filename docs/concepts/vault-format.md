# Vault format

APM stores all secrets in a single encrypted vault blob (current format version: V4).

## File location

Vault path is controlled by `APM_VAULT_PATH`. If unset, APM resolves `vault.dat` near the executable.

## Logical model

The vault payload is a structured object encrypted as one unit. Key groups include:

- entry collections by type (`entries`, `totp_entries`, `secure_notes`, media, infra secrets)
- space metadata (`spaces`, `current_space`)
- policy state (`active_policy`)
- cloud metadata (provider ids/tokens encrypted inside vault)
- audit/history records
- autocomplete data (`autocomplete_enabled`, `autocomplete_window_disabled`, `vocab_compressed`)
- TOTP metadata (`totp_order`, `totp_domain_links`)
- plugin access controls (`plugin_permission_overrides`)

## Security model

- Vault content is encrypted at rest.
- Decryption requires master-password-derived keys.
- Locking clears in-memory secret values for primary sensitive fields.

See [Encryption](./encryption.md) for cryptographic details.

## Cloud upload filtering

Cloud sync can serialize a filtered vault variant via `.apmignore` rules before upload.

This filtering does not mutate your local vault; it only affects upload payload generation.

## Vocabulary compression

Notes autocomplete vocabulary is compressed and stored in `vocab_compressed` to reduce on-disk footprint.

## Compatibility note

When new metadata fields are added, APM keeps backward compatibility handling in decryption/repair logic where feasible.
