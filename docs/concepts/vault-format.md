# Vault format

APM stores all secrets in a single encrypted vault file using the **V4 format**. This document
describes the on-disk structure.

!!! note

    See the [encryption concept](./encryption.md) for details on the cryptographic primitives
    used — this document focuses on the file format.

## File location

The default vault file location is platform-dependent:

=== "Windows"

    ```
    %USERPROFILE%\.apm\vault.dat
    ```

=== "macOS and Linux"

    ```
    ~/.apm/vault.dat
    ```

The location can be overridden with the `APM_VAULT_PATH` environment variable. See the
[environment variables reference](../reference/environment-variables.md) for details.

## V4 structure

The vault file consists of two layers:

### Unencrypted header (signed)

The header contains metadata necessary for vault operations without requiring decryption:

| Field             | Size        | Description                                |
| :---------------- | :---------- | :----------------------------------------- |
| Magic bytes       | 4 bytes     | File type identifier (`APM4`)              |
| Version           | 1 byte      | Format version (currently `4`)             |
| KDF parameters    | Variable    | Argon2id memory, iterations, parallelism   |
| Salt              | 32 bytes    | Random salt for key derivation             |
| Nonce             | 12-24 bytes | Unique nonce for this encryption cycle     |
| Recovery metadata | Variable    | Hashed recovery tokens and obfuscated keys |
| HMAC signature    | 32 bytes    | HMAC-SHA256 over the entire header         |

!!! important

    The header is not encrypted, but it is signed. Any modification to the header will be
    detected by the HMAC verification on unlock, preventing parameter downgrade attacks.

### Encrypted payload

The payload contains all vault entries encrypted with AES-256-GCM:

| Field              | Description                                                                |
| :----------------- | :------------------------------------------------------------------------- |
| Entries            | Array of structured secret entries (see [secret types](./secret-types.md)) |
| Namespace metadata | Namespace assignments and labels                                           |
| Audit log          | Tamper-evident interaction history                                         |
| Plugin data        | Plugin-specific storage                                                    |

## Atomic saves

Vault modifications use an atomic write pattern:

1. Write the new vault to a temporary file.
2. Verify the temporary file is valid and complete.
3. Atomically replace the old vault with the new one.

This prevents data corruption during power loss or process termination.

## Recovery key storage

Recovery keys are stored using XOR-obfuscation within the vault header, preventing simple memory
dumps from exposing them. See the [recovery concept](./recovery.md) for the full recovery flow.

## Next steps

See the [secret types](./secret-types.md) for details on what data structures are stored in the
payload, or learn about [security profiles](./security-profiles.md) that control KDF parameters.
