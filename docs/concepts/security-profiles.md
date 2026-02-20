# Security profiles

APM allows users to select from pre-defined and custom encryption profiles to balance security
strength and unlock latency.

!!! note

    See the [encryption concept](./encryption.md) for details on the underlying cryptographic
    primitives — this document focuses on profile configuration.

## Pre-defined profiles

| Profile      | Memory     | Time (Iterations) | Parallelism | Nonce Size | Use Case                        |
| :----------- | :--------- | :---------------- | :---------- | :--------- | :------------------------------ |
| **Standard** | 64 MB      | 3                 | 2           | 12 bytes   | Default for most users          |
| **Hardened** | 256 MB     | 5                 | 4           | 12 bytes   | High-value credentials          |
| **Paranoid** | 512 MB     | 6                 | 4           | 24 bytes   | Maximum security, slower unlock |
| **Legacy**   | 0 (PBKDF2) | 600,000           | 1           | 12 bytes   | Backward compatibility only     |

### Selecting a profile

Switch to a different profile using `pm profile set`:

```console
$ pm profile set hardened
Security profile updated to "Hardened".
Vault re-encrypted with new parameters.
```

!!! important

    Changing the security profile re-derives all encryption keys and re-encrypts the entire vault.
    This operation requires the master password and may take several seconds depending on the
    selected profile.

### Listing profiles

View available profiles:

```console
$ pm profile list
  Standard  (active)
  Hardened
  Paranoid
  Legacy
  MyCustom
```

## Custom profiles

For advanced users, APM allows creating custom security profiles with specific Argon2id parameters.

### Creating a custom profile

Use `pm sec_profile create` for interactive tuning:

```console
$ pm sec_profile create
? Profile name: UltraSecure
? Memory (MB): 384
? Iterations: 8
? Parallelism: 4

Profile "UltraSecure" created.
Estimated unlock time: ~2.1s
```

### Parameter guidance

| Parameter       | Description                             | Impact                                       |
| :-------------- | :-------------------------------------- | :------------------------------------------- |
| **Memory**      | RAM required during key derivation (MB) | Higher = more GPU-resistant, slower unlock   |
| **Iterations**  | Number of Argon2id passes               | Higher = more CPU time, slower unlock        |
| **Parallelism** | Number of threads used                  | Higher = faster on multi-core, same security |

!!! tip

    As a general rule, set the memory as high as your system can comfortably handle, then
    adjust iterations until the unlock time is acceptable for your workflow. Parallelism should
    match your CPU core count.

## Legacy profile

The Legacy profile uses PBKDF2 instead of Argon2id for backward compatibility with older vault
formats. It is not recommended for new vaults:

- **PBKDF2** with 600,000 iterations
- **Not memory-hard**: vulnerable to GPU-based attacks
- **Single-threaded**: cannot leverage modern multi-core CPUs

!!! important

    If you are using the Legacy profile, consider migrating to Standard or higher. Use
    `pm profile set standard` to upgrade your vault's cryptographic parameters.

## Next steps

See the [encryption concept](./encryption.md) for the full cryptographic architecture, or learn
about the [policy engine](./policy-engine.md) for enforcing organizational security standards.
