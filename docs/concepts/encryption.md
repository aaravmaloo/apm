# Encryption

APM uses industry-standard, high-performance cryptographic primitives designed to withstand modern
attack vectors, including high-end GPU clusters and dictionary attacks.

!!! note

    See the [vault management guide](../guides/vault-management.md) for an introduction to
    working with the vault — this document discusses the cryptographic internals.

## Key derivation: Argon2id

The master password is never stored. Keys are derived using **Argon2id**, the winner of the
Password Hashing Competition.

### How it works

Argon2id is a memory-hard key derivation function that combines the advantages of Argon2i (data-
independent memory access, resistant to side-channel attacks) and Argon2d (data-dependent memory
access, resistant to GPU cracking).

When you enter your master password, APM derives **96 bytes** of key material using Argon2id. This
material is split into three distinct 32-byte keys:

| Key                           | Purpose               | Usage                                      |
| :---------------------------- | :-------------------- | :----------------------------------------- |
| Encryption Key (32 bytes)     | Data confidentiality  | AES-256-GCM encryption of vault entries    |
| Authentication Key (32 bytes) | Data integrity        | HMAC-SHA256 signature over the vault file  |
| Validation Key (32 bytes)     | Password verification | Confirms correct master password on unlock |

### Memory-hard properties

Argon2id requires significant RAM during key derivation, making it extremely expensive to attack
with GPU or ASIC hardware:

- **Default**: 64 MB of RAM per derivation
- **Configurable**: Up to 512 MB via [security profiles](./security-profiles.md)
- **Parallelism**: Multi-threaded derivation for faster unlock on modern CPUs

## Authenticated encryption: AES-256-GCM

Confidentiality and integrity are provided by **AES-256** in **GCM (Galois/Counter Mode)**.

### Authenticated encryption

GCM mode provides both encryption and authentication in a single pass. This means that APM can
detect if any part of the encrypted vault has been modified, corrupted, or tampered with — the
decryption will fail with an authentication error rather than silently producing garbage data.

### Double-layer integrity

Beyond GCM's built-in authentication tag, APM applies an additional **HMAC-SHA256** signature over
the entire vault file. This signature is derived from the master password and covers all metadata,
providing defense-in-depth against sophisticated tampering attacks.

### Nonce integrity

Every save operation generates a unique, cryptographically random nonce matched to the encryption
operation. This prevents:

- **Replay attacks**: Re-submitting an older version of the vault.
- **Pattern analysis**: Detecting whether the same data was encrypted twice.

## Threat model

| Vector              | Status        | Mitigation                                                                 |
| :------------------ | :------------ | :------------------------------------------------------------------------- |
| Offline Brute-Force | Protected     | Argon2id high-cost derivation                                              |
| Vault Tampering     | Protected     | HMAC-SHA256 integrity signature across all metadata                        |
| Credential Theft    | Protected     | Cloud tokens are encrypted inside the vault                                |
| Identity Spoofing   | Protected     | Multi-factor recovery (Email -> Secure Token -> Recovery Key)              |
| Session Hijacking   | Protected     | Shell-scoped sessions (`APM_SESSION_ID`) and inactivity timeouts           |
| Weak Passwords      | Controlled    | Enforceable password policies via YAML [Policy Engine](./policy-engine.md) |
| Compromised Host    | Not Protected | Outside the security boundary (Keyloggers/Malware)                         |

!!! note

    APM is designed to protect your secrets at rest and during transit to cloud providers. It
    cannot protect against a fully compromised host machine where an attacker has kernel-level
    access or has installed keylogging software.

## Cryptographic inspection

You can inspect the current cryptographic parameters of your vault at any time:

```console
$ pm cinfo
Cipher: AES-256-GCM
KDF: Argon2id
Memory: 64 MB
Iterations: 3
Parallelism: 2
Nonce Size: 12 bytes
```

## Next steps

See the [vault format](./vault-format.md) for details on the on-disk structure, or learn about
configurable [security profiles](./security-profiles.md).
