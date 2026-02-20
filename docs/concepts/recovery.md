# Recovery

APM features a robust recovery engine designed for zero-knowledge environments. The recovery
process allows you to regain access to your vault if you forget your master password, without
compromising the security model.

## Recovery flow

The recovery process is a multi-step identity verification flow:

```text
[Forgot Password]
      |
      v
[pm auth recover]
      |
      v
[Email Verification] --> [Secure Token Sent]
      |
      v
[Token Entry] --> [Token Validated (SHA-256)]
      |
      v
[Recovery Key Entry] --> [DEK Unlocked]
      |
      v
[New Master Password] --> [Vault Re-encrypted]
```

## Secure tokens

When you initiate recovery, APM generates a **32-byte cryptographically secure hex token** and
sends it to your registered email address.

- Tokens are stored only in **hashed form** (SHA-256) — the plaintext token exists only in the
  email.
- Tokens expire after **15 minutes**.
- Each recovery attempt generates a new token, invalidating any previous ones.

## Recovery key

During vault initialization (`pm init`), you are prompted to set an optional recovery key. This
key is stored in the vault header using **XOR-obfuscation**, preventing simple memory dumps from
exposing it.

!!! important

    The recovery key is the only way to recover your vault if you forget your master password. If
    you did not set a recovery key during initialization and you forget your master password, your
    vault data is unrecoverable. This is an intentional property of zero-knowledge architecture.

## DEK unlocking

Successful identity verification (email token + recovery key) unlocks the **Data Encryption Key
(DEK)**. This allows APM to:

1. Decrypt the vault with the existing DEK.
2. Prompt for a new master password.
3. Re-derive encryption keys from the new master password.
4. Re-encrypt the vault with the new keys.
5. Update the vault metadata and HMAC signature.

The underlying data is never exposed in plaintext during this process — decryption and
re-encryption happen in memory.

## Identity verification

APM supports identity verification through the `pm auth` command group:

| Command           | Description                                           |
| :---------------- | :---------------------------------------------------- |
| `pm auth email`   | Update the registered email address                   |
| `pm auth reset`   | Reset the master password (requires current password) |
| `pm auth change`  | Change the master password                            |
| `pm auth recover` | Initiate the recovery flow                            |

## Security considerations

- **Offline attacks**: Recovery tokens are hashed, so intercepting the vault file does not reveal
  valid tokens.
- **Brute-force**: The 32-byte token space (256 bits of entropy) makes brute-force infeasible.
- **Time-limited**: The 15-minute expiration window limits the attack surface.
- **Single-use**: Each recovery attempt invalidates all previous tokens.

## Next steps

See the [encryption concept](./encryption.md) for details on the key derivation and encryption
architecture, or learn about [sessions](./sessions.md) for day-to-day vault access.
