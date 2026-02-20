# Sessions

APM uses shell-scoped sessions to provide secure, time-limited access to the decrypted vault.
Sessions prevent the need to enter the master password for every operation.

!!! note

    See the [sessions guide](../guides/sessions.md) for an introduction to working with sessions
    — this document discusses the session architecture in depth.

## Session architecture

When you run `pm unlock`, APM:

1. Derives the encryption keys from your master password using Argon2id.
2. Validates the keys against the vault's stored validation hash.
3. Generates a unique session ID and stores the derived keys in a temporary, secure location.
4. Sets the `APM_SESSION_ID` environment variable in the current shell.

Subsequent commands read the `APM_SESSION_ID` to retrieve the cached keys, bypassing the key
derivation step.

## Shell scoping

Sessions are scoped to the shell process via the `APM_SESSION_ID` environment variable:

| Property        | Behavior                                                   |
| :-------------- | :--------------------------------------------------------- |
| **Isolation**   | Each terminal has its own independent session              |
| **Inheritance** | Child processes inherit the session from the parent shell  |
| **Termination** | Closing the terminal invalidates the session               |
| **Cross-shell** | Sessions cannot be shared across different shell instances |

## Inactivity timeout

Sessions automatically expire after a configurable period of inactivity. The default timeout is
**1 hour**.

After expiration, the next vault operation will:

1. Detect the expired session.
2. Wipe the cached keys from memory.
3. Prompt for the master password.

## Session lifecycle

```text
pm unlock
  |
  v
[Master Password] --> [Argon2id KDF] --> [Key Validation] --> [Session Created]
                                                                     |
                                                                     v
                                                              [APM_SESSION_ID set]
                                                                     |
                                                          +----------+----------+
                                                          |                     |
                                                     [pm get, pm add, ...]  [Timeout]
                                                          |                     |
                                                          v                     v
                                                     [Keys from cache]   [Session Expired]
                                                                                |
                                                                                v
                                                                         [pm lock / auto]
                                                                                |
                                                                                v
                                                                         [Memory Wiped]
```

## Locking

`pm lock` immediately:

1. Wipes the derived keys from the secure temporary storage.
2. Clears the `APM_SESSION_ID` environment variable.
3. Any subsequent vault operations require re-entering the master password.

## Security considerations

- Session keys are stored in memory-only temporary locations, not on disk.
- The `APM_SESSION_ID` value itself is not a secret — it is an index into the secure key store,
  not the key itself.
- On lock, keys are overwritten with zeros before deallocation.

## Next steps

See the [encryption concept](./encryption.md) for details on the key derivation process, or learn
about [cloud synchronization](./cloud-sync.md).
