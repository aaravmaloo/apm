---
title: Managing sessions
description:
  A guide to unlocking, locking, and managing shell-scoped sessions in APM.
---

# Managing sessions

APM uses shell-scoped sessions to provide secure, time-limited access to your decrypted vault. Once
a session is started, subsequent commands can access the vault without re-entering the master
password.

## Unlocking the vault

Start a session with `pm unlock`:

```console
$ pm unlock
? Master Password: ********

Session started (timeout: 1 hour).
```

The first manual unlock automatically initializes a session that lasts for 1 hour. Subsequent
commands within the same shell session can access the vault without prompting for the password.

## Locking the vault

Immediately terminate and wipe the active session:

```console
$ pm lock
Session terminated. Memory wiped.
```

!!! important

    Always lock your vault when stepping away from your terminal. The session key is wiped from
    memory on lock, preventing any further access until the next unlock.

## Session scope

Sessions are scoped to the shell environment via the `APM_SESSION_ID` environment variable. This
means:

- Each terminal window has its own independent session.
- Closing the terminal automatically invalidates the session.
- Sessions cannot be shared across different shell instances.

## Inactivity timeout

Sessions automatically expire after a period of inactivity (default: 1 hour). After expiration,
the next vault operation will require re-entering the master password.

## Read-only mode

APM supports a read-only mode that prevents any mutations to the vault:

```console
$ pm readonly
Read-only mode enabled.
```

This is useful when you need to look up credentials without risking accidental modifications.

## Next steps

See the [sessions concept](../concepts/sessions.md) for details on the session architecture. Or,
learn about [extending APM with plugins](./plugins.md).
