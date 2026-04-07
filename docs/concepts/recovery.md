# Recovery

The current `pm` implementation supports recovery as a set of separate mechanisms layered around the v4 vault header. Recovery metadata is stored in the vault record outside the main encrypted payload so APM can verify recovery state before normal unlock succeeds.

## Recovery components in the code

### Recovery email

`pm auth email <address>` verifies an email address through SMTP and then stores recovery state in the vault.

What happens in the current flow:

1. A verification code is emailed.
2. You confirm the code in the terminal.
3. A recovery key is generated.
4. The recovery key is shown once.
5. Recovery metadata is saved with the vault.

## Recovery key

The recovery key is the main cryptographic recovery factor used by `pm auth recover`.

Important behavior:

- it is generated in a human-readable grouped format
- it is displayed once during recovery setup
- it is used to unwrap the vault DEK during the recovery flow

## Additional recovery factors

The current code also supports:

- one-time recovery codes through `pm auth codes generate`
- passkey registration and verification through `pm auth passkey ...`
- trustee quorum shares through `pm auth quorum-setup` and `pm auth quorum-recover`

If both passkeys and recovery codes are configured, the recovery flow lets the user choose which second factor to use.

## Commands

```bash
pm auth email you@example.com
pm auth recover
pm auth codes generate
pm auth codes status
pm auth passkey register
pm auth passkey verify
pm auth passkey disable
pm auth quorum-setup
pm auth quorum-recover
pm auth alerts --enable
pm auth level 2
```

## Security levels and alerts

The current code exposes:

- `pm auth level [1-3]`
- `pm auth alerts --enable`
- `pm auth alerts --disable`

Alert level controls gate which alert events are written. Recovery-related email verification uses SMTP during setup and recovery, but general alert delivery in the current implementation is logged locally rather than sent as email.

## What `pm auth recover` actually does

The implemented recovery flow in `main.go` is:

1. verify the recovery email identity by hash match
2. send a six-digit email code
3. verify the recovery key
4. optionally require a passkey or one-time recovery code
5. decrypt the vault with the recovered DEK
6. prompt for a new master password
7. re-encrypt and save the vault

Quorum recovery is a separate path that reconstructs the recovery key from trustee shares before the vault is re-encrypted under a new master password.

## Accuracy notes

- Recovery metadata is available from the vault header in v4.
- The alert email address is stored as part of recovery metadata.
- One-time recovery codes are tracked for used and unused state.
- Recovery configuration is optional and must be set up explicitly.
