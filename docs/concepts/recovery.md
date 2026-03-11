# Recovery

APM recovery is designed for zero-knowledge environments. It enables vault recovery without disclosing secrets to any server.

## Flow

1. `pm auth recover` initiates recovery.
2. An email verification token is sent and verified.
3. A recovery key gates DEK unlock.
4. Optional factors such as passkeys or recovery codes can be applied.
5. The vault is re-encrypted with a new master password.

## Properties

- Tokens are stored hashed and expire quickly.
- Recovery is single-use per attempt.
- The recovery key is required if configured.