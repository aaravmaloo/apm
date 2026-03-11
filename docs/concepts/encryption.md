# Encryption

APM uses a zero-knowledge model with encrypted-at-rest storage and authenticated encryption.

## Key derivation

Argon2id derives encryption and authentication keys from the master password. This is memory-hard and slows GPU attacks.

## Encryption and integrity

Vault data is encrypted with AES-GCM. Integrity is enforced with HMAC signatures over vault metadata to detect tampering.

## Recovery design

Recovery uses verified identity steps and a recovery key that gates DEK access. Optional recovery factors add extra assurance without breaking zero-knowledge guarantees.