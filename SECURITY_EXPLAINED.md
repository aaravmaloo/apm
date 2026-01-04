# APM Vault Security

The APM vault uses industry-standard, high-performance cryptographic primitives designed to withstand modern attack vectors, including high-end GPU clusters and dictionary attacks.

## 1. Argon2id: The State-of-the-Art Key Derivation

When you enter your master password, it isn't used directly for encryption. Instead, it passes through **Argon2id**, the winner of the Password Hashing Competition.

- **Resistant to GPU/ASIC Cracking**: Unlike older methods like SHA-256 or PBKDF2, Argon2 is "memory-hard." It requires a significant amount of RAM (64MB in our current config) to compute. This makes it extremely expensive for hackers to use GPUs or specialized hardware to brute-force your password.
- **Argon2id Variant**: This specific variant provides the best of both worlds: resistance to side-channel attacks and resistance to GPU cracking.

## 2. AES-256-GCM: The Gold Standard for Encryption

APM uses **AES-256** in **GCM (Galois/Counter Mode)**. This is applied in a multi-layer encryption scheme to protect your data.

- **256-bit Key**: The key is 256 bits long. Brute-forcing such a key would take billions of years with all the computing power on Earth.
- **Authenticated Encryption (GCM)**: GCM doesn't just encrypt the data; it also creates a "tag" (MAC). If even a single bit of the encrypted file is changed, the decryption will fail immediately. This prevents "bit-flipping" attacks where an attacker tries to modify your data without knowing the password.

## 3. High-Entropy Salts and Nonces

- **Random 16-byte Salt**: Every vault has a unique, randomly generated salt. Even if two people use the exact same master password, their encrypted vaults will look completely different, preventing "Rainbow Table" attacks.
- **Unique Nonce for Every Save**: Every time you save your vault, a new random **nonce** (Number used ONCE) is generated. This ensures that the same data encrypted twice results in different ciphertext.

## 4. Zero-Knowledge and Security on Disk

- **0600 Permissions**: On Linux and Windows, the vault and session files are saved with restricted permissions (Windows uses ACLs, but Go's `WriteFile` with `0600` maps to restricted access where possible).
- **No Master Password Storage**: Your master password is never saved to disk in plaintext. It only stays in memory or in a temporary session file during an active "sudo" session (using `pm_session.json` which is also permission-restricted and automatically deleted).

## The Brute Force Reality Check

To crack a vault with a strong 12-character password:
1. An attacker needs to guess the password.
2. For *each guess*, they must spend time and memory calculating Argon2id.
3. Even if they could try 1 million passwords per second (highly optimistic for Argon2), it would still take **longer than the age of the universe** to exhaust the search space.

> Your security is as strong as your master password. Use a long, complex passphrase for maximum protection!
