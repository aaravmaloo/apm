# APM Vault Security

The APM vault uses industry-standard, high-performance cryptographic primitives designed to withstand modern attack vectors, including high-end GPU clusters and dictionary attacks.

## 1. Argon2id: The State-of-the-Art Key Derivation

When you enter your master password, it isn't used directly for encryption. Instead, it passes through **Argon2id**, the winner of the Password Hashing Competition.

- **Resistant to GPU/ASIC Cracking**: Unlike older methods like SHA-256 or PBKDF2, Argon2 is "memory-hard." APM is configured to use **128MB** of RAM, 3 iterations, and 4 threads to compute the keys. 
- **Three-Layer Derivation**: APM derives 96 bytes of key material from your password, splitting it into three distinct 32-byte keys for Encryption, Authentication, and internal Key Validation.

## 2. AES-256-GCM: The Gold Standard for Encryption

APM uses **AES-256** in **GCM (Galois/Counter Mode)**. This provides both confidentiality and built-in authentication.

- **256-bit Key**: Resistance to all known brute-force attacks.
- **Authenticated Encryption**: GCM ensures that data hasn't been modified. APM further strengthens this with an **Encrypt-then-MAC** approach using a separate HMAC-SHA256 signature over the entire vault file.

## 3. High-Entropy Salts and Nonces

- **Random 16-byte Salt**: Every vault has a unique, randomly generated salt. Even if two people use the exact same master password, their encrypted vaults will look completely different.
- **Unique Nonce for Every Save**: Every time you save your vault, a new random **nonce** is generated. This ensures that the same data encrypted twice results in different ciphertext.

## 4. Secure Credential Handling

- **Encrypted Storage**: To prevent API leaks, Google Drive credentials and tokens are migrated into the vault's encrypted core. They are only decrypted into memory when a cloud operation is requested.
- **Zero-Knowledge Architecture**: The APM developer cannot access your vault. Your master password is the ONLY key to your data.
- **Memory Hygiene**: Sensitive keys and blocks are wiped from memory immediately after use.

## The Brute Force Reality Check

To crack a vault with a strong 12-character password:
1. An attacker needs to guess the password.
2. For *each guess*, they must spend time and memory calculating Argon2id.
3. Even if they could try 1 million passwords per second, it would still take **longer than the age of the universe** to exhaust the search space.

> Your security is as strong as your master password. Use a long, complex passphrase for maximum protection!
