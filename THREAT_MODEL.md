# APM Threat Model

This document outlines the security boundaries, assumptions, and explicit non-goals of the APM tool.

## 1. Protected Against
*   **Offline Brute-Force**: Argon2id (128MB, 3 iterations) makes GPU/ASIC crackers prohibitively expensive to run against your vault file.
*   **Vault Tampering**: Any bit-level modification to the vault file is detected via the HMAC-SHA256 signature before decryption occurs.
*   **Plaintext Leakage**: Sensitive data is only decrypted into memory and wiped from buffers as soon as the operation completes.
*   **Credential Theft**: Google Drive credentials and tokens are encrypted with your Master Password inside the vault, preventing leaks from plain JSON files on disk.
*   **Cloud Integrity**: Vaults stored in the cloud are fully encrypted; even if a multi-device 'Retrieval Key' is compromised, the vault cannot be decrypted without the Master Password.

## 2. Explicitly NOT Protected Against
*   **Compromised Host**: If a keylogger or memory-scraping malware is active on your OS, APM cannot protect your master password or decrypted secrets.
*   **Weak Master Passwords**: No amount of Argon2id can save a dictionary-based password from a targeted attack.
*   **User Error**: APM does not protect against you forgetting your master password; there are no backdoors or recovery keys.
*   **Process Persistence**: While APM wipes its own buffers, it cannot guarantee that the OS won't swap pages containing sensitive data to disk.

## 3. Assumptions
*   **Clean Binary**: You are running an untampered version of APM compiled from trusted source code.
*   **Secure Environment**: The terminal and OS environment variables are not being monitored by a third party.
*   **Entropy Source**: The system's CSPRNG (`crypto/rand`) is providing high-quality randomness.
