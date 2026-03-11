# Vault Format

APM uses a custom binary format called **Vault V4** for storing encrypted data on disk. This page describes the exact byte layout, integrity mechanisms, and backward compatibility.

---

## File Signature

Every APM vault file begins with the ASCII magic bytes:

```
APMVAULT
```

This 8-byte signature identifies the file as an APM vault and enables format detection by other tools.

---

## V4 Binary Layout

```
┌──────────────────────────────────────────────────────┐
│ Offset  │ Size     │ Field                           │
├──────────────────────────────────────────────────────┤
│ 0       │ 8 bytes  │ Magic: "APMVAULT"               │
│ 8       │ 1 byte   │ Version: 0x04                   │
│ 9       │ 1 byte   │ Profile ID (0-3)                │
│ 10      │ 16 bytes │ Argon2 Salt                     │
│ 26      │ 32 bytes │ Validator Hash (SHA-256)         │
│ 58      │ N bytes  │ Encrypted Payload (AES-GCM)     │
│ 58+N    │ 32 bytes │ HMAC-SHA256 Signature            │
└──────────────────────────────────────────────────────┘
```

### Header Fields

| Field              | Size     | Description                                                            |
| :----------------- | :------- | :--------------------------------------------------------------------- |
| **Magic**          | 8 bytes  | Fixed `APMVAULT` ASCII string                                          |
| **Version**        | 1 byte   | Format version (currently `4`)                                         |
| **Profile ID**     | 1 byte   | Security profile: `0`=Standard, `1`=Hardened, `2`=Paranoid, `3`=Legacy |
| **Salt**           | 16 bytes | Random salt for Argon2id key derivation                                |
| **Validator Hash** | 32 bytes | SHA-256 hash of the validator key (for password check)                 |

### Encrypted Payload

The payload starts at offset 58 and contains:

```
nonce (12 bytes) + ciphertext (variable) + GCM tag (16 bytes)
```

The **nonce** is prepended to the ciphertext. AES-256-GCM's authentication tag is appended by the Go `crypto/aes` library automatically.

### HMAC Signature

The final 32 bytes are an **HMAC-SHA256 signature** computed using the authentication key over:

- Version byte
- Profile ID byte
- Salt
- Validator hash
- Entire encrypted payload

This provides **pre-decryption tamper detection**.

---

## Encrypted Vault Contents

The decrypted JSON payload contains the full `Vault` struct:

```json
{
  "entries": [
    {
      "id": "uuid-v4",
      "username": "...",
      "password": "...",
      "account": "...",
      "space": "...",
      "entry_type": "password",
      "custom_fields": {},
      "created_at": "2026-01-15T10:30:00Z",
      "updated_at": "2026-01-15T10:30:00Z"
    }
  ],
  "totp_entries": [...],
  "totp_order": ["entry1", "entry2"],
  "notes": [...],
  "api_keys": [...],
  "tokens": [...],
  "ssh_keys": [...],
  "ssh_configs": [...],
  "cloud_credentials": [...],
  "k8s_secrets": [...],
  "docker_registries": [...],
  "cicd_secrets": [...],
  "recovery_codes_entries": [...],
  "certificates": [...],
  "banking_entries": [...],
  "documents": [...],
  "software_licenses": [...],
  "legal_contracts": [...],
  "gov_ids": [...],
  "medical_records": [...],
  "travel_entries": [...],
  "contacts": [...],
  "wifi_entries": [...],
  "photos": [...],
  "audio_entries": [...],
  "video_entries": [...],
  "recovery_email": "...",
  "recovery_hash": "...",
  "recovery_salt": "...",
  "alerts_enabled": true,
  "alert_email": "...",
  "security_level": 2,
  "current_space": "default",
  "spaces": ["default", "Work", "Personal"],
  "vocab_compressed": "base64...",
  "cloud_config": {...},
  "mcp_tokens": [...],
  "plugin_permission_overrides": {...},
  "secret_telemetry": {...},
  "history": [...],
  "current_profile_params": {...}
}
```

---

## Version History

| Version | Changes                                                                    |
| :------ | :------------------------------------------------------------------------- |
| V1      | Simple AES-CBC encryption                                                  |
| V2      | Added HMAC integrity                                                       |
| V3      | Migrated to AES-GCM, added Argon2id profiles                               |
| **V4**  | Added `APMVAULT` magic, validator hash, recovery metadata, new entry types |

---

## Backward Compatibility

APM detects older vault formats automatically:

1. **V4** — Full `APMVAULT` header with magic bytes
2. **Pre-V4** — Falls back to legacy decryption (`decryptOldVault`) which uses hardcoded Argon2 parameters

!!! warning "Legacy Vaults"
    Legacy vaults (pre-V4) are supported for reading but **cannot receive new features** like recovery, trust scoring, or vocabulary. You should re-encrypt with `pm profile` to upgrade to V4.

---

## File Locations

| Platform | Default Vault Path                |
| :------- | :-------------------------------- |
| All      | `./vault.dat` (current directory) |
| Override | `APM_VAULT_PATH` env variable     |

---

## Next Steps

- **[Encryption](encryption.md)** — How keys are derived and data is encrypted
- **[Secret Types](secret-types.md)** — All entry type schemas