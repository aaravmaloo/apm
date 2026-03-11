# Secret Types

APM supports **25+ structured secret types**, each with validated fields, type-specific display logic, and dedicated schemas. This page documents every type and its fields.

---

## Overview

Every entry in APM has a specific type that determines:

- **Field schema** — What data the entry stores
- **Display logic** — How it's rendered in search results and the interactive browser
- **Validation** — Type-specific field validation rules
- **Trust scoring** — How trust and risk are calculated

---

## 1. Password

The most common entry type for website and application credentials.

| Field           | Type     | Required | Description                       |
| :-------------- | :------- | :------: | :-------------------------------- |
| `account`       | `string` |    ✅     | Service name (e.g., "github.com") |
| `username`      | `string` |    ❌     | Login username or email           |
| `password`      | `string` |    ✅     | The password                      |
| `space`         | `string` |    ❌     | Logical space for organization    |
| `custom_fields` | `map`    |    ❌     | Arbitrary key-value data          |

---

## 2. TOTP (Two-Factor Authentication)

Time-based one-time password entries for 2FA.

| Field     | Type     | Required | Description                |
| :-------- | :------- | :------: | :------------------------- |
| `account` | `string` |    ✅     | Service name               |
| `secret`  | `string` |    ✅     | Base32-encoded TOTP secret |
| `space`   | `string` |    ❌     | Logical space              |

TOTP entries support persistent ordering via `totp_order` in the vault.

---

## 3. Government ID

Official identification documents.

| Field       | Type     | Required | Description                                     |
| :---------- | :------- | :------: | :---------------------------------------------- |
| `type`      | `string` |    ✅     | ID type (passport, driver's license, SSN, etc.) |
| `id_number` | `string` |    ✅     | The ID number                                   |
| `name`      | `string` |    ❌     | Name on the document                            |
| `expiry`    | `string` |    ❌     | Expiration date                                 |
| `space`     | `string` |    ❌     | Logical space                                   |

---

## 4. Medical Record

Health-related information.

| Field           | Type       | Required | Description                  |
| :-------------- | :--------- | :------: | :--------------------------- |
| `label`         | `string`   |    ✅     | Record identifier            |
| `insurance_id`  | `string`   |    ❌     | Insurance ID number          |
| `prescriptions` | `string[]` |    ❌     | List of active prescriptions |
| `allergies`     | `string[]` |    ❌     | List of known allergies      |
| `space`         | `string`   |    ❌     | Logical space                |

---

## 5. Travel Information

Booking and travel documents.

| Field             | Type     | Required | Description                    |
| :---------------- | :------- | :------: | :----------------------------- |
| `label`           | `string` |    ✅     | Trip/booking name              |
| `ticket_number`   | `string` |    ❌     | Ticket or reservation number   |
| `booking_code`    | `string` |    ❌     | Booking confirmation code      |
| `loyalty_program` | `string` |    ❌     | Frequent flyer / hotel program |
| `space`           | `string` |    ❌     | Logical space                  |

---

## 6. Contact

Personal or professional contact information.

| Field       | Type     | Required | Description               |
| :---------- | :------- | :------: | :------------------------ |
| `name`      | `string` |    ✅     | Full name                 |
| `phone`     | `string` |    ❌     | Phone number              |
| `email`     | `string` |    ❌     | Email address             |
| `address`   | `string` |    ❌     | Physical address          |
| `emergency` | `bool`   |    ❌     | Mark as emergency contact |
| `space`     | `string` |    ❌     | Logical space             |

---

## 7. Wi-Fi

Wireless network credentials.

| Field           | Type     | Required | Description           |
| :-------------- | :------- | :------: | :-------------------- |
| `ssid`          | `string` |    ✅     | Network name          |
| `password`      | `string` |    ✅     | Network password      |
| `security_type` | `string` |    ❌     | WPA2, WPA3, WEP, etc. |
| `router_ip`     | `string` |    ❌     | Router admin IP       |
| `space`         | `string` |    ❌     | Logical space         |

---

## 8. API Key

API access credentials.

| Field     | Type     | Required | Description              |
| :-------- | :------- | :------: | :----------------------- |
| `name`    | `string` |    ✅     | Identifier               |
| `service` | `string` |    ❌     | Service (e.g., "Stripe") |
| `key`     | `string` |    ✅     | The API key              |
| `space`   | `string` |    ❌     | Logical space            |

---

## 9. Token

Generic authentication tokens.

| Field        | Type     | Required | Description              |
| :----------- | :------- | :------: | :----------------------- |
| `name`       | `string` |    ✅     | Identifier               |
| `token`      | `string` |    ✅     | The token value          |
| `token_type` | `string` |    ❌     | Bearer, OAuth, JWT, etc. |
| `space`      | `string` |    ❌     | Logical space            |

---

## 10. SSH Key

SSH key pairs.

| Field         | Type     | Required | Description             |
| :------------ | :------- | :------: | :---------------------- |
| `name`        | `string` |    ✅     | Key identifier          |
| `private_key` | `string` |    ✅     | PEM-encoded private key |
| `space`       | `string` |    ❌     | Logical space           |

---

## 11. SSH Config

SSH connection configurations.

| Field         | Type     | Required | Description           |
| :------------ | :------- | :------: | :-------------------- |
| `alias`       | `string` |    ✅     | Connection alias      |
| `host`        | `string` |    ✅     | Hostname or IP        |
| `user`        | `string` |    ❌     | SSH username          |
| `port`        | `int`    |    ❌     | SSH port (default 22) |
| `key_path`    | `string` |    ❌     | Path to SSH key file  |
| `fingerprint` | `string` |    ❌     | Host key fingerprint  |
| `space`       | `string` |    ❌     | Logical space         |

---

## 12. Cloud Credentials

AWS, GCP, Azure, and other cloud provider credentials.

| Field        | Type     | Required | Description       |
| :----------- | :------- | :------: | :---------------- |
| `label`      | `string` |    ✅     | Identifier        |
| `access_key` | `string` |    ✅     | Access key ID     |
| `secret_key` | `string` |    ✅     | Secret access key |
| `region`     | `string` |    ❌     | Default region    |
| `role_arn`   | `string` |    ❌     | IAM role ARN      |
| `expiry`     | `string` |    ❌     | Key expiration    |
| `space`      | `string` |    ❌     | Logical space     |

---

## 13. Kubernetes Secret

Kubernetes cluster access credentials.

| Field         | Type     | Required | Description          |
| :------------ | :------- | :------: | :------------------- |
| `name`        | `string` |    ✅     | Secret name          |
| `cluster_url` | `string` |    ✅     | Cluster API URL      |
| `namespace`   | `string` |    ❌     | Kubernetes namespace |
| `expiration`  | `string` |    ❌     | Token expiration     |
| `space`       | `string` |    ❌     | Logical space        |

---

## 14. Docker Registry

Container registry credentials.

| Field          | Type     | Required | Description       |
| :------------- | :------- | :------: | :---------------- |
| `name`         | `string` |    ✅     | Registry name     |
| `registry_url` | `string` |    ✅     | Registry URL      |
| `username`     | `string` |    ❌     | Registry username |
| `token`        | `string` |    ✅     | Access token      |
| `space`        | `string` |    ❌     | Logical space     |

---

## 15. CI/CD Secret

Continuous integration and deployment secrets.

| Field      | Type       | Required | Description                |
| :--------- | :--------- | :------: | :------------------------- |
| `name`     | `string`   |    ✅     | Pipeline/service name      |
| `webhook`  | `string`   |    ❌     | Webhook URL                |
| `env_vars` | `string[]` |    ❌     | Environment variable pairs |
| `space`    | `string`   |    ❌     | Logical space              |

---

## 16. Secure Note

Free-form encrypted text with vocabulary engine support.

| Field     | Type     | Required | Description           |
| :-------- | :------- | :------: | :-------------------- |
| `name`    | `string` |    ✅     | Note title            |
| `content` | `string` |    ✅     | Note body (plaintext) |
| `space`   | `string` |    ❌     | Logical space         |

Notes integrate with the vocabulary engine for autocomplete, aliases, and word scoring.

---

## 17. Recovery Codes

One-time use backup codes for 2FA.

| Field     | Type       | Required | Description            |
| :-------- | :--------- | :------: | :--------------------- |
| `service` | `string`   |    ✅     | Service name           |
| `codes`   | `string[]` |    ✅     | List of recovery codes |
| `space`   | `string`   |    ❌     | Logical space          |

---

## 18. Certificate

TLS/SSL certificates and private keys.

| Field         | Type     | Required | Description            |
| :------------ | :------- | :------: | :--------------------- |
| `label`       | `string` |    ✅     | Certificate identifier |
| `cert_data`   | `string` |    ✅     | PEM certificate data   |
| `private_key` | `string` |    ❌     | PEM private key        |
| `issuer`      | `string` |    ❌     | Certificate issuer     |
| `expiry`      | `string` |    ❌     | Expiration date        |
| `space`       | `string` |    ❌     | Logical space          |

---

## 19. Banking

Financial account information.

| Field     | Type     | Required | Description                     |
| :-------- | :------- | :------: | :------------------------------ |
| `label`   | `string` |    ✅     | Account identifier              |
| `type`    | `string` |    ✅     | Credit card, bank account, etc. |
| `details` | `string` |    ✅     | Account/card number             |
| `cvv`     | `string` |    ❌     | CVV/security code               |
| `expiry`  | `string` |    ❌     | Expiration date                 |
| `space`   | `string` |    ❌     | Logical space                   |

---

## 20. Document

File attachments with optional password protection.

| Field       | Type     | Required | Description             |
| :---------- | :------- | :------: | :---------------------- |
| `name`      | `string` |    ✅     | Document name           |
| `file_name` | `string` |    ✅     | Original filename       |
| `content`   | `[]byte` |    ✅     | Binary file content     |
| `password`  | `string` |    ❌     | Document-level password |
| `tags`      | `string` |    ❌     | Comma-separated tags    |
| `space`     | `string` |    ❌     | Logical space           |

---

## 21. Software License

Software license keys and activation info.

| Field             | Type     | Required | Description           |
| :---------------- | :------- | :------: | :-------------------- |
| `product_name`    | `string` |    ✅     | Software product name |
| `serial_key`      | `string` |    ✅     | License/serial key    |
| `activation_info` | `string` |    ❌     | Activation details    |
| `expiry`          | `string` |    ❌     | License expiration    |
| `space`           | `string` |    ❌     | Logical space         |

---

## 22. Legal Contract

Legal document metadata and summaries.

| Field              | Type     | Required | Description             |
| :----------------- | :------- | :------: | :---------------------- |
| `name`             | `string` |    ✅     | Contract name           |
| `summary`          | `string` |    ❌     | Brief summary           |
| `parties_involved` | `string` |    ❌     | Parties to the contract |
| `signed_date`      | `string` |    ❌     | Date signed             |
| `space`            | `string` |    ❌     | Logical space           |

---

## 23. Photo

Encrypted photo storage.

| Field       | Type     | Required | Description       |
| :---------- | :------- | :------: | :---------------- |
| `name`      | `string` |    ✅     | Photo name        |
| `file_name` | `string` |    ✅     | Original filename |
| `content`   | `[]byte` |    ✅     | Binary image data |
| `space`     | `string` |    ❌     | Logical space     |

Photos support quicklook preview in the terminal via ASCII art rendering.

---

## 24. Audio

Encrypted audio file storage.

| Field       | Type     | Required | Description       |
| :---------- | :------- | :------: | :---------------- |
| `name`      | `string` |    ✅     | Audio name        |
| `file_name` | `string` |    ✅     | Original filename |
| `content`   | `[]byte` |    ✅     | Binary audio data |
| `space`     | `string` |    ❌     | Logical space     |

---

## 25. Video

Encrypted video file storage.

| Field       | Type     | Required | Description       |
| :---------- | :------- | :------: | :---------------- |
| `name`      | `string` |    ✅     | Video name        |
| `file_name` | `string` |    ✅     | Original filename |
| `content`   | `[]byte` |    ✅     | Binary video data |
| `space`     | `string` |    ❌     | Logical space     |

---

## Common Fields

All entry types share these metadata properties managed by APM internally:

| Field        | Type     | Description                  |
| :----------- | :------- | :--------------------------- |
| `id`         | `string` | UUID v4 assigned on creation |
| `created_at` | `time`   | Creation timestamp           |
| `updated_at` | `time`   | Last modification timestamp  |
| `space`      | `string` | Logical space assignment     |
| `entry_type` | `string` | Type identifier              |

---

## Telemetry Metadata

Each entry also tracks telemetry data (**per-secret**, not global):

| Field             | Type     | Description                                       |
| :---------------- | :------- | :------------------------------------------------ |
| `access_count`    | `int`    | Number of times accessed                          |
| `last_accessed`   | `time`   | Last access timestamp                             |
| `created_at`      | `time`   | When first created                                |
| `last_rotated`    | `time`   | When the secret was last changed                  |
| `exposed`         | `bool`   | Whether the secret has been exposed               |
| `privilege_level` | `string` | `normal`, `elevated`, `admin`, `root`, `critical` |
| `last_accessor`   | `string` | Who last accessed (`user` or `AI`)                |

This telemetry feeds into the [Trust Scoring](../guides/vault-management.md#trust-scores) system.

---

## Next Steps

- **[Vault Format](vault-format.md)** — How entries are stored in the binary file
- **[Vault Management Guide](../guides/vault-management.md)** — Adding and managing entries