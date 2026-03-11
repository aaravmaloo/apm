# Importing and Exporting

APM supports importing data from external sources and exporting your vault contents in multiple formats. This enables migration from other password managers and secure backup creation.

---

## Supported Formats

| Format | Import | Export | Encryption Support | Notes                              |
| :----- | :----: | :----: | :----------------: | :--------------------------------- |
| JSON   |   ✅    |   ✅    |     ✅ Optional     | Full-fidelity, all entry types     |
| CSV    |   ✅    |   ✅    |         ❌          | Password entries only              |
| TXT    |   ✅    |   ✅    |         ❌          | Human-readable, optional redaction |

---

## Exporting

### JSON Export

```bash
pm export json
```

Exports all vault entries to a JSON file with the full APM data structure. This is the **most complete** export format, preserving all entry types and their fields.

**With encryption:**

```bash
pm export json --encrypt
```

This encrypts the export file with a separate password, producing a protected JSON file that can only be read with the export password.

### CSV Export

```bash
pm export csv
```

Exports **password entries only** in a standard CSV format:

```csv
account,username,password
github.com,aarav,s3cr3t_p4ss
```

!!! warning
    CSV export includes passwords in plaintext. Handle the output file with extreme care and delete it after use.

### TXT Export

```bash
pm export txt
```

Exports a human-readable text file covering all entry types with formatted sections.

**With password redaction:**

```bash
pm export txt --no-password
```

This creates a reference document with sensitive values replaced by `********`.

---

## Importing

### From JSON

```bash
pm import json backup.json
```

Imports entries from a JSON file matching APM's export format. All entry types are supported.

**From encrypted JSON:**

```bash
pm import json encrypted_backup.json --decrypt
```

You'll be prompted for the export password.

### From CSV

```bash
pm import csv passwords.csv
```

Expects columns for `account`, `username`, and `password`. This is compatible with exports from many other password managers (1Password, Bitwarden, Chrome, etc.).

### From TXT

```bash
pm import txt vault_export.txt
```

Parses structured text files. The parser looks for `Account:`, `Username:`, and `Password:` labels.

---

## Import Behavior

When importing:

- **Duplicate detection** — APM checks for existing entries with the same account name
- **Space assignment** — Imported entries are placed in the currently active space
- **Validation** — Entries are validated against any loaded password policies
- **Audit logging** — Each import action is recorded in the audit log

---

## Migration from Other Password Managers

### From Chrome / Brave / Edge

1. Export passwords from `chrome://settings/passwords`  (CSV format)
2. Import: `pm import csv chrome_passwords.csv`

### From 1Password

1. Export from 1Password (CSV format)
2. Import: `pm import csv 1password_export.csv`

### From Bitwarden

1. Export from Bitwarden (JSON or CSV)
2. Import: `pm import json bitwarden_export.json` or `pm import csv bitwarden_export.csv`

### From KeePass

1. Export from KeePass (CSV format)
2. Import: `pm import csv keepass_export.csv`

!!! tip
    After importing, delete the export files from other password managers. They contain plaintext credentials.

---

## Next Steps

- **[Vault Management](vault-management.md)** — Organizing imported entries
- **[Cloud Sync](cloud-sync.md)** — Sync your vault after importing