---
title: Importing and exporting data
description:
  A guide to migrating data to and from APM using import and export commands.
---

# Importing and exporting data

APM supports importing credentials from external sources and exporting vault data to various
formats for backup or migration purposes.

## Importing data

### Supported formats

APM can ingest data from the following formats:

| Format  | Extension | Description                                |
| :------ | :-------- | :----------------------------------------- |
| JSON    | `.json`   | Structured JSON export from other managers |
| CSV     | `.csv`    | Comma-separated values with header row     |
| KeePass | `.kdbx`   | KeePass database files                     |

### Import command

Import entries from an external file:

```console
$ pm import ./exports/bitwarden.json
? Detected format: JSON
? Import 47 entries? Yes

Imported 47 entries successfully.
```

APM will automatically detect the format and map fields to the appropriate categories.

!!! tip

    Review imported entries with `pm get` after import to verify field mapping. Some fields may
    require manual adjustment depending on the source format.

## Exporting data

### Export to encrypted format

Export your vault to an encrypted archive:

```console
$ pm export --encrypted
? Master Password: ********
? Export path: ./backup/vault-backup.apm

Exported 142 entries to encrypted archive.
```

### Export to plaintext

Export your vault to a plaintext format for migration:

```console
$ pm export --format json
? Master Password: ********
? Export path: ./backup/vault-export.json

Exported 142 entries to JSON.
```

!!! important

    Plaintext exports contain your secrets in cleartext. Handle these files with extreme care and
    delete them securely after use. Prefer encrypted exports for backups.

### Supported export formats

| Format    | Flag            | Description                  |
| :-------- | :-------------- | :--------------------------- |
| JSON      | `--format json` | Structured JSON output       |
| CSV       | `--format csv`  | Comma-separated values       |
| Encrypted | `--encrypted`   | APM native encrypted archive |

## Next steps

See the [vault management guide](./vault-management.md) for more on managing entries, or learn
about [cloud synchronization](./cloud-sync.md) for automated backups.
