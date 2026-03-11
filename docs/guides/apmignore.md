# Using .apmignore

The `.apmignore` file controls what APM excludes from cloud upload payloads. It's processed **before** encryption and upload during `pm cloud sync`, allowing you to maintain local-only data while still syncing the rest of your vault.

---

## File Location

Place `.apmignore` in one of these locations (searched in order):

1. **Same directory as your vault file** (most common)
2. **Current working directory** when running `pm cloud sync`

APM loads the nearest applicable file.

---

## Sections

### `[spaces]` — Ignore Entire Spaces

Exclude whole spaces from cloud uploads:

```ini
[spaces]
private
temp
archive_*
```

Supports glob wildcards (`*` matches any characters).

### `[entries]` — Ignore Specific Entries

Exclude entries using `space:type:name` patterns:

```ini
[entries]
work:password:legacy_admin
*:notes:*draft*
personal:api_key:test_*
*:ssh_key:*
```

| Component | Description | Wildcard Support |
| :-------- | :---------- | :--------------- |
| `space`   | Space name  | `*` for any      |
| `type`    | Entry type  | `*` for any      |
| `name`    | Entry name  | `*` for any      |

!!! tip "Type Names"
    Use lowercase type identifiers: `password`, `totp`, `token`, `notes`, `api_key`, `ssh_key`, `ssh_config`, `wifi`, `gov_id`, `medical`, `travel`, `contact`, `cloud_creds`, `k8s`, `docker`, `cicd`, `recovery_codes`, `certificate`, `banking`, `document`, `software_license`, `legal`, `photo`, `audio`, `video`.

### `[cloud-specific-ignore]` — Provider-Specific Rules

Exclude entries only for a specific provider:

```ini
[cloud-specific-ignore]
dropbox:work:password:legacy_admin
github:*:ssh_key:*
gdrive:personal:notes:*journal*
```

Format: `provider:space:type:name`

Supported providers: `gdrive`, `github`, `dropbox`

### `[vocab]` — Ignore Vocabulary Words

Exclude specific words from the vocabulary index during cloud exports:

```ini
[vocab]
internal_project_name
secret_codename
```

### `[misc]` — Miscellaneous Flags

```ini
[misc]
ignore:vocab
```

| Flag           | Effect                                              |
| :------------- | :-------------------------------------------------- |
| `ignore:vocab` | Strip the entire compressed vocabulary from uploads |

---

## Complete Example

```ini
# ============================================
# .apmignore — APM Cloud Upload Filter
# ============================================

# Spaces to never upload
[spaces]
private
temp_*

# Entries to exclude from all providers
[entries]
work:password:local_dev_db
*:notes:*scratch*
personal:ssh_key:id_ed25519_local

# Provider-specific exclusions
[cloud-specific-ignore]
dropbox:work:password:legacy_admin
github:*:document:*confidential*

# Vocabulary words to exclude
[vocab]
internal_project_alpha

# Strip the entire vocabulary from uploads
[misc]
ignore:vocab
```

---

## Pattern Matching Rules

- Patterns are **case-insensitive** for space and type matching
- Entry names are **case-sensitive**
- `*` matches zero or more characters (glob-style)
- Comments start with `#` and are ignored
- Inline comments after entries are supported (after `#`)
- Empty lines are skipped

---

## How Filtering Works

When you run `pm cloud sync`:

1. APM loads and parses `.apmignore`
2. A **filtered copy** of the vault is created in memory
3. Entries matching ignore rules are removed from the copy
4. If `ignore:vocab` is set, the vocabulary blob is stripped
5. The filtered vault is encrypted and uploaded

!!! info "Local Vault Unaffected"
    Filtering only affects the **upload payload**. Your local vault file is never modified by `.apmignore`. All ignored entries remain safely stored locally.

---

## Debugging

To verify what your `.apmignore` is filtering, check the audit log after a sync:

```bash
pm audit
```

Sync events include details about which provider received the upload and how many entries were in the filtered payload.

---

## Next Steps

- **[Cloud Synchronization](cloud-sync.md)** — Full sync guide
- **[.apmignore Reference](../reference/apmignore.md)** — Format specification