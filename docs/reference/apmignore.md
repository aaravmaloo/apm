# .apmignore Reference

Complete format specification for the `.apmignore` file that controls cloud upload filtering.

---

## File Resolution

APM searches for `.apmignore` in this order:

1. Same directory as the vault file
2. Current working directory

The first file found is used. Only one `.apmignore` file is loaded per sync operation.

---

## Syntax

- Lines starting with `#` are comments
- Empty lines are ignored
- Section headers are enclosed in `[]`
- Patterns support `*` glob wildcards

---

## Sections

### `[spaces]`

List space names to exclude from uploads. One per line.

```ini
[spaces]
private
temp_*
archive
```

| Pattern   | Matches                        |
| :-------- | :----------------------------- |
| `private` | Exactly "private"              |
| `temp_*`  | "temp_1", "temp_staging", etc. |
| `*`       | All spaces (upload nothing)    |

---

### `[entries]`

Entry patterns in `space:type:name` format.

```ini
[entries]
work:password:legacy_admin
*:notes:*draft*
personal:ssh_key:*
*:*:test_*
```

| Component | Description | Wildcard        |
| :-------- | :---------- | :-------------- |
| `space`   | Space name  | `*` = any space |
| `type`    | Entry type  | `*` = any type  |
| `name`    | Entry name  | `*` = any name  |

**Type identifiers:** `password`, `totp`, `token`, `notes`, `api_key`, `ssh_key`, `ssh_config`, `wifi`, `gov_id`, `medical`, `travel`, `contact`, `cloud_creds`, `k8s`, `docker`, `cicd`, `recovery_codes`, `certificate`, `banking`, `document`, `software_license`, `legal`, `photo`, `audio`, `video`

---

### `[cloud-specific-ignore]`

Provider-specific entry patterns in `provider:space:type:name` format.

```ini
[cloud-specific-ignore]
dropbox:work:password:legacy_admin
github:*:ssh_key:*
gdrive:personal:notes:*journal*
```

**Providers:** `gdrive`, `github`, `dropbox`

---

### `[vocab]`

Specific vocabulary words to exclude.

```ini
[vocab]
internal_codename
secret_project
```

---

### `[misc]`

Miscellaneous flags.

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
# .apmignore — Cloud Upload Filter
# ============================================

# Never sync these spaces
[spaces]
private
temp_*

# Exclude specific entries from all providers
[entries]
work:password:local_dev_db
*:notes:*scratch*
*:ssh_key:id_ed25519_local

# Provider-specific exclusions
[cloud-specific-ignore]
dropbox:work:password:legacy_admin
github:*:document:*confidential*

# Words to strip from vocabulary
[vocab]
internal_project_alpha

# Strip entire vocabulary
[misc]
ignore:vocab
```