# Managing Your Vault

This guide covers the day-to-day operations of working with your APM vault — adding entries, searching, editing, organizing with spaces, and using the vocabulary engine for notes.

---

## Adding Entries

### Interactive Add

```bash
pm add
```

This opens an interactive menu showing all 25+ supported secret types. Select a type, then fill in the structured fields. Each type has a specific schema — for example, an SSH Config entry asks for alias, host, user, port, key path, and fingerprint.

### Adding to a Specific Space

If you have spaces configured, entries inherit the currently active space. Switch spaces before adding:

```bash
pm space switch Work
pm add    # This entry will be in the "Work" space
```

### Field Validation

APM validates fields as you enter them. If you have a **password policy** loaded, new passwords are validated against the policy's requirements (minimum length, uppercase, numbers, symbols).

---

## Searching and Retrieving Entries

### Fuzzy Search

```bash
pm get [query]
```

APM performs fuzzy search across **all entry types** simultaneously — matching against account names, usernames, service names, labels, and other identifiers. Results are ranked by match quality.

!!! example "Search Examples"
    ```bash
    pm get github        # Find GitHub credentials
    pm get aws           # Find AWS cloud credentials, API keys, etc.
    pm get "john doe"    # Find contacts named John Doe
    pm get wifi          # Find Wi-Fi passwords
    ```

### Interactive Browser

When results are returned, APM enters an interactive browser mode. Keyboard controls:

| Key        | Action                                   |
| :--------- | :--------------------------------------- |
| ++enter++  | View full entry details                  |
| ++c++      | Copy password/secret to clipboard        |
| ++e++      | Edit this entry                          |
| ++d++      | Delete this entry                        |
| ++s++      | Toggle show/hide sensitive fields        |
| ++q++      | Quicklook (preview notes, render photos) |
| ++m++      | View metadata (timestamps, trust score)  |
| ++escape++ | Exit the browser                         |

### Clipboard Expiry

When you copy a secret to the clipboard, APM automatically clears it after a short timeout to prevent accidental exposure.

### Safe Display

Sensitive fields are **hidden by default** in search results. To reveal them:

```bash
pm get github --show-pass
```

Or press ++s++ in the interactive view.

---

## Editing Entries

```bash
pm edit [name]
```

This opens an interactive editor for the matched entry. Each field is presented with its current value, and you can press ++enter++ to keep it or type a new value.

All edits are tracked by the **secret telemetry** system — recording who modified the entry, when, and via what context (user or AI).

---

## Deleting Entries

```bash
pm del [name]
```

APM prompts for confirmation before permanent deletion. The deletion event is recorded in the audit log.

!!! warning
    Deletion is permanent. There is no trash or undo. If you need to preserve deleted entries, export your vault first.

---

## Organizing with Spaces

Spaces provide logical segmentation within a single vault file. They're useful for separating work credentials from personal ones, or organizing by project.

### Creating and Managing Spaces

```bash
# Create a new space
pm space create DevOps

# List all spaces
pm space list

# Switch to a space
pm space switch DevOps

# See the currently active space
pm space current

# Remove a space (entries in it are moved to default)
pm space remove DevOps
```

### How Spaces Affect Operations

- **Adding** — New entries inherit the active space
- **Searching** — `pm get` searches within the active space by default
- **Cloud sync** — Spaces can be excluded via `.apmignore`
- **TOTP** — TOTP entries are space-aware

---

## Generating Passwords

```bash
pm gen
```

APM generates a high-entropy password using cryptographically secure randomness. The generated password is displayed and automatically copied to your clipboard.

!!! tip
    Generate a password first with `pm gen`, then paste it when `pm add` asks for the password field.

---

## Notes and the Vocabulary Engine

Secure notes in APM are more than text blobs. The **vocabulary engine** builds a compressed index from your notes and provides autocomplete functionality.

### Enabling Vocabulary

```bash
pm vocab enable     # Turn on vocabulary indexing
pm vocab disable    # Turn it off
pm vocab status     # Check if it's active
```

### Writing Notes with Autocomplete

When adding or editing a secure note, APM offers autocomplete suggestions based on your vocabulary. Suggestions are ranked by frequency and user feedback (accepted suggestions increase a word's score; dismissed ones decrease it).

### Managing the Vocabulary

```bash
# List all indexed words with scores
pm vocab

# Create an alias (normalizes terms)
pm vocab alias k8s kubernetes
pm vocab alias tf terraform

# List all aliases
pm vocab alias-list

# Remove an alias
pm vocab alias-remove k8s

# Adjust word ranking manually
pm vocab rank deploy +5    # Boost "deploy"
pm vocab rank temp -3      # Demote "temp"

# Remove a word from the index
pm vocab remove obsolete_term

# Rebuild the entire vocabulary from current notes
pm vocab reindex
```

### How Vocabulary Storage Works

The vocabulary is stored as a **gzip-compressed JSON** blob inside the encrypted vault (`Vault.VocabCompressed`). This means:

- It's encrypted at rest alongside all other vault data
- It can be stripped from cloud uploads using `ignore:vocab` in `.apmignore`
- It's rebuilt from notes content during reindexing

---

## Vault Health and Trust

### Health Dashboard

```bash
pm health
```

Produces a numeric score (0–100) based on:

- **Encryption profile** — Hardened/Paranoid profiles earn bonus points; Legacy loses points
- **Alert configuration** — Enabled alerts earn points
- **Weak secrets** — Passwords shorter than 8 characters are penalized
- **High-risk secrets** — Trust scores below 55 (high risk) or 35 (critical) add penalties

### Trust Scores

```bash
pm trust
```

Every secret gets a trust score based on:

| Factor                 | Penalty | Threshold             |
| :--------------------- | :------ | :-------------------- |
| Marked as exposed      | −45     | Any                   |
| No rotation > 365 days | −35     | Last rotation too old |
| No rotation > 180 days | −20     | Last rotation aging   |
| No rotation > 90 days  | −10     | Last rotation recent  |
| Access count > 200     | −20     | High frequency        |
| Access count > 75      | −10     | Elevated frequency    |
| Privilege: critical    | −15     | Root/admin secrets    |
| Privilege: elevated    | −8      | Elevated access       |

Risk levels: **Low** (≥80), **Medium** (≥55), **High** (≥35), **Critical** (<35)

---

## Audit Log

```bash
pm audit
```

Every vault interaction is logged with:

- **Timestamp** — When the action occurred
- **Action** — What was done (e.g., `ENTRY_ADDED`, `VAULT_UNLOCKED`, `CLOUD_SYNCED`)
- **User** — System username
- **Hostname** — Machine name

The audit log is stored outside the vault at `~/.config/apm/audit.json` and is append-only.

---

## Cryptographic Information

```bash
pm cinfo
```

Displays the active cryptographic parameters:

- Profile name and Argon2id parameters
- Nonce sizes
- Vault format version
- Whether recovery is configured

---

## Next Steps

- **[Cloud Synchronization](cloud-sync.md)** — Sync your vault across devices
- **[Sessions](sessions.md)** — Advanced session management
- **[CLI Reference](../reference/cli.md)** — Every command in detail