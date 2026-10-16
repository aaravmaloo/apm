# Managing Your Vault

This guide covers the day-to-day operations of working with your APM vault — adding entries, searching, editing, organizing with spaces,.

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

## Editing and Deleting Entries

Entry mutation happens from the interactive `pm get` browser.

```bash
pm get github
```

From the results view:

- Press ++e++ to edit the selected entry
- Press ++d++ to delete the selected entry

Edits are tracked by the **secret telemetry** system, recording who modified the entry, when, and via what context. Deletions are recorded in the audit log.

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

## Watchtower

```bash
pm watchtower
```

Watchtower checks every item in the vault and the vault's own setup, and scores the vault from 0 to 100 (grade A to F). It looks for:

- **Weak passwords**: common passwords, words with l33t spellings, keyboard runs like `qwerty`, sequences, repeats, dates and years, and passwords that contain the username or site name. Empty passwords don't count.
- **Reused passwords**: the same password, or almost the same (`Summer2023!` and `Summer2024!`), across all spaces. Findings for one shared password share a group.
- **Breached passwords** (opt-in, see below), **exposed** items, and passwords **not changed in 6 months**.
- **Expiring** cards, certificates, documents, licenses and cloud credentials (30 days ahead), and passports and IDs (180 days ahead).
- Logins on **plain http://** sites, sites that offer **two-factor** or **passkeys** you haven't set up, weak or unprotected **SSH keys**, weak **certificates**, **open or WEP Wi-Fi**, used-up **recovery codes**, and live **API keys** pasted into notes.
- **Setup**: encryption profile, alerts, account recovery, auto-lock, Touch ID, audit log integrity, AI assistant access and the breach check.

The score counts the share of items affected in each category, so a few problems in a big vault don't sink it. Each finding shows how many points fixing it gives back.

| Flag                 | What it does                                          |
| :------------------- | :---------------------------------------------------- |
| `--all`              | List every finding, not only the top 10               |
| `--kind <kind>`      | Only one kind, for example `--kind reused`            |
| `--space <space>`    | Only items in one space                               |
| `--json`             | The full report, as the desktop app reads it          |
| `--fail-under <N>`   | Exit 1 when the score is below N, for scripts and CI  |
| `--show-dismissed`   | Also list dismissed findings                          |

Accept a finding with `pm watchtower ignore <finding-id> [--reason "..."] [--days N]` and bring it back with `pm watchtower restore <finding-id>`. Dismissed findings don't count against the score.

### Breach check

```bash
pm watchtower breach on
pm watchtower breach check
```

The breach check is off until you turn it on. It asks Have I Been Pwned's Pwned Passwords service about each password with k-anonymity: only the first 5 characters of the password's SHA-1 hash leave your computer, and the reply is padded. Unchanged passwords are checked again after a week. `pm watchtower breach off` turns it off and forgets the results.

### Trust scores

```bash
pm watchtower trust
```

Every item gets a trust score:

| Factor                       | Penalty |
| :--------------------------- | :------ |
| Marked as exposed            | −45     |
| Not rotated in over a year   | −35     |
| Not rotated in 6 months      | −20     |
| Not rotated in 90 days       | −10     |
| More than 200 uses           | −20     |
| More than 75 uses            | −10     |
| Privilege: critical/root/admin | −15   |
| Privilege: elevated          | −8      |

Risk levels: **Low** (≥80), **Medium** (≥55), **High** (≥35), **Critical** (<35).

Mark an item with `pm watchtower mark <item> --exposed` (or `--not-exposed`) and `--privilege standard|elevated|admin|root|critical`. Privileged items get higher-severity findings, and an AI assistant reading one for the first time shows up as activity.

### Activity

```bash
pm watchtower activity
pm watchtower activity ack --all
```

Activity lists unusual events: wrong passwords before an unlock, an unlock on a new device or at an hour you don't usually unlock, many secrets revealed in a short time, exports, assistants reading privileged items, being refused or reading many items quickly, a changed audit log, the vault file changed outside APM, the wrong-password counter reset, the clock moving back, and weakened security settings. Events are kept inside the encrypted vault. `ack <event-id>` (or `--all`) marks them as you; for an unusual hour it also teaches APM that hour. With alerts and anomaly detection on, high and critical events are emailed.

---

## Wrong passwords

Wrong master passwords never lock the vault for good, and the right password always opens it. The first 3 are free, then each one adds a wait before the next try: 30 seconds after the 4th, 1 minute after the 5th, 5 minutes after the 6th, 15 minutes after the 7th and 1 hour from the 8th on. The CLI, the desktop app and the browser extension share the count. After the next unlock, pm shows how many wrong passwords were entered and from where.

`pm auth lockout <N>` (5 or more) makes the vault need recovery after N wrong passwords in a row. It is off by default; set up recovery first.

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
