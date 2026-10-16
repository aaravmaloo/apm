# CLI Reference

This reference reflects the command trees defined in the current source.

## Personal binary: `pm`

### Core vault flow

- `pm setup`
- `pm unlock`
- `pm readonly <mins>`
- `pm lock`
- `pm mode`
- `pm cinfo`
- `pm info`

### Entries and retrieval

- `pm add [type]`
- `pm get [query]`
- `pm gen`
- `pm totp [entry_name]`
- `pm import <file>`
- `pm export`
- `pm export compare <file>`

`pm add` currently supports 25 types. `pm get` is the main interactive search and management flow.

### Import, export and compare

`pm import <file>` detects the format, compares the file with your vault and imports only what you choose. It reads:

| Source | Files | Passkeys |
| --- | --- | --- |
| APM | export `.json` (plain or encrypted), `vault.dat` and backups, v1 `.json`, `.csv`, `.txt` | Yes |
| Bitwarden | `.json`, password protected `.json` (PBKDF2-SHA256 or Argon2id), `.zip`, `.csv` | Yes, from `.json` |
| 1Password | `.1pux`, `.csv` | No. 1Password leaves passkeys out of its exports |
| KeePass and KeePassXC | XML export, `.csv` | Yes, KeePassXC passkeys from XML |
| FIDO Credential Exchange (CXF 1.0) | `.json` (full header or a bare account) | Yes |
| Chrome, Edge, Brave, Firefox, Safari | passwords `.csv` | No |
| Authenticator apps | `.txt` with `otpauth://` links | No |

Every row gets a status: new, already in your vault, conflict (same name, different contents), possible duplicate (the same login, key or passkey under another name) or can't be imported (with the reason). Conflicts and duplicates take one of four actions: skip, merge (fill empty fields, add websites, notes and passkeys, keep your values), replace (take the file's values; your old values stay in the item's history) or keep both. The suggested action never loses a passkey or an account.

- `--dry-run` shows the comparison and stops. `--show-secrets` shows secret values in it. `--json` prints the plan or the result.
- `--on-conflict` and `--on-duplicate` take `skip`, `merge`, `replace`, `keep-both` or `ask`. `-y` imports without asking.
- `--space <name>` imports into a space. `--keep-spaces` turns Bitwarden folders, 1Password vaults, KeePass groups and APM spaces into spaces.
- `-p` gives the export password; on a terminal APM asks for it when needed.
- Logins' one-time codes become linked authenticator items. Codes APM cannot generate (Steam, HOTP, 8 digits, non-30s, SHA-256) are listed as can't be imported.
- Password history becomes item history. One import is one vault commit, so `pm lgit undo` reverts it.
- `pm import --formats` lists every format and how to export it from the other app.

`pm export` writes `--format apm` (default: everything, including passkeys, spaces, favorites and, with `--files`, documents and media; encrypted with Argon2id and AES-256-GCM when you set a password), `cxf` (FIDO Credential Exchange, passkeys included), `bitwarden` (Bitwarden `.json` with passkeys; password protected with `-p` or `--encrypt`), `csv` or `txt`. On a terminal it offers to encrypt.

- `--type`, `--space` and `--no-passkeys` narrow the export. `--without-password` leaves secrets out of `csv` and `txt`.
- `--dry-run` shows what would be exported and what the format leaves out, for example "CSV cannot hold passkeys".
- It never overwrites a file without `--force` or a confirmation. Files are written with mode 0600.
- CXF 1.0 only allows passkeys whose sign counter is 0. APM keeps a counter at 0 when it starts there, as synced passkeys do, so passkeys you create or import stay exportable.

`pm export compare <file>` compares the vault with an earlier export or backup: only in the file, changed, the same, and only in your vault.

### Sessions

- `pm unlock [--timeout 1h] [--inactivity 15m]`
- `pm lock`
- `pm autolock [--idle 15m|never] [--max 1h|never] [--sleep on|off]`
- `pm session issue`
- `pm session list`
- `pm session revoke <id>`

`pm autolock` shows or changes when the vault locks itself. The policy is saved in the vault and shared by the desktop app (Settings, Sessions, Auto-lock), `pm` sessions and the browser extension. Durations take Go syntax (`15m`, `4h`) or a number of minutes, and round up to whole minutes; `never` turns a limit off and prints a warning. `pm unlock` uses the policy unless you pass `--timeout` or `--inactivity`. With `--sleep on`, a `pm` session also ends once the computer has slept (macOS and Linux).

Ephemeral sessions can be bound to host, PID, and agent identity.

### Recovery and auth

- `pm auth email [address]`
- `pm auth recover`
- `pm auth reset`
- `pm auth change`
- `pm auth alerts`
- `pm auth level [1-3]`
- `pm auth quorum-setup`
- `pm auth quorum-recover`
- `pm auth passkey register`
- `pm auth passkey verify`
- `pm auth passkey disable`
- `pm auth codes generate`
- `pm auth codes status`

### Profiles, spaces, and policy

- `pm profile list`
- `pm profile current`
- `pm profile set <name>`
- `pm profile edit [name]`
- `pm profile create <name>`
- `pm space create [name]`
- `pm space switch [name]`
- `pm space list`
- `pm policy load [name]`
- `pm policy show`
- `pm policy clear`

### Cloud

- `pm cloud init [gdrive|github|dropbox|all]`
- `pm cloud sync [gdrive|github|dropbox]`
- `pm cloud auto-sync`
- `pm cloud get [gdrive|github|dropbox] [retrieval_key|repo]`
- `pm cloud diff [gdrive|github|dropbox]`
- `pm cloud delete [gdrive]`
- `pm cloud reset`

Notes:

- Google Drive and Dropbox support `APM_PUBLIC` and `self_hosted` modes.
- GitHub uses token-based auth and a repository target.
- `cloud get` can work with provider identifiers such as repo, file ID, or Dropbox path.

### Browser extension

- `pm extension link [--browser chrome,edge] [--id <extension id>] [--no-wait]`
- `pm extension unlink`
- `pm extension status [--port N]`
- `pm extension serve [--port N] [--locked] [--idle 15m]`
- `pm extension token [--show]`
- `pm extension rotate`
- `pm totp link <entry> <domain>`
- `pm totp unlink <entry> [domain]`

`pm extension link` lets the extension work without the desktop app. It registers `pm` as a native messaging host (`dev.apm.bridge`) with every Chromium browser it finds (Chrome, Edge, Brave, Arc, Vivaldi, Chromium), allowed only for the APM extension, then waits in the terminal. If the extension is not paired yet it shows a code; check that the terminal shows the same one and answer `y`. You do this once. From then on, whenever the app is closed, the browser starts `pm` on its own and the extension sends the same requests over stdio. `pm` holds the key only while it runs, locks on the vault's auto-lock policy, and exits when the browser closes. While the app is running, the extension uses the app. `pm extension unlink` removes the registration; `pm extension rotate` revokes the pairing.

`pm extension serve` serves the same loopback API as the desktop app from a terminal, until Ctrl+C, instead of linking. Pair a browser by approving the code it shows, or paste the token from `pm extension token --show`. It locks on the vault's auto-lock policy unless you pass `--idle`.

`pm extension status` shows which browsers are linked, what is serving the extension right now (the app, `pm extension serve`, or the browser-started `pm`), the vault's lock state and item count, and the pairing token's fingerprint. It exits 1 when the extension has no way to reach `pm`, when something other than APM holds the port, or when the token does not match the running bridge.

A login can hold several websites: `website` plus `urls` ("Other websites" in the desktop app). The extension offers the login on any of them, and can add the site you are on to a login.

While the vault is unlocked, the desktop app and `pm extension serve` fetch each login's logo from the site itself (never from a third-party service) and cache it under `icons/` in the APM config directory. Turn this off with the `siteIcons` vault setting ("Show website icons" in the desktop app), or set `APM_ICONS_OFFLINE=1`. See [Storage](storage.md#browser-bridge-and-website-icons) for the cache layout.

### MCP

- `pm mcp add [assistant] [--yes]`
- `pm mcp list`
- `pm mcp revoke <name|id>`
- `pm mcp pause`
- `pm mcp resume`
- `pm mcp settings [--approve-with any|touchid] [--expiry 5m|15m|30m|1h] [--new-assistants ask|block] [--ask-before-secrets on|off]`
- `pm mcp bypass <assistant> ask|always|1h`
- `pm mcp config`
- `pm mcp serve [--client <assistant>] [--token <token>]`
- `pm mcp token` (legacy, hidden)

`pm mcp add` sets up an AI assistant to use APM. Without an argument it asks which assistant you use. It then runs the assistant's own setup command, merges an `apm` entry into the config file the assistant reads (keeping other keys, backing the old file up to `<file>.apm-backup`, and refusing to touch a file that isn't plain JSON), or opens the assistant's install link. Each way starts `pm mcp serve --client <assistant>`. The first time the assistant starts it, approve it in the APM prompt.

A newly allowed assistant may use `list_vault`, `search_vault`, `get_entry`, `decrypt_entry`, `get_totp`, `generate_password`, `add_entry`, `edit_entry`, `delete_entry`, `tx_list` and `tx_abort`. Change this per assistant in **Settings → AI access**. Permissions and revokes apply from the assistant's next tool call.

`pm mcp list` shows the allowed assistants (with whether their changes ask first) and any legacy tokens. `pm mcp revoke` takes an assistant's name or id, or a legacy token's name. `pm mcp config` prints the generic server entry for assistants `pm mcp add` doesn't know. `pm mcp serve` is what assistants run; with `--token` it uses a legacy token instead of pairing.

`pm mcp pause` refuses every tool call from every assistant until `pm mcp resume`. `pm mcp settings` without flags prints the MCP settings; with flags it changes them: `--approve-with touchid` lets only a touch approve on a Mac with Touch ID, `--expiry` sets how long a change request stays open, `--new-assistants block` refuses assistants APM doesn't know without a prompt, and `--ask-before-secrets on` makes `get_entry`, `decrypt_entry`, `get_totp` and `search_vault` ask first. `pm mcp bypass` sets whether an assistant's adds, edits and deletes are approved in the prompt (`ask`), without asking (`always`), or without asking for the next hour (`1h`). Connect and read requests always ask.

Stricter changes apply at once. Looser ones (resume, `--approve-with any`, a longer expiry, `--new-assistants ask`, `--ask-before-secrets off`, `bypass always` or `1h`) need you at the terminal: stdin and stdout must be a terminal, and pm asks for Touch ID, or the master password when Touch ID isn't available. Otherwise pm prints `Loosening MCP settings needs you at the terminal.` and exits 1. Each command prints what changed. See [MCP settings](../concepts/mcp.md#settings).

### Auditing and diagnostics

- `pm watchtower [--all] [--kind <kind>] [--space <space>] [--json] [--fail-under N] [--show-dismissed]`
- `pm watchtower ignore <finding-id> [--reason "..."] [--days N]` and `pm watchtower restore <finding-id>`
- `pm watchtower trust [--json]`
- `pm watchtower mark <item> [--exposed | --not-exposed] [--privilege <level>]`
- `pm watchtower breach on|off|check`
- `pm watchtower activity [--all] [--json]` and `pm watchtower activity ack <event-id> | --all`
- `pm auth lockout [N|off]`
- `pm audit`
- `pm loaded`
- `pm compromise`
- `pm update`

### Optional command trees

Depending on build and runtime state, `pm` also exposes:

- `pm inject ...`

## Team binary: `pm-team`

### Session and identity

- `pm-team init <org_name> <admin_username>`
- `pm-team login <username>`
- `pm-team whoami`
- `pm-team logout`

### Departments

- `pm-team dept list`
- `pm-team dept create <name>`
- `pm-team dept switch <username> <dept_id>`

### Users

- `pm-team user list`
- `pm-team user add <username>`
- `pm-team user remove <username>`
- `pm-team user promote <username> <role>`
- `pm-team user roles`
- `pm-team user permission grant <username> <permission>`
- `pm-team user permission revoke <username> <permission>`

### Shared vault operations

- `pm-team add`
- `pm-team list`
- `pm-team get [query]`
- `pm-team gen`
- `pm-team edit <entry_name>`
- `pm-team delete <entry_name>`

Implementation notes:

- `pm-team list` currently prints only some shared entry categories.
- `pm-team get` is the main search path for broader retrieval.
- `pm-team edit` is only fully implemented for a smaller subset of entry types.

### Approvals and reporting

- `pm-team approvals list`
- `pm-team approvals approve <idx>`
- `pm-team approvals deny <idx>`
- `pm-team export`
- `pm-team audit`
- `pm-team health`
- `pm-team info`

### Type-specific shared namespaces

The team binary also registers type-focused command groups with `add`, `list`, and `get` subcommands:

- `pm-team password`
- `pm-team totp`
- `pm-team apikey`
- `pm-team token`
- `pm-team note`
- `pm-team ssh`
- `pm-team cert`
- `pm-team wifi`
- `pm-team recovery`
- `pm-team banking`
- `pm-team doc`
- `pm-team gov`
- `pm-team medical`
- `pm-team travel`
- `pm-team contact`
- `pm-team cloud`
- `pm-team k8s`
- `pm-team docker`
- `pm-team ssh-config`
- `pm-team cicd`
- `pm-team license`
- `pm-team legal`
