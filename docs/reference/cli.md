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
- `pm tui`

### Entries and retrieval

- `pm add [type]`
- `pm get [query]`
- `pm gen`
- `pm totp [entry_name]`
- `pm import <file>`
- `pm export`

`pm add` currently supports 25 types. `pm get` is the main interactive search and management flow.

### Sessions

- `pm session issue`
- `pm session list`
- `pm session revoke <id>`

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

### Plugins

- `pm plugins installed`
- `pm plugins list`
- `pm plugins market`
- `pm plugins add [name]`
- `pm plugins install [name]`
- `pm plugins push [name]`
- `pm plugins remove [name]`
- `pm plugins search`
- `pm plugins local [path]`
- `pm plugins access [plugin] [permission] [on|off]`
- `pm plugins run [plugin] [command] [args...]`

Plugins may also register extra root-level commands.

### MCP

- `pm mcp config`
- `pm mcp token`
- `pm mcp list`
- `pm mcp revoke [name_or_token]`
- `pm mcp serve`

### Autofill and autocomplete

- `pm autofill start`
- `pm autofill stop`
- `pm autofill status`
- `pm autofill list-profiles`
- `pm autofill daemon`
- `pm autocomplete enable`
- `pm autocomplete disable`
- `pm autocomplete start`
- `pm autocomplete stop`
- `pm autocomplete status`
- `pm autocomplete window enable`
- `pm autocomplete window disable`
- `pm autocomplete window status`
- `pm autocomplete link-totp`

These flows are primarily relevant on Windows.

### Notes and vocabulary

- `pm vocab`
- `pm vocab enable`
- `pm vocab disable`
- `pm vocab status`
- `pm vocab alias`
- `pm vocab alias-list`
- `pm vocab alias-remove [alias]`
- `pm vocab rank [word] [delta]`
- `pm vocab remove [word]`
- `pm vocab reindex`

### Auditing and diagnostics

- `pm health`
- `pm trust`
- `pm audit`
- `pm loaded`
- `pm brutetest [minutes]`
- `pm compromise`
- `pm update`

### Optional command trees

Depending on build and runtime state, `pm` also exposes:

- `pm inject ...`
- `pm faceid ...`
- plugin-defined root commands

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
