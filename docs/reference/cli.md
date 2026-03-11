# CLI Reference

This reference lists the primary `pm` commands and explains what they do. For flags, run `pm <command> --help`.

## Core lifecycle

- `pm init` initializes a new vault.
- `pm unlock` starts a session and unlocks daemon state.
- `pm lock` ends a session and wipes decrypted data.

## Entry operations

- `pm add` adds an entry via an interactive flow.
- `pm get [query]` searches the vault with fuzzy matching.
- `pm edit [id]` edits an existing entry.
- `pm del [id]` deletes an entry.
- `pm gen` generates passwords.

## Spaces

- `pm space list` lists spaces.
- `pm space create <name>` creates a space.
- `pm space switch <name>` switches active space.
- `pm space remove <name>` removes a space.

## Notes and vocabulary

- `pm vocab enable|disable|status` toggles indexing.
- `pm vocab` lists words and aliases.
- `pm vocab alias` creates or updates aliases.
- `pm vocab alias-list` lists aliases.
- `pm vocab alias-remove <alias>` removes an alias.
- `pm vocab rank <word> <delta>` adjusts ranking.
- `pm vocab remove <word>` deletes a word.
- `pm vocab reindex` rebuilds the vocabulary.
## TOTP

- `pm totp` opens the interactive list.
- `pm totp <entry>` copies a specific code.
- `pm autocomplete link-totp` links a TOTP entry to a domain.

## Autofill and autocomplete

- `pm autofill start|stop|status|list-profiles` controls the Windows daemon.
- `pm autocomplete enable|disable` controls autostart registration.
- `pm autocomplete start|stop` manually starts or stops the daemon.
- `pm autocomplete status` shows daemon state and autostart status.
- `pm autocomplete window enable|disable|status` controls popup hints.

## Cloud sync

- `pm cloud init` configures provider credentials.
- `pm cloud sync` uploads or downloads the vault blob.
- `pm cloud autosync` runs periodic sync loops.
- `pm cloud get` downloads remote vault blob.
- `pm cloud reset` clears sync configuration.

## Plugins

- `pm plugins market` lists marketplace plugins.
- `pm plugins install <name>` installs a plugin.
- `pm plugins installed` lists local plugins.
- `pm plugins push <name>` publishes a plugin.
- `pm plugins access` shows permission overrides.
- `pm plugins access <plugin> <permission> on|off` toggles a permission.

## MCP

- `pm mcp token` generates a token.
- `pm mcp serve` starts the server.
- `pm mcp config` outputs config hints.

## Utility

- `pm info` shows version and environment.
- `pm health` runs health checks.
- `pm trust` shows trust/risk scoring.
- `pm update` updates the binary.
