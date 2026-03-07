# Plugin API reference

APM plugins are defined by `plugin.json`.

## Top-level schema

```json
{
  "schema_version": "1.0",
  "name": "plugin_name",
  "version": "1.0.0",
  "description": "Plugin description",
  "author": "Author",
  "permissions": ["vault.read"],
  "file_storage": {
    "enabled": false,
    "allowed_types": []
  },
  "commands": {},
  "hooks": {}
}
```

## Commands

`commands` is a map:

- key: command name
- value: `description`, `flags`, `steps`

Each step:

- `op`: operation id
- `args`: list of strings (supports `{{var}}` substitution)

## Hooks

`hooks` keys use:

- `<event>:<command>`

Examples:

- `pre:add`
- `post:unlock`

## Core operations

- `s:out` print output
- `s:clip` clipboard write
- `s:sleep` sleep seconds
- `s:exec` execute shell command
- `s:in` prompt for input

- `v:get` get secret by name (entry/token/totp fallback)
- `v:add` add password entry
- `v:list` list password-entry names
- `v:del` delete password entry
- `v:backup` create timestamped vault backup
- `v:dump` export vault JSON into variable or stdout
- `v:replace` replace vault with JSON payload

- `net:get` HTTP GET
- `net:post` HTTP POST
- `crypto:hash` SHA-256 hash
- `c:sync` trigger cloud sync signal

## Permission model

Permissions are declared by plugin and checked per step.

Use runtime controls:

```console
pm plugins access
pm plugins access <plugin> <permission> on|off
```

By default, declared permissions are enabled.
