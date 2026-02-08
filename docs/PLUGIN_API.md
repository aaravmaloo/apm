# APM Plugin API Reference

This document describes how to create plugins for the APM CLI. APM uses a declarative, JSON-driven execution engine that allows building complex workflows without writing Go code.

## Plugin Structure

A plugin is a directory containing a `plugin.json` manifest file. All assets are stored relative to this directory.

```text
my-plugin/
└── plugin.json      # Manifest file
```

## Manifest (`plugin.json`)

The manifest defines the plugin's metadata, permissions, and command definitions.

### Schema Example

```json
{
  "name": "backup-tool",
  "version": "1.2.0",
  "description": "Backup vault to remote server",
  "author": "Aarav Maloo",
  "permissions": [
    "vault.read",
    "network.outbound"
  ],
  "commands": {
    "backup-remote": {
      "description": "Sync vault to remote endpoint",
      "steps": [
        { "op": "v:get", "args": ["MySecret", "pass"] },
        { "op": "net:post", "args": ["https://api.myapp.com/sync", "{\"key\": \"{{pass}}\"}", "resp"] },
        { "op": "s:out", "args": ["Server Response: {{resp}}"] }
      ]
    }
  }
}
```

## Operations Glossary (`op`)

APM execute plugins through a series of "ops". Each op takes a list of `args`.

### Vault Operations
| Op | Args | Description | Permission |
| :--- | :--- | :--- | :--- |
| `v:get` | `[key, assignTo]` | Retrieves password/token for `key`. | `vault.read` |
| `v:add` | `[acc, pass, user]` | Adds a new entry to the vault. | `vault.write` |
| `v:list` | `[assignTo]` | Lists all accounts as a CSV string. | `vault.read` |
| `v:del` | `[key]` | Deletes an entry from the vault. | `vault.write` |
| `v:backup`| `[]` | Creates a timestamped local backup. | `vault.write` |
| `v:lock` | `[]` | Signals a vault lock event. | None |

### System & IO Operations
| Op | Args | Description | Permission |
| :--- | :--- | :--- | :--- |
| `s:out` | `[message]` | Prints a message to the console. | None |
| `s:in` | `[prompt, assignTo]` | Prompts for user input. | None |
| `s:clip` | `[text]` | Copies text to system clipboard. | `system.write` |
| `s:sleep` | `[seconds]` | Pauses execution. | None |

### Network Operations
| Op | Args | Description | Permission |
| :--- | :--- | :--- | :--- |
| `net:get` | `[url, assignTo]` | Performs an HTTP GET request. | `network.outbound` |
| `net:post`| `[url, payload, assignTo]` | Performs an HTTP POST request. | `network.outbound` |

### Cryptographic Operations
| Op | Args | Description | Permission |
| :--- | :--- | :--- | :--- |
| `crypto:hash` | `[data, assignTo]` | Computes SHA-256 hash. | `crypto.use` |

## Variable Substitution

You can use variables stored via `assignTo` in any argument using the `{{name}}` syntax.
- **System Reserved**: `{{USER}}`, `{{OS}}`, `{{TIMESTAMP}}` (Available at runtime).

## Permissions

Permissions must be explicitly requested in the `permissions` array of the manifest.
Support for wildcard matching is available (e.g., `vault.*` grants all vault permissions).

### Vault Operations
- `vault.read`, `vault.write`, `vault.delete`
- `vault.import`, `vault.export`, `vault.backup`, `vault.restore`
- `vault.history`, `vault.lock`, `vault.unlock`, `vault.sync`

### Item Operations
- `vault.item.create`, `vault.item.read`, `vault.item.update`, `vault.item.delete`
- `vault.item.move`, `vault.item.copy`, `vault.item.share`
- `vault.item.field.*` (Granular field access: password, username, url, notes, totp, tags, metadata)

### Network Access
- `network.outbound`, `network.inbound`
- Protocol specific: `network.http`, `network.https`, `network.ssh`, `network.ftp`, `network.ws`, etc.
- `network.proxy`, `network.dns`

### System Integration
- `system.read`, `system.write`, `system.exec`
- `system.clipboard.read`, `system.clipboard.write`
- `system.env.read`, `system.env.write`
- `system.process.read`, `system.process.write`, `system.process.kill`
- `system.notification`, `system.audio.*`, `system.camera`

### Cryptography
- `crypto.hash`, `crypto.random`
- `crypto.encrypt`, `crypto.decrypt`
- `crypto.sign`, `crypto.verify`
- `crypto.key.*` (generate, store, load, delete)

### Plugin Management
- `plugin.list`, `plugin.install`, `plugin.uninstall`, `plugin.update`
- `plugin.config.read`, `plugin.config.write`

### UI & Interaction
- `ui.prompt`, `ui.alert`, `ui.confirm`, `ui.toast`
- `ui.window.*`, `ui.menu.*`, `ui.theme.set`

### User & Session
- `user.read`, `user.write`, `user.auth`
- `user.session.read`, `user.session.write`

### Audit & Logging
- `audit.read`, `audit.write`
- `audit.log.read`, `audit.log.write`

## Implementation Details

Plugins are installed via:
1. `pm plugins add <name>` (Marketplace)
2. `pm plugins local <path>` (Local Development)

The manager stores them in `/plugins_cache/` and dynamically registers commands on startup.
