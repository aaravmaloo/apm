# APM Plugin API Reference

This document describes how to create plugins for the APM CLI. Plugins allow you to extend the functionality of the password manager with custom commands, hooks, and file handling capabilities.

## Plugin Structure

A plugin is a directory containing a `plugin.json` manifest file and any necessary executable scripts or binaries.

```text
my-plugin/
├── plugin.json      # Manifest file
├── hook.sh          # (Optional) Hook script
└── command.py       # (Optional) Command script
```

## Manifest (`plugin.json`)

The manifest defines the plugin's metadata, permissions, and capabilities.

### Schema (`v1`)

```json
{
  "name": "my-plugin",
  "version": "1.0.0",
  "description": "A description of what the plugin does",
  "author": "Your Name",
  "permissions": [
    "vault.read",
    "network.outbound"
  ],
  "file_storage": {
    "enabled": true,
    "allowed_types": [".json", ".txt"]
  },
  "commands": {
    "my-command": {
      "description": "Does something cool",
      "flags": {
        "verbose": { "type": "bool", "default": "false" }
      },
      "steps": [
        {
          "action": "exec",
          "command": "python command.py",
          "message": "Running custom command..."
        }
      ]
    }
  },
  "hooks": {
    "pre-add": [
      {
        "action": "exec",
        "command": "./hook.sh",
        "message": "Validating entry..."
      }
    ]
  }
}
```

### Fields

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `name` | string | Yes | Unique identifier for the plugin (kebab-case). |
| `version` | string | Yes | Semantic version (e.g., `1.0.0`). |
| `description` | string | Yes | Short description of functionality. |
| `author` | string | Yes | Author name or email. |
| `permissions` | array | No | List of required permissions. |

### Permissions

- `vault.read`: Read entries from the vault.
- `vault.write`: Add or modify vault entries.
- `file.storage`: Store custom files in the plugin's data directory.
- `crypto.use`: Access encryption/decryption helpers.
- `network.outbound`: Make network requests.

## Commands

Plugins can register custom CLI commands.

### `commands` Object

Keys are the command names (e.g., `pm my-command`). Values are command definitions.

| Field | Type | Description |
| :--- | :--- | :--- |
| `description` | string | Help text for the command. |
| `flags` | map | Command line flags (not fully implemented yet). |
| `steps` | array | List of steps to execute. |

### Command Steps

| Action | Description |
| :--- | :--- |
| `exec` | Execute a system command or script. |
| `print` | Print a message to stdout. |
| `http` | Make an HTTP request (requires `network.outbound`). |

## Hooks

Plugins can intercept APM events.

### Supported Events

- `pre-add`: Triggered before adding a new entry.
- `post-add`: Triggered after adding a new entry.
- `pre-unlock`: Triggered before unlocking the vault.

## Versioning

Plugins must follow [Semantic Versioning 2.0.0](https://semver.org/).
- **Major** (X.y.z): Breaking changes.
- **Minor** (x.Y.z): New features (backward compatible).
- **Patch** (x.y.Z): Bug fixes.
