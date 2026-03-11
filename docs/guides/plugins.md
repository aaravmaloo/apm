# Using Plugins

APM features a manifest-based plugin system that lets you extend the CLI with custom commands, hooks, and automation workflows. Plugins are distributed via a cloud-based marketplace or installed locally.

---

## Installing Plugins

### From the Marketplace

```bash
# Browse available plugins
pm plugins market

# Install a plugin by name
pm plugins install vault_cleaner

# Search for plugins
pm plugins search backup
```

### From a Local Directory

```bash
pm plugins local /path/to/plugin/directory
```

The directory must contain a valid `plugin.json` manifest.

### Listing Installed Plugins

```bash
pm plugins installed
```

---

## Managing Plugin Permissions

Every plugin declares the permissions it needs in its `plugin.json` manifest. APM enforces these at runtime and stores **permission overrides** inside your encrypted vault.

### Viewing Permissions

```bash
pm plugins access
```

Shows all installed plugins and their current permission states.

### Toggling Permissions

```bash
# Disable a specific permission for a plugin
pm plugins access vault_cleaner vault.delete off

# Re-enable it
pm plugins access vault_cleaner vault.delete on
```

!!! warning "Permission Overrides Travel with Your Vault"
    Permission overrides are stored inside the encrypted vault. When you sync your vault to cloud, the overrides travel with it — ensuring consistent security policy across devices.

---

## Running Plugin Commands

Plugins can register custom commands that appear in the APM CLI:

```bash
pm plugins run <plugin_name> <command>
```

Or, if the plugin registers hooks, they fire automatically during vault lifecycle events.

---

## Publishing Plugins

```bash
pm plugins push <plugin_name>
```

Uploads the plugin to the marketplace via your configured cloud provider. The plugin must have:

- A valid `plugin.json` manifest
- Version following semantic versioning (e.g., `1.0.0`)

---

## Creating a Plugin

### Directory Structure

```
my_plugin/
└── plugin.json
```

### Manifest Schema (`plugin.json`)

```json
{
  "name": "my_plugin",
  "version": "1.0.0",
  "description": "A brief description of what this plugin does",
  "author": "Your Name",
  "permissions_required": [
    "vault.read",
    "vault.write",
    "file.storage"
  ],
  "allowed_file_types": [".json", ".txt"],
  "commands": ["backup", "restore"],
  "hooks": ["post:add", "pre:sync"]
}
```

### Manifest Fields

| Field                  | Type       | Required | Description                           |
| :--------------------- | :--------- | :------- | :------------------------------------ |
| `name`                 | `string`   | ✅        | Unique plugin identifier              |
| `version`              | `string`   | ✅        | Semantic version (`X.Y.Z`)            |
| `description`          | `string`   | ❌        | Human-readable description            |
| `author`               | `string`   | ❌        | Plugin author                         |
| `permissions_required` | `string[]` | ✅        | List of required permissions          |
| `allowed_file_types`   | `string[]` | ❌        | File extensions the plugin may access |
| `commands`             | `string[]` | ❌        | Commands the plugin exposes           |
| `hooks`                | `string[]` | ❌        | Lifecycle hooks to listen for         |

### Hook Types

Hooks fire at specific points in the vault lifecycle:

| Hook Pattern  | When It Fires              |
| :------------ | :------------------------- |
| `pre:add`     | Before an entry is added   |
| `post:add`    | After an entry is added    |
| `pre:sync`    | Before a cloud sync        |
| `post:sync`   | After a cloud sync         |
| `pre:delete`  | Before an entry is deleted |
| `post:delete` | After an entry is deleted  |

---

## Example Plugins

APM ships with example plugins in the `examples/plugins/` directory:

### `quick_backup` — Automated Vault Backup

```json
{
  "name": "quick_backup",
  "version": "1.0.0",
  "description": "Creates a timestamped backup of the vault file",
  "permissions_required": ["vault.read", "vault.backup", "file.storage"],
  "commands": ["backup"]
}
```

### `clip_auto_clear` — Clipboard Auto-Clear

```json
{
  "name": "clip_auto_clear",
  "version": "1.0.0",
  "description": "Clears clipboard after a configurable delay",
  "permissions_required": ["system.clipboard.write"],
  "commands": ["clear"]
}
```

### `cloud_sync_hook` — Auto-Sync After Add

```json
{
  "name": "cloud_sync_hook",
  "version": "1.0.0",
  "description": "Triggers cloud sync after adding entries",
  "permissions_required": ["vault.read", "cloud.sync"],
  "hooks": ["post:add"]
}
```

---

## Security Considerations

!!! danger "Plugins Execute Code"
    Plugins can execute arbitrary commands on your system within their declared permissions. Always:

    1. **Review permissions** before installing (`pm plugins access`)
    2. **Disable unnecessary permissions** (`pm plugins access <name> <perm> off`)
    3. **Only install plugins from trusted sources**

---

## Next Steps

- **[Plugin API Reference](../reference/plugin-api.md)** — Full permission catalog and step commands
- **[Plugin Architecture](../concepts/plugins.md)** — Deep technical details