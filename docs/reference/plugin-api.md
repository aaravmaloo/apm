# Plugin API Reference

Complete reference for the APM plugin system — manifest schema, permission catalog, step commands, and hook system.

---

## Manifest Schema

```json
{
  "name": "string (required)",
  "version": "string (required, semver)",
  "description": "string",
  "author": "string",
  "permissions_required": ["string[]"],
  "allowed_file_types": ["string[]"],
  "commands": ["string[]"],
  "hooks": ["string[]"]
}
```

### Field Rules

| Field                  | Required | Validation                                 |
| :--------------------- | :------: | :----------------------------------------- |
| `name`                 |    ✅     | Non-empty string                           |
| `version`              |    ✅     | Semantic versioning (`X.Y.Z[-prerelease]`) |
| `description`          |    ❌     | Free text                                  |
| `author`               |    ❌     | Free text                                  |
| `permissions_required` |    ✅     | Only known permissions or `category.*`     |
| `allowed_file_types`   |    ❌     | File extensions with leading dot           |
| `commands`             |    ❌     | Command name strings                       |
| `hooks`                |    ❌     | `pre:command` or `post:command` patterns   |

---

## Complete Permission Catalog

### Vault Permissions

| Permission      | Description                       |
| :-------------- | :-------------------------------- |
| `vault.read`    | Read vault entries and metadata   |
| `vault.write`   | Write/modify vault entries        |
| `vault.delete`  | Delete vault entries              |
| `vault.import`  | Import data into the vault        |
| `vault.export`  | Export data from the vault        |
| `vault.backup`  | Create vault backups              |
| `vault.restore` | Restore from vault backups        |
| `vault.history` | Access vault modification history |
| `vault.lock`    | Lock the vault                    |
| `vault.unlock`  | Unlock the vault                  |
| `vault.sync`    | Trigger cloud synchronization     |

### Vault Item Permissions

| Permission          | Description                  |
| :------------------ | :--------------------------- |
| `vault.item.create` | Create new vault entries     |
| `vault.item.read`   | Read existing entries        |
| `vault.item.update` | Update existing entries      |
| `vault.item.delete` | Delete entries               |
| `vault.item.move`   | Move entries between spaces  |
| `vault.item.copy`   | Copy entries                 |
| `vault.item.share`  | Share entries (team edition) |

### Vault Field Permissions

| Permission                        | Description           |
| :-------------------------------- | :-------------------- |
| `vault.item.field.password.read`  | Read password fields  |
| `vault.item.field.password.write` | Write password fields |
| `vault.item.field.username.read`  | Read username fields  |
| `vault.item.field.username.write` | Write username fields |
| `vault.item.field.url.read`       | Read URL fields       |
| `vault.item.field.url.write`      | Write URL fields      |
| `vault.item.field.notes.read`     | Read note content     |
| `vault.item.field.notes.write`    | Write note content    |
| `vault.item.field.totp.read`      | Read TOTP secrets     |
| `vault.item.field.totp.write`     | Write TOTP secrets    |
| `vault.item.field.tags.read`      | Read entry tags       |
| `vault.item.field.tags.write`     | Write entry tags      |
| `vault.item.field.metadata.read`  | Read entry metadata   |
| `vault.item.field.metadata.write` | Write entry metadata  |
| `vault.item.field.custom.read`    | Read custom fields    |
| `vault.item.field.custom.write`   | Write custom fields   |

### Network Permissions

| Permission         | Description                     |
| :----------------- | :------------------------------ |
| `network.outbound` | General outbound network access |
| `network.inbound`  | Accept inbound connections      |
| `network.http`     | HTTP requests                   |
| `network.https`    | HTTPS requests                  |
| `network.ftp`      | FTP connections                 |
| `network.sftp`     | SFTP connections                |
| `network.ssh`      | SSH connections                 |
| `network.ws`       | WebSocket connections           |
| `network.wss`      | Secure WebSocket connections    |
| `network.tcp`      | Raw TCP connections             |
| `network.udp`      | UDP connections                 |
| `network.icmp`     | ICMP (ping)                     |
| `network.proxy`    | Proxy connections               |
| `network.dns`      | DNS queries                     |
| `network.api.rest` | REST API calls                  |
| `network.api.grpc` | gRPC API calls                  |

### System Permissions

| Permission               | Description                |
| :----------------------- | :------------------------- |
| `system.read`            | Read system information    |
| `system.write`           | Write system files         |
| `system.exec`            | Execute system commands    |
| `system.env.read`        | Read environment variables |
| `system.env.write`       | Set environment variables  |
| `system.process.read`    | Read process information   |
| `system.process.write`   | Modify processes           |
| `system.process.kill`    | Kill processes             |
| `system.clipboard.read`  | Read from clipboard        |
| `system.clipboard.write` | Write to clipboard         |
| `system.notification`    | Show system notifications  |
| `system.audio.record`    | Record audio               |
| `system.audio.play`      | Play audio                 |
| `system.camera`          | Access camera              |
| `system.location`        | Access location services   |
| `system.power`           | Control power state        |
| `system.usb.read`        | Read USB devices           |
| `system.usb.write`       | Write to USB devices       |
| `system.bluetooth`       | Access Bluetooth           |
| `system.wifi`            | Access Wi-Fi interfaces    |

### Cryptography Permissions

| Permission             | Description                 |
| :--------------------- | :-------------------------- |
| `crypto.use`           | General cryptography access |
| `crypto.hash`          | Compute hashes              |
| `crypto.random`        | Generate random data        |
| `crypto.encrypt`       | Encrypt data                |
| `crypto.decrypt`       | Decrypt data                |
| `crypto.sign`          | Create digital signatures   |
| `crypto.verify`        | Verify digital signatures   |
| `crypto.key.generate`  | Generate cryptographic keys |
| `crypto.key.store`     | Store keys                  |
| `crypto.key.load`      | Load stored keys            |
| `crypto.key.delete`    | Delete stored keys          |
| `crypto.cert.generate` | Generate certificates       |
| `crypto.cert.validate` | Validate certificates       |

### File Storage

| Permission     | Description                                     |
| :------------- | :---------------------------------------------- |
| `file.storage` | Read and write files (limited to allowed types) |

### Plugin Management Permissions

| Permission            | Description                |
| :-------------------- | :------------------------- |
| `plugin.list`         | List installed plugins     |
| `plugin.install`      | Install plugins            |
| `plugin.uninstall`    | Remove plugins             |
| `plugin.update`       | Update plugins             |
| `plugin.config.read`  | Read plugin configuration  |
| `plugin.config.write` | Write plugin configuration |
| `plugin.reload`       | Reload plugin state        |

### UI Permissions

| Permission           | Description               |
| :------------------- | :------------------------ |
| `ui.prompt`          | Show user prompts         |
| `ui.alert`           | Show alert dialogs        |
| `ui.confirm`         | Show confirmation dialogs |
| `ui.toast`           | Show toast notifications  |
| `ui.dialog`          | Show custom dialogs       |
| `ui.window.open`     | Open windows              |
| `ui.window.close`    | Close windows             |
| `ui.window.maximize` | Maximize windows          |
| `ui.window.minimize` | Minimize windows          |
| `ui.menu.add`        | Add menu items            |
| `ui.menu.remove`     | Remove menu items         |
| `ui.theme.set`       | Change UI theme           |
| `ui.font.set`        | Change UI font            |

### User & Session Permissions

| Permission           | Description                     |
| :------------------- | :------------------------------ |
| `user.read`          | Read user information           |
| `user.write`         | Modify user information         |
| `user.auth`          | Trigger authentication          |
| `user.session.read`  | Read session data               |
| `user.session.write` | Modify session data             |
| `user.profile.read`  | Read user profile               |
| `user.profile.write` | Modify user profile             |
| `user.biometric`     | Access biometric authentication |

### Audit Permissions

| Permission         | Description            |
| :----------------- | :--------------------- |
| `audit.read`       | Read audit data        |
| `audit.write`      | Write audit entries    |
| `audit.log.read`   | Read audit logs        |
| `audit.log.write`  | Write to audit logs    |
| `audit.alert.read` | Read audit alerts      |
| `audit.report`     | Generate audit reports |

### Database Permissions

| Permission        | Description                |
| :---------------- | :------------------------- |
| `db.read`         | Read internal database     |
| `db.write`        | Write to internal database |
| `db.query`        | Execute database queries   |
| `db.schema.read`  | Read database schema       |
| `db.schema.write` | Modify database schema     |

### AI / ML Permissions

| Permission      | Description           |
| :-------------- | :-------------------- |
| `ai.model.load` | Load ML models        |
| `ai.predict`    | Run model predictions |
| `ai.train`      | Train models          |

### IoT / Hardware Permissions

| Permission    | Description            |
| :------------ | :--------------------- |
| `iot.scan`    | Scan for IoT devices   |
| `iot.connect` | Connect to IoT devices |
| `iot.control` | Control IoT devices    |

### Cloud Permissions

| Permission           | Description                |
| :------------------- | :------------------------- |
| `cloud.sync`         | Trigger cloud sync         |
| `cloud.backup`       | Create cloud backups       |
| `cloud.restore`      | Restore from cloud         |
| `cloud.config.read`  | Read cloud configuration   |
| `cloud.config.write` | Modify cloud configuration |

### Wildcard Permissions

Use `category.*` syntax for group-level access:

```json
"permissions_required": ["vault.*", "network.*", "system.*"]
```

---

## Step Commands

The step executor supports these built-in commands:

| Command         | Required Permission  | Description            |
| :-------------- | :------------------- | :--------------------- |
| `vault.list`    | `vault.read`         | List vault entries     |
| `vault.get`     | `vault.read`         | Get a specific entry   |
| `vault.add`     | `vault.write`        | Add a new entry        |
| `vault.edit`    | `vault.write`        | Edit an existing entry |
| `vault.delete`  | `vault.delete`       | Delete an entry        |
| `vault.search`  | `vault.read`         | Search entries         |
| `file.read`     | `file.storage`       | Read a file            |
| `file.write`    | `file.storage`       | Write a file           |
| `file.delete`   | `file.storage`       | Delete a file          |
| `file.list`     | `file.storage`       | List files             |
| `exec`          | `system.exec`        | Execute shell command  |
| `http.get`      | `network.http`       | HTTP GET request       |
| `http.post`     | `network.http`       | HTTP POST request      |
| `http.download` | `network.http`       | Download a file        |
| `crypto.hash`   | `crypto.hash`        | Compute SHA-256 hash   |
| `crypto.random` | `crypto.random`      | Generate random bytes  |
| `set`           | (none)               | Set a variable         |
| `print`         | (none)               | Output text            |
| `prompt`        | `ui.prompt`          | Ask user for input     |
| `confirm`       | `ui.confirm`         | Ask yes/no question    |
| `toast`         | `ui.toast`           | Show notification      |
| `clipboard`     | `system.clipboard.*` | Copy to clipboard      |

### Variable Substitution

Steps can reference variables from previous steps:

```
${variable_name}    → Value of the variable
${output.0}         → First line of previous step output
```

---

## Hook System

### Hook Patterns

```
pre:<command>   — Fires before the command executes
post:<command>  — Fires after the command completes
```

### Available Hooks

| Hook          | Fires When                 |
| :------------ | :------------------------- |
| `pre:add`     | Before an entry is added   |
| `post:add`    | After an entry is added    |
| `pre:edit`    | Before an entry is edited  |
| `post:edit`   | After an entry is edited   |
| `pre:delete`  | Before an entry is deleted |
| `post:delete` | After an entry is deleted  |
| `pre:sync`    | Before cloud sync          |
| `post:sync`   | After cloud sync           |
| `pre:unlock`  | Before vault unlock        |
| `post:unlock` | After vault unlock         |
| `pre:lock`    | Before vault lock          |
| `post:lock`   | After vault lock           |
| `pre:export`  | Before export              |
| `post:export` | After export               |
| `pre:import`  | Before import              |
| `post:import` | After import               |

If a `pre:` hook returns an error, the associated command is aborted.

---

## Runtime Permission Overrides

Users can override plugin permissions after installation:

```bash
# Interactive toggle list (space key to select/deselect)
pm plugins access

# Direct toggle
pm plugins access <plugin> <permission> on|off
```

Overrides are stored inside the encrypted vault under `plugin_permission_overrides` and synced across devices.

The effective permissions for a plugin are:

```
effective = declared_permissions ∩ user_overrides
```

If a user disables a permission, the plugin cannot use it regardless of what the manifest declares.