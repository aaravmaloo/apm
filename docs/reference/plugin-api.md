# Plugin API reference

APM plugins are declarative JSON manifests that define commands as sequences of typed operations.

!!! note

    See the [plugins concept](../concepts/plugins.md) for architecture details and the
    [plugins guide](../guides/plugins.md) for usage — this document is the full API reference.

## Manifest schema

Every plugin must contain a `plugin.json` file at its root:

```json
{
  "name": "<string>",
  "version": "<semver>",
  "description": "<string>",
  "author": "<string>",
  "permissions": ["<permission>", "..."],
  "commands": {
    "<command-name>": {
      "description": "<string>",
      "steps": [
        { "op": "<op-type>", "args": ["<arg1>", "<arg2>", "..."] }
      ]
    }
  }
}
```

| Field         | Type     | Required | Description                      |
| :------------ | :------- | :------- | :------------------------------- |
| `name`        | string   | Yes      | Unique plugin identifier         |
| `version`     | string   | Yes      | Semantic version (e.g., `1.2.0`) |
| `description` | string   | Yes      | Human-readable description       |
| `author`      | string   | Yes      | Plugin author                    |
| `permissions` | string[] | Yes      | Required permission scopes       |
| `commands`    | object   | Yes      | Command definitions              |

## Operations glossary

### Vault operations

| Op         | Args                            | Description               | Permission    |
| :--------- | :------------------------------ | :------------------------ | :------------ |
| `v:get`    | `[key, assignTo]`               | Retrieve an entry by name | `vault.read`  |
| `v:add`    | `[account, password, username]` | Create a new entry        | `vault.write` |
| `v:list`   | `[assignTo]`                    | List all entry names      | `vault.read`  |
| `v:del`    | `[key]`                         | Delete an entry           | `vault.write` |
| `v:backup` | `[]`                            | Trigger a vault backup    | `vault.write` |
| `v:lock`   | `[]`                            | Lock the vault session    | None          |

### System / IO operations

| Op        | Args                  | Description                  | Permission        |
| :-------- | :-------------------- | :--------------------------- | :---------------- |
| `s:out`   | `[message]`           | Print to stdout              | None              |
| `s:in`    | `[prompt, assignTo]`  | Read user input              | None              |
| `s:clip`  | `[text]`              | Copy text to clipboard       | `system.write`    |
| `s:sleep` | `[seconds]`           | Pause execution              | None              |
| `s:exec`  | `[command, assignTo]` | Execute a shell command      | `system.exec`     |
| `s:read`  | `[path, assignTo]`    | Read a file                  | `system.read`     |
| `s:write` | `[path, content]`     | Write a file                 | `system.write`    |
| `s:env`   | `[varName, assignTo]` | Read an environment variable | `system.env.read` |

### Network operations

| Op         | Args                       | Description       | Permission         |
| :--------- | :------------------------- | :---------------- | :----------------- |
| `net:get`  | `[url, assignTo]`          | HTTP GET request  | `network.outbound` |
| `net:post` | `[url, payload, assignTo]` | HTTP POST request | `network.outbound` |

### Cryptographic operations

| Op            | Args               | Description  | Permission   |
| :------------ | :----------------- | :----------- | :----------- |
| `crypto:hash` | `[data, assignTo]` | SHA-256 hash | `crypto.use` |

## Variable substitution

Values stored via the `assignTo` argument can be referenced in subsequent operations using the
`{{name}}` template syntax:

```json
{ "op": "v:get", "args": ["MySecret", "pass"] },
{ "op": "s:out", "args": ["The password is: {{pass}}"] }
```

### Built-in variables

| Variable        | Description                 |
| :-------------- | :-------------------------- |
| `{{USER}}`      | Current OS username         |
| `{{OS}}`        | Operating system identifier |
| `{{TIMESTAMP}}` | Current UTC timestamp       |

## Permissions reference

### Vault permissions

| Permission           | Scope                                                                         |
| :------------------- | :---------------------------------------------------------------------------- |
| `vault.read`         | Read entry metadata and secrets                                               |
| `vault.write`        | Create, edit, and delete entries                                              |
| `vault.item.*`       | All item-level operations                                                     |
| `vault.item.field.*` | All field-level access (password, username, url, notes, totp, tags, metadata) |

### Network permissions

| Permission         | Scope                        |
| :----------------- | :--------------------------- |
| `network.outbound` | General outbound HTTP access |
| `network.http`     | HTTP-specific access         |
| `network.ssh`      | SSH protocol access          |

### System permissions

| Permission               | Scope                          |
| :----------------------- | :----------------------------- |
| `system.exec`            | Execute shell commands         |
| `system.read`            | Read filesystem                |
| `system.write`           | Write filesystem and clipboard |
| `system.env.read`        | Read environment variables     |
| `system.clipboard.write` | Write to clipboard only        |

### Crypto permissions

| Permission       | Scope                            |
| :--------------- | :------------------------------- |
| `crypto.use`     | General cryptographic operations |
| `crypto.hash`    | Hashing operations               |
| `crypto.encrypt` | Encryption operations            |
| `crypto.key.*`   | Key management operations        |

### UI permissions

| Permission    | Scope               |
| :------------ | :------------------ |
| `ui.prompt`   | Interactive prompts |
| `ui.alert`    | Alert dialogs       |
| `ui.window.*` | Window management   |

### Audit and user permissions

| Permission        | Scope                 |
| :---------------- | :-------------------- |
| `audit.read`      | Read audit logs       |
| `audit.write`     | Write audit entries   |
| `user.read`       | Read user information |
| `user.session.*`  | Session management    |
| `plugin.list`     | List other plugins    |
| `plugin.config.*` | Plugin configuration  |
