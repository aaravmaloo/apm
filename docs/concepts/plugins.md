# Plugins

APM features a declarative, JSON-driven plugin architecture that allows extending the CLI with
custom commands and workflows without writing Go code.

!!! note

    See the [plugins guide](../guides/plugins.md) for an introduction to using plugins — this
    document discusses the plugin architecture and permission model.

## Architecture

Plugins are executed through a series of operations ("ops"). Each plugin defines:

1. **Metadata**: Name, version, description, author.
2. **Permissions**: Explicit capability requests.
3. **Commands**: Named command definitions, each containing a sequence of ops.

```text
plugin.json --> [Parser] --> [Permission Check] --> [Op Executor] --> [Output]
```

The plugin engine validates requested permissions against the granted capabilities before executing
any operation.

## Permission model

Permissions must be explicitly requested in the plugin manifest's `permissions` array. APM supports
over **150 granular permissions** across the following domains:

| Domain      | Examples                                                   | Description                        |
| :---------- | :--------------------------------------------------------- | :--------------------------------- |
| **Vault**   | `vault.read`, `vault.write`, `vault.item.*`                | Access to vault entries and fields |
| **Network** | `network.outbound`, `network.http`, `network.ssh`          | Network protocol access            |
| **System**  | `system.exec`, `system.env.read`, `system.clipboard.write` | OS-level operations                |
| **Crypto**  | `crypto.hash`, `crypto.encrypt`, `crypto.key.*`            | Cryptographic operations           |
| **UI**      | `ui.prompt`, `ui.alert`, `ui.window.*`                     | User interface interactions        |
| **Audit**   | `audit.read`, `audit.write`                                | Audit log access                   |
| **Plugin**  | `plugin.list`, `plugin.config.*`                           | Plugin self-management             |
| **User**    | `user.read`, `user.session.*`                              | User and session access            |

### Wildcard matching

Permissions support hierarchical wildcard matching:

- `vault.*` grants all vault-related permissions.
- `vault.item.*` grants all item-level permissions.
- `vault.item.field.*` grants all field-level access (password, username, url, notes, totp, tags,
  metadata).

## Operation types

Plugins execute through typed operations. Each op takes a list of arguments and optionally assigns
results to variables.

### Vault operations

| Op         | Args                            | Permission    |
| :--------- | :------------------------------ | :------------ |
| `v:get`    | `[key, assignTo]`               | `vault.read`  |
| `v:add`    | `[account, password, username]` | `vault.write` |
| `v:list`   | `[assignTo]`                    | `vault.read`  |
| `v:del`    | `[key]`                         | `vault.write` |
| `v:backup` | `[]`                            | `vault.write` |
| `v:lock`   | `[]`                            | None          |

### System operations

| Op        | Args                 | Permission     |
| :-------- | :------------------- | :------------- |
| `s:out`   | `[message]`          | None           |
| `s:in`    | `[prompt, assignTo]` | None           |
| `s:clip`  | `[text]`             | `system.write` |
| `s:sleep` | `[seconds]`          | None           |

### Network operations

| Op         | Args                       | Permission         |
| :--------- | :------------------------- | :----------------- |
| `net:get`  | `[url, assignTo]`          | `network.outbound` |
| `net:post` | `[url, payload, assignTo]` | `network.outbound` |

### Crypto operations

| Op            | Args               | Permission   |
| :------------ | :----------------- | :----------- |
| `crypto:hash` | `[data, assignTo]` | `crypto.use` |

## Variable substitution

Variables stored via `assignTo` can be referenced in any subsequent argument using the `{{name}}`
template syntax.

### System variables

The following variables are available at runtime without explicit assignment:

| Variable        | Description                 |
| :-------------- | :-------------------------- |
| `{{USER}}`      | Current OS username         |
| `{{OS}}`        | Operating system identifier |
| `{{TIMESTAMP}}` | Current UTC timestamp       |

## Storage

Plugins are stored in the `plugins_cache/` directory and dynamically register commands on startup.

### Installation sources

| Source      | Command                   | Description                           |
| :---------- | :------------------------ | :------------------------------------ |
| Marketplace | `pm plugins add <name>`   | Install from cloud-synced marketplace |
| Local       | `pm plugins local <path>` | Load from local filesystem            |

## Next steps

See the [Plugin API reference](../reference/plugin-api.md) for the complete operations glossary and
permissions listing. Or, learn about the [MCP server](./mcp.md).
