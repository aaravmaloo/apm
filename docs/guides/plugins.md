---
title: Using plugins
description:
  A guide to installing, managing, and developing plugins for APM.
---

# Using plugins

APM features a declarative, JSON-driven plugin architecture that allows extending the CLI with
custom commands and workflows without writing Go code.

## Installing plugins

### From the marketplace

Install a plugin from the cloud-synced marketplace:

```console
$ pm plugins add backup-tool
Downloading backup-tool v1.2.0...
Plugin installed successfully.
```

### From a local directory

Install a plugin from a local directory for development:

```console
$ pm plugins local ./my-plugin
Plugin loaded from ./my-plugin
```

## Listing installed plugins

View all installed plugins:

```console
$ pm plugins list
+-------------+---------+---------------------------+
| Name        | Version | Description               |
+-------------+---------+---------------------------+
| backup-tool | 1.2.0   | Backup vault to server    |
| audit-ext   | 0.5.0   | Extended audit reports     |
+-------------+---------+---------------------------+
```

## Running plugin commands

Plugins register their own commands that are available at the top level:

```console
$ pm backup-remote
Syncing vault to remote endpoint...
Server Response: 200 OK
```

## Removing plugins

Uninstall a plugin:

```console
$ pm plugins remove backup-tool
Plugin removed.
```

## Creating a plugin

A plugin is a directory containing a `plugin.json` manifest file:

```text
my-plugin/
  plugin.json
```

The manifest defines metadata, permissions, and command definitions:

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

!!! tip

    See the [Plugin API reference](../reference/plugin-api.md) for the complete operations
    glossary and permissions list.

## Next steps

See the [plugins concept](../concepts/plugins.md) for details on the plugin architecture, or read
the [Plugin API reference](../reference/plugin-api.md) for the full SDK documentation.
