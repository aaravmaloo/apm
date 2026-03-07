---
title: Using plugins
description:
  Build and manage APM plugins with legacy plugin manifests.
---

# Using plugins

APM plugins are manifest-driven (`plugin.json`).

## Create a plugin

Create a folder with `plugin.json`:

```json
{
  "schema_version": "1.0",
  "name": "my_plugin",
  "version": "1.0.0",
  "description": "Example plugin",
  "author": "you",
  "permissions": ["vault.read"],
  "file_storage": {
    "enabled": false,
    "allowed_types": []
  },
  "commands": {
    "hello": {
      "description": "Print a greeting",
      "flags": {},
      "steps": [
        { "op": "s:out", "args": ["hello from my_plugin"] }
      ]
    }
  },
  "hooks": {}
}
```

## Install local plugin

```console
pm plugins local ./path/to/my_plugin
```

## Marketplace flow

```console
pm plugins push my_plugin --path ./path/to/my_plugin
pm plugins market
pm plugins install my_plugin
```

## Permission controls

```console
pm plugins access
pm plugins access my_plugin vault.write off
pm plugins access my_plugin vault.write on
```

## Examples

See `examples/plugins/` for working `plugin.json` examples.
