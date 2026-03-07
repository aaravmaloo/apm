# Plugins

APM plugins use a legacy manifest model: each plugin is a folder with a `plugin.json`.

## Plugin definition model

A `plugin.json` defines:

- metadata (`name`, `version`, `description`, `author`)
- declared `permissions`
- optional `commands` with step pipelines
- optional `hooks` keyed by `<event>:<command>` (for example `post:unlock`)

## Runtime model

- plugins are loaded from local `plugins/`
- step operations run through the built-in step engine
- permission overrides are enforced at runtime

Manage permissions with:

```console
pm plugins access
pm plugins access <plugin> <permission> on|off
```

## Distribution model

- publish: `pm plugins push <name>`
- discover: `pm plugins market`
- install: `pm plugins install <name>`

## Related docs

- [Plugin guide](../guides/plugins.md)
- [Plugin API reference](../reference/plugin-api.md)
