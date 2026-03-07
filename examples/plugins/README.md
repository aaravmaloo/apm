# APM Legacy Plugin Examples

These examples use the legacy `plugin.json` architecture.

## Pattern

1. Define metadata and permissions in `plugin.json`
2. Add command steps under `commands`
3. Optionally add hook steps under `hooks`

Install a local example:

```console
pm plugins local ./examples/plugins/hello_vault
```
