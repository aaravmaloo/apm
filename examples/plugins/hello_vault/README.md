# Hello Vault (Legacy `plugin.json` Example)

This example demonstrates a legacy plugin manifest and command-step flow.

## What it does

- Requests `vault.read`
- Exposes a `hello` command
- Reads one vault key (default: `username`) and prints it

## Usage

```console
pm plugins local ./examples/plugins/hello_vault
```
