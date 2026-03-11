# MCP Tools Reference

This file documents the MCP tool schemas and required permissions for each tool.

## Core tools

- `list_entries` requires read permission.
- `get_entry` requires read or secrets permission depending on fields.
- `add_entry`, `edit_entry`, `delete_entry` require write permission.
- `get_totp` requires totp permission.

## Transactions

Write tools use transaction guardrails to prevent unintended mutations. A preview is created first and committed only with explicit approval, returning a receipt id on success.