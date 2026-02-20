---
title: MCP integration
description:
  A guide to connecting AI assistants to your APM vault via the Model Context Protocol.
---

# MCP integration

APM includes a native MCP (Model Context Protocol) server that allows AI assistants like Claude
Desktop, Cursor, and Windsurf to interact with your encrypted vault in a safe, controlled manner.

## Generating an access token

Create a token with specific permissions for your AI assistant:

```console
$ pm mcp token
? Select permissions:
  [x] read    - List and search entries
  [x] secrets - Retrieve passwords and secrets
  [ ] totp    - Generate TOTP codes
  [ ] write   - Add new entries

Token generated: POXXXXXX...
```

!!! tip

    Use separate tokens for different AI clients with the minimum required permissions. You can
    always generate additional tokens with different scopes.

## Configuring your AI client

### Claude Desktop

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "apm": {
      "command": "C:\\path\\to\\pm.exe",
      "args": ["mcp", "serve", "--token", "POXXXXXX..."]
    }
  }
}
```

### Cursor / Windsurf / Others

Add the following to your MCP configuration:

```json
{
  "mcpServers": {
    "apm": {
      "command": "C:\\path\\to\\pm.exe",
      "args": ["mcp", "serve", "--token", "POXXXXXX..."],
      "capabilities": ["tools"],
      "env": {
        "APM_VAULT_PATH": "C:\\path\\to\\vault.dat"
      }
    }
  }
}
```

### Quick configuration

Use `pm mcp config` to get a ready-to-paste configuration snippet:

```console
$ pm mcp config
Copy the following configuration to your MCP client:
{
  "mcpServers": {
    "apm": {
      ...
    }
  }
}
```

## Starting the server

The MCP server is started automatically by the AI client using the configured command. You can also
start it manually for testing:

```console
$ pm mcp serve --token POXXXXXX...
MCP server listening on stdio...
```

!!! important

    The MCP server requires an active APM session. You **must** run `pm unlock` in your terminal
    before the AI agent can access the vault.

## Available tools

The MCP server exposes the following tools to AI assistants:

| Tool           | Description                                 | Required Permission |
| :------------- | :------------------------------------------ | :------------------ |
| `list_vault`   | Lists all entries by category (titles only) | `read`              |
| `search_vault` | Performs fuzzy search across metadata       | `read`              |
| `get_entry`    | Retrieves full details including secrets    | `secrets`           |
| `get_totp`     | Generates a 2FA code for a specific entry   | `totp`              |
| `add_entry`    | Securely adds a new entry to the vault      | `write`             |

## Security best practices

- **Session locking**: Always `pm lock` when not using the AI assistant to wipe the session key.
- **Granular tokens**: Use separate tokens for different AI clients with minimal required scopes.
- **Audit logs**: Monitor `pm audit` to see which actions the AI has performed.
- **Token rotation**: Periodically regenerate tokens and revoke old ones.

## Next steps

See the [MCP concept](../concepts/mcp.md) for details on the server architecture. Or, read the
[MCP tools reference](../reference/mcp-tools.md) for full tool schemas and permission details.
