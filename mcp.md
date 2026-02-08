# APM MCP Server Integration Guide

APM includes a high-performance, secure MCP (Model Context Protocol) server that allows AI assistants to interact with your encrypted vault in a safe, controlled manner.

## Architecture

The MCP server acts as a bridge between your local APM vault and an AI client. It implements the Model Context Protocol, exposing specific "tools" that the AI can call.

| Component           | Description                                                                         |
| :------------------ | :---------------------------------------------------------------------------------- |
| **CLI Wrapper**     | The `pm mcp serve` command starts the MCP server using the same binary as the CLI.  |
| **Token Auth**      | Access is controlled via HMAC-signed JWT-like tokens generated with `pm mcp token`. |
| **Session Control** | The server requires an active, unlocked vault session (`APM_SESSION_ID`).           |
| **Tool Registry**   | Defines the available operations (Search, Get, Add, TOTP) and their schemas.        |

## Available Tools

The following tools are exposed via the MCP server:

| Tool Name      | Description                                  | Required Permissions |
| :------------- | :------------------------------------------- | :------------------- |
| `list_vault`   | Lists all entries by category (titles only). | `read`               |
| `search_vault` | Performs fuzzy search across metadata.       | `read`               |
| `get_entry`    | Retrieves full details including secrets.    | `secrets`            |
| `get_totp`     | Generates a 2FA code for a specific entry.   | `totp`               |
| `add_entry`    | Securely adds a new entry to the vault.      | `write`              |

## Setup Instructions

### 1. Generate Access Token
Run the following command to create a token for your AI assistant:
```bash
pm mcp token
```

### 2. Client Configuration
Configure your AI client (Claude, Cursor, etc.) use the token.

#### Claude Desktop (`claude_desktop_config.json`)
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

## Security Best Practices

> [!IMPORTANT]
> - **Session Locking**: Always `pm lock` when not using the AI assistant to wipe the session key.
> - **Granular Tokens**: Use separate tokens for different AI clients with minimal required scopes.
> - **Audit Logs**: Monitor `pm audit` to see which actions the AI has performed.
