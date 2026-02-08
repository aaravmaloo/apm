# APM Model Context Protocol (MCP) Documentation

APM provides a native MCP server implementation, allowing AI agents (like Claude, Cursor, or Windsurf) to securely interact with your encrypted vault.

## 1. Overview

The APM MCP server acts as a bridge between your local encrypted vault and external AI tools. It follows the Model Context Protocol standard to expose vault capabilities as "tools" that agents can execute.

## 2. Security Architecture

The MCP server is designed with a "Security-First" approach:
- **Zero-Knowledge**: The MCP server never stores your master password.
- **Session-Based**: Access is only possible when an active session exists (unlocked via `pm unlock`).
- **Token Authorization**: Every connection requires a unique access token with granular permissions.
- **Granular Permissions**: You can restrict tokens to specific actions (e.g., `read` only, no `secrets`).

## 3. Setup and Configuration

### 3.1 Generating an Access Token

Run the following command to start the interactive setup:

```bash
pm mcp token
```

You will be prompted for:
1. **Token Name**: A friendly name (e.g., "Cursor").
2. **Permissions**: Select from `read`, `write`, `delete`, `secrets`, or `all`.
3. **Expiry**: Time in minutes until the token expires (0 for no expiry).

### 3.2 Client Configuration

#### Claude Desktop
Add the following to your `mcp.json`:

| Key       | Value                                       |
| :-------- | :------------------------------------------ |
| `command` | `C:\path\to\pm.exe`                         |
| `args`    | `["mcp", "serve", "--token", "YOUR_TOKEN"]` |

#### Cursor / Windsurf
Add a new MCP server with the following settings:

| Setting | Value                             |
| :------ | :-------------------------------- |
| Type    | `command`                         |
| Command | `pm mcp serve --token YOUR_TOKEN` |

## 4. Available Tools

The following tools are exposed to AI agents via MCP:

| Tool Name      | Permissions | Description                                    |
| :------------- | :---------- | :--------------------------------------------- |
| `list_vault`   | `read`      | Lists all entries in the vault by category.    |
| `search_vault` | `read`      | Search for keywords across all entries.        |
| `get_entry`    | `read`      | Retrieve details for a specific entry.         |
| `get_totp`     | `secrets`   | Generate the current TOTP code for an account. |
| `add_entry`    | `write`     | Create a new entry in the vault.               |
| `edit_entry`   | `write`     | Modify an existing entry.                      |
| `delete_entry` | `delete`    | Remove an entry from the vault.                |

## 5. Troubleshooting

### "No active session" Error
The MCP server requires your vault to be unlocked.
**Solution**: Run `pm unlock` in your terminal and ensure the session hasn't timed out.

### Permission Denied
The token used does not have the required permissions for the tool being called.
**Solution**: Revoke the token with `pm mcp revoke [name]` and generate a new one with the correct permissions.

### Token Expired
The token has reached its predefined expiration time.
**Solution**: Generate a new token using `pm mcp token`.
