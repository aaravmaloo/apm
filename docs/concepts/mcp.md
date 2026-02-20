# MCP server

APM includes a high-performance, secure MCP (Model Context Protocol) server that allows AI
assistants to interact with your encrypted vault in a safe, controlled manner.

!!! note

    See the [MCP integration guide](../guides/mcp-integration.md) for setup instructions — this
    document discusses the server architecture and security model.

## Architecture

The MCP server acts as a bridge between your local APM vault and an AI client. It implements the
Model Context Protocol, exposing specific "tools" that the AI can call.

```text
[AI Client] <--stdio--> [MCP Server (pm.exe)] <--session--> [Encrypted Vault]
```

| Component           | Description                                                                        |
| :------------------ | :--------------------------------------------------------------------------------- |
| **CLI Wrapper**     | The `pm mcp serve` command starts the MCP server using the same binary as the CLI  |
| **Token Auth**      | Access is controlled via HMAC-signed JWT-like tokens generated with `pm mcp token` |
| **Session Control** | The server requires an active, unlocked vault session (`APM_SESSION_ID`)           |
| **Tool Registry**   | Defines the available operations and their JSON schemas                            |

## Token authentication

MCP tokens are HMAC-signed payloads that encode:

- **Permissions**: Which tools the token holder can invoke.
- **Creation timestamp**: When the token was generated.
- **Vault binding**: Which vault the token is authorized for.

Tokens are generated interactively with `pm mcp token`, where the user selects the specific
permissions to grant.

### Permission scopes

| Scope     | Access Level                                    | Tools Available              |
| :-------- | :---------------------------------------------- | :--------------------------- |
| `read`    | List and search entries (metadata only)         | `list_vault`, `search_vault` |
| `secrets` | Retrieve full entry details including passwords | `get_entry`                  |
| `totp`    | Generate TOTP codes                             | `get_totp`                   |
| `write`   | Create new entries                              | `add_entry`                  |

!!! important

    Each scope is independent. Granting `secrets` does not automatically grant `read` — both must
    be explicitly selected during token generation.

## Tool registry

The MCP server exposes the following tools:

### list_vault

Lists all entries in the vault, grouped by category. Returns titles and metadata only — no
secrets are included in the response.

### search_vault

Performs fuzzy search across entry metadata. Accepts a query string and returns matching entries
ranked by relevance.

### get_entry

Retrieves the full details of a specific entry, including the stored secret. Requires the
`secrets` permission scope.

### get_totp

Generates a time-based one-time password for a specific entry. Requires the `totp` permission
scope and the entry must have a TOTP seed configured.

### add_entry

Securely adds a new entry to the vault. Requires the `write` permission scope.

## Session dependency

The MCP server does not handle vault decryption directly. It relies on an active APM session
established via `pm unlock`. If no session is active, all tool calls will fail with an
authentication error.

```text
Terminal 1: pm unlock
Terminal 2: AI client starts MCP server
```

## Security model

- **No persistent state**: The MCP server is stateless — it does not cache secrets or maintain
  connections.
- **Audit trail**: All MCP tool invocations are logged in the `pm audit` log.
- **Token revocation**: Tokens can be invalidated by regenerating them.
- **Process isolation**: The MCP server runs as a child process of the AI client, inheriting the
  session from the shell environment.

## Next steps

See the [MCP tools reference](../reference/mcp-tools.md) for full tool schemas, or learn about
[vault recovery](./recovery.md).
