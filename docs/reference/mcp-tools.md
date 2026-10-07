# MCP Tools Reference

Complete reference for every tool exposed by the APM MCP server, including schemas, required permissions, and transaction behavior.

---

## Permissions

Assistants set up with `pm mcp add` are [paired](../concepts/mcp.md#pairing): you allow each one in APM the first time it connects. Each tool has a permission with the tool's own name (`list_vault`, `add_entry`, ...). A newly allowed assistant may use `list_vault`, `search_vault`, `get_entry`, `decrypt_entry`, `get_totp`, `generate_password`, `add_entry`, `edit_entry`, `delete_entry`, `tx_list` and `tx_abort`. `manage_profiles`, `manage_spaces`, `cloud_config`, `cloud_sync`, `get_history` and `get_audit_logs` apply without asking you, so they're off until you turn them on in **Settings → AI access**.

APM checks the assistant's permissions on every call, so a change or a revoke applies to its next call. Calls return:

- `APM didn't allow <assistant>. Ask again by restarting <assistant>.` when you declined the assistant, didn't answer within 2 minutes, or revoked it.
- `Denied. <assistant> isn't allowed to use <tool>. ...` when its permissions leave the tool out.
- `APM has paused MCP access. Resume it in APM settings.` for every tool while MCP access is paused (`pm mcp pause`).
- `APM isn't accepting new assistants. Allow them in APM settings.` for an assistant APM doesn't know while new assistants are blocked.
- `Not allowed in APM.` from `get_entry`, `decrypt_entry`, `get_totp` and `search_vault` when **Ask before secrets** is on and you decline the read or don't answer within 2 minutes.

See [MCP settings](../concepts/mcp.md#settings) for these settings.

The **Required scope** lines below are for [legacy tokens](../concepts/mcp.md#legacy-tokens) (`pm mcp serve --token`), which use scopes instead.

---

## Read Tools

### `list_entries`

List all entries in the vault (metadata only).

**Required scope:** `read`

**Returns:** Array of entry summaries with IDs, names, types, spaces, and creation dates. Sensitive fields (passwords, keys) are not included.

---

### `search_entries`

Search entries by query string.

**Required scope:** `read`

**Parameters:**

| Parameter | Type     | Required | Description          |
| :-------- | :------- | :------: | :------------------- |
| `query`   | `string` |    ✅     | Search query (fuzzy) |
| `space`   | `string` |    ❌     | Filter by space      |
| `type`    | `string` |    ❌     | Filter by entry type |

**Returns:** Matching entries with relevance scoring.

---

### `get_entry`

Get a specific entry by ID or name.

**Required scope:** `read` (metadata) or `secrets` (sensitive fields)

**Parameters:**

| Parameter        | Type     | Required | Description              |
| :--------------- | :------- | :------: | :----------------------- |
| `id`             | `string` |    ❌     | Entry UUID               |
| `name`           | `string` |    ❌     | Entry name (fuzzy match) |
| `include_secret` | `bool`   |    ❌     | Include sensitive fields |

**Notes:** If `include_secret` is true, the `secrets` scope is required. Without it, passwords, keys, and tokens are redacted.

---

## Secret Tools

### `decrypt_entry`

Retrieve the full entry including all sensitive fields.

**Required scope:** `secrets`

**Parameters:**

| Parameter | Type     | Required | Description |
| :-------- | :------- | :------: | :---------- |
| `id`      | `string` |    ✅     | Entry UUID  |

---

### `get_totp`

Generate a TOTP code for a specific entry.

**Required scope:** `secrets`

**Parameters:**

| Parameter | Type     | Required | Description       |
| :-------- | :------- | :------: | :---------------- |
| `account` | `string` |    ✅     | TOTP account name |

**Returns:** Current 6-digit TOTP code and seconds remaining.

---

## Write Tools

All write tools use [transaction guardrails](../concepts/mcp.md#transaction-guardrails).

### `add_entry`

Add a new entry to the vault.

**Required scope:** `write`

**Parameters:**

| Parameter | Type     | Required | Description                  |
| :-------- | :------- | :------: | :--------------------------- |
| `type`    | `string` |    ✅     | Entry type                   |
| `fields`  | `object` |    ✅     | Entry fields (type-specific) |
| `space`   | `string` |    ❌     | Target space                 |

**Transaction flow:**

1. The call queues a pending request. Nothing is written yet.
2. APM shows an approval prompt on top of every window and Space, including full-screen apps. Touch the Touch ID sensor or click **Approve** to approve it; on a Mac without Touch ID, press Space. Esc or **Reject** rejects it. The assistant cannot approve it.
3. The call waits up to 2 minutes for your answer and returns the outcome: `Approved. Added "<name>". Receipt <receipt>`, or `Rejected in APM. Nothing changed.`
4. If you haven't answered after 2 minutes, the call returns `Still waiting for approval (request <tx_id>, expires <time>)`. The request stays open for 15 minutes (the expiry setting: 5, 15, 30 or 60), and the assistant can check it with `tx_list`.

When you set the assistant to approve changes without asking (`pm mcp bypass`), steps 2 and 3 are skipped: the request is approved at once and the call returns the result.

---

### `edit_entry`

Edit an existing entry.

**Required scope:** `write`

**Parameters:**

| Parameter | Type     | Required | Description    |
| :-------- | :------- | :------: | :------------- |
| `id`      | `string` |    ✅     | Entry UUID     |
| `fields`  | `object` |    ✅     | Updated fields |

---

### `delete_entry`

Delete an entry.

**Required scope:** `write`

**Parameters:**

| Parameter | Type     | Required | Description    |
| :-------- | :------- | :------: | :------------- |
| `id`      | `string` |    ✅     | Entry UUID     |

---

### `manage_spaces`

Create, switch, or remove spaces.

**Required scope:** `write`

**Parameters:**

| Parameter | Type     | Required | Description                     |
| :-------- | :------- | :------: | :------------------------------ |
| `action`  | `string` |    ✅     | `create`, `switch`, or `remove` |
| `name`    | `string` |    ✅     | Space name                      |

---

### `cloud_sync`

Trigger a cloud synchronization.

**Required scope:** `write`

---

## Admin Tools

### `manage_profiles`

View or change the encryption profile.

**Required scope:** `admin`

---

### `cloud_config`

View or modify cloud provider configuration.

**Required scope:** `admin`

---

### `get_history`

Retrieve vault modification history.

**Required scope:** `admin`

---

### `get_audit_logs`

Read the audit log.

**Required scope:** `admin`

---

## Transaction Guardrails Summary

| Tool            | Uses Transaction | Call returns                              | Commit                        |
| :-------------- | :--------------: | :---------------------------------------- | :---------------------------- |
| `add_entry`     |        ✅         | Your answer, after waiting up to 2 minutes | When you approve the prompt   |
| `edit_entry`    |        ✅         | Your answer, after waiting up to 2 minutes | When you approve the prompt   |
| `delete_entry`  |        ✅         | Your answer, after waiting up to 2 minutes | When you approve the prompt   |
| `manage_spaces` |        ❌         | —                                         | Executes immediately          |
| `get_entry`, `decrypt_entry`, `get_totp`, `search_vault` | With **Ask before secrets** | Your answer, after waiting up to 2 minutes | Runs when you allow it (otherwise immediately) |
| Other read tools |        ❌         | —                                         | Executes immediately          |

---

## Error Codes

| Code                  | Description                        |
| :-------------------- | :--------------------------------- |
| `PERMISSION_DENIED`   | The assistant or token lacks the permission |
| `SESSION_REQUIRED`    | No active APM session              |
| `ENTRY_NOT_FOUND`     | Entry ID/name not found            |
| `TRANSACTION_EXPIRED` | Request expired before you approved it |
| `INVALID_PARAMETERS`  | Missing or malformed parameters    |
| `VAULT_LOCKED`        | Vault is not unlocked              |