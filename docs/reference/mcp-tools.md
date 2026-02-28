# MCP tools reference

The APM MCP server exposes the following tools to AI assistants. Each tool has a JSON schema
defining its input parameters and expected output.

!!! note

    See the [MCP concept](../concepts/mcp.md) for architecture details and the
    [MCP integration guide](../guides/mcp-integration.md) for setup — this document is the full
    tool schema reference.

## list_vault

Lists all entries in the vault grouped by category. Returns titles and metadata only.

### Parameters

None.

### Response

```json
{
  "categories": {
    "Password": ["GitHub", "Gmail", "AWS Console"],
    "API Key": ["Stripe", "OpenAI"],
    "SSH Key": ["Production Server"]
  },
  "total": 6
}
```

### Required permission

`read`

---

## search_vault

Performs fuzzy search across entry names and metadata.

### Parameters

| Parameter | Type   | Required | Description |
| :-------- | :----- | :------- | :---------- |
| `query`   | string | Yes      | Search term |

### Response

```json
{
  "results": [
    { "name": "GitHub", "category": "Password", "score": 0.95 },
    { "name": "GitLab", "category": "Password", "score": 0.72 }
  ]
}
```

### Required permission

`read`

---

## get_entry

Retrieves the full details of a specific entry, including all secret fields.

### Parameters

| Parameter | Type   | Required | Description      |
| :-------- | :----- | :------- | :--------------- |
| `name`    | string | Yes      | Exact entry name |

### Response

```json
{
  "name": "GitHub",
  "category": "Password",
  "username": "aarav@example.com",
  "password": "s3cureP@ssw0rd!",
  "url": "https://github.com",
  "created": "2025-01-15T10:30:00Z",
  "modified": "2025-06-01T14:22:00Z"
}
```

### Required permission

`secrets`

---

## get_totp

Generates a time-based one-time password for a specific entry.

### Parameters

| Parameter | Type   | Required | Description                 |
| :-------- | :----- | :------- | :-------------------------- |
| `name`    | string | Yes      | Entry name with a TOTP seed |

### Response

```json
{
  "code": "482913",
  "remaining_seconds": 18,
  "period": 30
}
```

### Required permission

`totp`

---

## add_entry

Adds a new entry to the vault.

### Parameters

| Parameter  | Type   | Required | Description                        |
| :--------- | :----- | :------- | :--------------------------------- |
| `name`     | string | Yes      | Display name for the entry         |
| `category` | string | Yes      | One of the 22 supported categories |
| `fields`   | object | Yes      | Category-specific fields           |
| `tx_id`    | string | No       | Transaction id returned from preview |
| `approve`  | bool   | No       | Must be `true` to commit a pending transaction |

### Example input

```json
{
  "name": "New Service",
  "category": "Password",
  "fields": {
    "username": "admin",
    "password": "g3n3r@t3d!P@ss",
    "url": "https://newservice.com"
  }
}
```

### Response

```json
{
  "status": "created",
  "name": "New Service"
}
```

### Required permission

`write`

### Transaction guardrails

Mutating tools (`add_entry`, `edit_entry`, `delete_entry`) run in transaction mode:

1. First call without `tx_id` creates a pending transaction and returns a preview.
2. Re-call with `tx_id` and `approve: true` to commit.
3. Successful commits return a cryptographic receipt id.

---

## tx_list

Lists active MCP transactions and their status.

### Parameters

| Parameter | Type    | Required | Description                     |
| :-------- | :------ | :------- | :------------------------------ |
| `limit`   | integer | No       | Max transactions to return      |

### Required permission

`tx_list`

---

## tx_abort

Aborts a pending MCP transaction by id.

### Parameters

| Parameter | Type   | Required | Description            |
| :-------- | :----- | :------- | :--------------------- |
| `tx_id`   | string | Yes      | Pending transaction id |

### Required permission

`tx_abort`
