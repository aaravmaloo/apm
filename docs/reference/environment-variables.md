# Environment Variables

All environment variables supported by APM.

---

## Core Variables

| Variable           | Description                                              | Default       |
| :----------------- | :------------------------------------------------------- | :------------ |
| `APM_VAULT_PATH`   | Override the vault file location                         | `./vault.dat` |
| `APM_SESSION_ID`   | Scope sessions to a specific shell instance              | `global`      |
| `APM_EPHEMERAL_ID` | Use an ephemeral delegated session instead of the global | (none)        |

---

## Context Variables

| Variable      | Description                                      | Default       |
| :------------ | :----------------------------------------------- | :------------ |
| `APM_ACTOR`   | Identifies the actor in telemetry and audit logs | (system user) |
| `APM_CONTEXT` | Execution context identifier (e.g., `mcp`, `ci`) | (none)        |

---

## Variable Details

### `APM_VAULT_PATH`

Overrides the default vault file location for all commands:

```bash
export APM_VAULT_PATH="/secure/vault.dat"
pm unlock  # Uses /secure/vault.dat instead of ./vault.dat
```

### `APM_SESSION_ID`

Creates independent sessions per terminal. Each unique value gets its own session file:

```bash
# Terminal 1
export APM_SESSION_ID="dev"
pm unlock

# Terminal 2
export APM_SESSION_ID="ops"
pm unlock
# Both terminals have independent sessions
```

Session file naming: `$TEMP/pm_session_{APM_SESSION_ID}.json`

### `APM_EPHEMERAL_ID`

Uses a previously issued ephemeral session for authentication:

```bash
export APM_EPHEMERAL_ID="eps_a1b2c3d4..."
pm get github  # Authenticated via ephemeral session
```

When set, APM validates the ephemeral session's bindings (host, PID, agent) instead of checking the regular session file.

### `APM_ACTOR`

Tags audit log entries and telemetry with the actor name:

```bash
export APM_ACTOR="github-actions"
pm get aws_credentials  # Audit log shows actor = "github-actions"
```

Used by ephemeral sessions to verify agent binding.

### `APM_CONTEXT`

Identifies the execution context:

```bash
export APM_CONTEXT="mcp"  # Marks operations as MCP-initiated
export APM_CONTEXT="ci"   # Marks operations as CI/CD-initiated
```

Affects telemetry recording (e.g., `last_accessor` field in secret telemetry).