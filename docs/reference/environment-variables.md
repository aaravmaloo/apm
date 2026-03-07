# Environment variables

APM reads the following variables when set.

## Core

| Variable | Description | Default |
| :-- | :-- | :-- |
| `APM_VAULT_PATH` | Absolute or relative vault path override | `vault.dat` near executable |

## Session and runtime

| Variable | Description | Default |
| :-- | :-- | :-- |
| `APM_SESSION_ID` | Active session identifier (managed by APM) | unset |
| `APM_SESSION_TIMEOUT` | Session timeout hint in minutes | `60` |

## Cloud

| Variable | Description | Default |
| :-- | :-- | :-- |
| `APM_CLOUD_PROVIDER` | Preferred provider (`gdrive`, `github`, `dropbox`) | unset |
| `APM_GITHUB_TOKEN` | GitHub token for sync | unset |
| `APM_GITHUB_REPO` | GitHub repository for sync | unset |

## Security and policy

| Variable | Description | Default |
| :-- | :-- | :-- |
| `APM_SECURITY_PROFILE` | Default encryption profile | `standard` |
| `APM_POLICY_PATH` | YAML policy location | unset |
| `APM_EPHEMERAL_ID` | Ephemeral session id | unset |
| `APM_EPHEMERAL_AGENT` | Ephemeral session agent label | unset |

## MCP

| Variable | Description | Default |
| :-- | :-- | :-- |
| `APM_MCP_TOKEN` | MCP access token | unset |
| `APM_MCP_LOG_LEVEL` | MCP logging level | `info` |

## Plugins

| Variable | Description | Default |
| :-- | :-- | :-- |
| `APM_PLUGIN_DIR` | Override plugin source directory | `<install_root>/plugins` |
