# Environment variables

APM reads the following environment variables to customize behavior. Set these in your shell
profile to persist across sessions.

## Core variables

| Variable              | Description                                                  | Default            |
| :-------------------- | :----------------------------------------------------------- | :----------------- |
| `APM_VAULT_PATH`      | Override the default vault file location                     | `~/.apm/vault.dat` |
| `APM_CONFIG_DIR`      | Override the configuration directory                         | `~/.apm/`          |
| `APM_SESSION_ID`      | Active session identifier (set automatically by `pm unlock`) | None               |
| `APM_SESSION_TIMEOUT` | Session inactivity timeout in minutes                        | `60`               |

## Cloud variables

| Variable             | Description                                            | Default        |
| :------------------- | :----------------------------------------------------- | :------------- |
| `APM_CLOUD_PROVIDER` | Default cloud provider (`gdrive`, `github`, `dropbox`) | None           |
| `APM_GITHUB_TOKEN`   | GitHub Personal Access Token for cloud sync            | None           |
| `APM_GITHUB_REPO`    | GitHub repository name for vault storage               | `vault-backup` |

## Security variables

| Variable               | Description                         | Default    |
| :--------------------- | :---------------------------------- | :--------- |
| `APM_SECURITY_PROFILE` | Default security profile name       | `standard` |
| `APM_POLICY_PATH`      | Path to the active YAML policy file | None       |

## MCP variables

| Variable            | Description                                                 | Default |
| :------------------ | :---------------------------------------------------------- | :------ |
| `APM_MCP_TOKEN`     | MCP access token for the server                             | None    |
| `APM_MCP_LOG_LEVEL` | MCP server log verbosity (`debug`, `info`, `warn`, `error`) | `info`  |

## Plugin variables

| Variable         | Description                         | Default                 |
| :--------------- | :---------------------------------- | :---------------------- |
| `APM_PLUGIN_DIR` | Override the plugin cache directory | `~/.apm/plugins_cache/` |

## Team variables

| Variable       | Description                              | Default        |
| :------------- | :--------------------------------------- | :------------- |
| `APM_TEAM_DIR` | Override the team edition data directory | `~/.apm-team/` |

## Platform-specific defaults

=== "Windows"

    | Variable         | Resolved Default               |
    | :--------------- | :----------------------------- |
    | `APM_VAULT_PATH` | `%USERPROFILE%\.apm\vault.dat` |
    | `APM_CONFIG_DIR` | `%USERPROFILE%\.apm\`          |
    | `APM_TEAM_DIR`   | `%USERPROFILE%\.apm-team\`     |

=== "macOS and Linux"

    | Variable         | Resolved Default   |
    | :--------------- | :----------------- |
    | `APM_VAULT_PATH` | `~/.apm/vault.dat` |
    | `APM_CONFIG_DIR` | `~/.apm/`          |
    | `APM_TEAM_DIR`   | `~/.apm-team/`     |
