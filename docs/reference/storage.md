# Storage

APM stores data in the following locations. All paths are configurable via
[environment variables](./environment-variables.md).

## Vault file

The primary encrypted vault file.

=== "Windows"

    ```
    %USERPROFILE%\.apm\vault.dat
    ```

=== "macOS and Linux"

    ```
    ~/.apm/vault.dat
    ```

Override with `APM_VAULT_PATH`.

## Configuration directory

APM's configuration files and metadata.

=== "Windows"

    ```
    %USERPROFILE%\.apm\
    ```

=== "macOS and Linux"

    ```
    ~/.apm/
    ```

### Directory contents

| Path             | Description                       |
| :--------------- | :-------------------------------- |
| `vault.dat`      | Primary encrypted vault           |
| `config.yaml`    | User configuration                |
| `policies/`      | Loaded YAML policy files          |
| `plugins_cache/` | Installed plugin manifests        |
| `cloud/`         | Cloud provider tokens (encrypted) |
| `audit.log`      | Tamper-evident audit log          |

## Session storage

Active session keys are stored in platform-specific temporary locations:

=== "Windows"

    ```
    %TEMP%\apm-session-<id>
    ```

=== "macOS and Linux"

    ```
    /tmp/apm-session-<id>
    ```

Session files are memory-only where supported and are wiped on `pm lock` or session timeout.

## Plugin storage

Plugins are stored in the `plugins_cache/` directory within the configuration directory:

```text
~/.apm/plugins_cache/
  backup-tool/
    plugin.json
  audit-ext/
    plugin.json
```

## Cloud provider tokens

OAuth tokens and personal access tokens for cloud providers are encrypted inside the vault:

| Provider     | Token Type                    |
| :----------- | :---------------------------- |
| Google Drive | OAuth2 access + refresh token |
| GitHub       | Personal Access Token         |
| Dropbox      | OAuth2 access + refresh token |

These tokens are never stored in plaintext. They are encrypted alongside your secrets using the
same AES-256-GCM scheme.

## Team edition storage

The team edition uses a separate storage model:

=== "Windows"

    ```
    %USERPROFILE%\.apm-team\
    ```

=== "macOS and Linux"

    ```
    ~/.apm-team/
    ```

| Path           | Description                          |
| :------------- | :----------------------------------- |
| `org.dat`      | Encrypted organization vault         |
| `members/`     | Per-member key material              |
| `departments/` | Department-scoped encryption domains |
