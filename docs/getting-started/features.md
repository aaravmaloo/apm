# Features

APM provides essential features for credential management — from storing simple passwords to
managing complex infrastructure secrets across teams.

APM's interface can be broken down into sections, which are usable independently or together.

## Vault Management

Creating, storing, and retrieving secrets in your encrypted vault.

- `pm init`: Initialize a new zero-knowledge encrypted vault.
- `pm add`: Interactive menu to store any of the 22 supported secret types.
- `pm get [query]`: Fuzzy search and display entry details.
- `pm edit [name]`: Interactive modification of existing entry metadata.
- `pm del [name]`: Permanent deletion of an entry from the vault.
- `pm gen`: High-entropy password generator.

See the [vault management guide](../guides/vault-management.md) to get started.

## Session Management

Controlling access to your decrypted vault.

- `pm unlock`: Start a session-scoped unlock instance with inactivity timeout.
- `pm lock`: Immediately terminate and wipe the active session.

See the [sessions guide](../guides/sessions.md) to get started.

## TOTP

Generating time-based one-time passwords.

- `pm totp show`: Real-time generation of 2FA codes with live countdowns.

See the [TOTP guide](../guides/totp.md) to get started.

## Cloud Synchronization

Syncing your vault across devices using cloud providers.

- `pm cloud init <provider>`: Set up synchronization with Google Drive, GitHub, or Dropbox.
- `pm cloud push`: Upload the vault to the configured provider.
- `pm cloud pull`: Download and merge the vault from the provider.

See the [cloud sync guide](../guides/cloud-sync.md) to get started.

## Authentication & Recovery

Managing your master password and recovery options.

- `pm auth email`: Update the associated email address.
- `pm auth reset`: Reset the master password (requires current password).
- `pm auth change`: Change the master password.
- `pm auth recover`: Recover vault access via recovery key and identity verification.

See the [recovery concept](../concepts/recovery.md) for details.

## Security & Auditing

Inspecting the security posture of your vault.

- `pm health`: Dashboard with security scoring and vulnerability reporting.
- `pm audit`: Tamper-evident log of every vault interaction.
- `pm cinfo`: Inspect current vault cryptographic parameters.

See the [encryption concept](../concepts/encryption.md) for details.

## Import & Export

Migrating data to and from APM.

- `pm import`: Ingest data from external files (JSON, CSV, KDBX).
- `pm export`: Securely dump vault data to encrypted or plaintext formats.

See the [import/export guide](../guides/import-export.md) to get started.

## Policy & Compliance

Enforcing organizational security standards.

- `pm policy load`: Load a YAML-based password policy.
- `pm policy show`: Display the active policy.
- `pm policy clear`: Remove the active policy.

See the [policy engine concept](../concepts/policy-engine.md) for details.

## Plugins

Extending APM with declarative plugins.

- `pm plugins add <name>`: Install a plugin from the marketplace.
- `pm plugins local <path>`: Install a plugin from a local directory.
- `pm plugins list`: List installed plugins.
- `pm plugins remove <name>`: Uninstall a plugin.

See the [plugins guide](../guides/plugins.md) to get started.

## MCP Server

Connecting AI assistants to your vault.

- `pm mcp token`: Generate an access token with granular permissions.
- `pm mcp serve`: Start the Model Context Protocol server.
- `pm mcp config`: Display the configuration snippet for your AI client.

See the [MCP integration guide](../guides/mcp-integration.md) to get started.

## Namespaces

Organizing secrets into isolated compartments.

- `pm space list`: List all namespaces.
- `pm space create <name>`: Create a new namespace.
- `pm space switch <name>`: Switch to a different namespace.

See the [vault management guide](../guides/vault-management.md) for details.

## Security Profiles

Tuning encryption strength.

- `pm profile list`: List available security profiles.
- `pm profile set <name>`: Switch to a different profile.
- `pm sec_profile create`: Create a custom security profile.

See the [security profiles concept](../concepts/security-profiles.md) for details.

## Utility

Managing APM itself.

- `pm info`: Display version, install path, and environment details.
- `pm update`: Automated self-update engine to fetch the latest builds.

## The Team Interface

Managing credentials across organizations with RBAC.

- `pm-team init`: Set up an organization.
- `pm-team dept`: Manage departments as isolated encryption domains.
- `pm-team user`: Onboard and manage team members.
- `pm-team approvals`: Handle pending sensitive entry requests.

See the [team edition documentation](../team/index.md) to get started.

## Next steps

Read the [guides](../guides/index.md) for an introduction to each feature, check out the
[concept](../concepts/index.md) pages for in-depth details about APM's features, or learn how to
[get help](./help.md) if you run into any problems.
