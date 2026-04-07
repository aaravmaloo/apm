# Features

This page lists the capabilities that are implemented in the current codebase.

## Personal vault

- Local encrypted vault stored as `APMVAULT`, current format v4
- 25 structured personal secret types
- Spaces for compartmentalizing entries inside one vault
- Interactive search, details, editing, deletion, and TOTP access
- Password generation, audit logging, trust scoring, and health scoring

## Crypto and profiles

- Built-in profiles: `standard`, `hardened`, `paranoid`, `legacy`
- Cipher support: `aes-gcm` and `xchacha20-poly1305`
- Versioned header metadata for vault crypto parameters
- `pm cinfo` and `pm profile` for inspection and tuning

## Sessions and automation

- Standard unlock sessions with expiry and inactivity controls
- Read-only session mode
- Shell-scoped sessions via `APM_SESSION_ID`
- Ephemeral delegated sessions via `pm session issue`
- Shell injection with `pm inject` and `.apminject`

## Recovery and auth

- Recovery email registration with SMTP verification
- Recovery key generated during setup and shown once
- One-time recovery codes
- Recovery passkey registration and verification
- Quorum share setup and trustee-based recovery
- Security alert level controls and recovery-related status commands

## Cloud sync

- Google Drive sync
- GitHub sync
- Dropbox sync
- Provider diff and selective merge flow
- Provider-specific `.apmignore` filtering before upload

## Extensibility

- Manifest-based plugins
- Hook execution around vault actions
- Plugin marketplace commands
- Runtime-added plugin commands
- Built-in MCP server with permission-scoped tokens

## Desktop integration

- Windows autofill daemon
- Autocomplete popup and domain matching
- TOTP linking for autofill flows
- Optional Face ID command tree when built with face-recognition support
- Bubble Tea TUI entry point through `pm tui`

## Team edition

The separate `pm-team` module adds:

- organizations
- departments
- roles and permission overrides
- approval workflows
- shared entry management
