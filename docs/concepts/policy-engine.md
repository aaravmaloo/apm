# Policy engine

APM enforces security standards through a flexible, YAML-based policy engine. Policies define
requirements for password complexity, rotation schedules, and other compliance rules.

!!! note

    See the [vault management guide](../guides/vault-management.md) for an introduction to
    working with the vault — this document discusses policy enforcement in depth.

## How policies work

Policies are YAML files that define security rules. When a policy is active, APM validates entries
against these rules during `pm add` and reports violations during `pm health` audits.

## Policy file format

A typical policy file:

```yaml
name: corporate-standard
version: 1.0

password:
  min_length: 14
  require_uppercase: true
  require_lowercase: true
  require_digits: true
  require_symbols: true
  max_age_days: 90
  disallow_reuse: 5

audit:
  require_rotation_check: true
  alert_on_weak: true
```

## Loading a policy

Load a policy file into the active vault:

```console
$ pm policy load ./policies/corporate-standard.yaml
Policy "corporate-standard" loaded successfully.
```

## Inspecting the active policy

Display the currently active policy:

```console
$ pm policy show
Active Policy: corporate-standard v1.0

Password Requirements:
  Min Length:        14
  Uppercase:         Required
  Lowercase:         Required
  Digits:            Required
  Symbols:           Required
  Max Age:           90 days
  Reuse Prevention:  Last 5
```

## Clearing a policy

Remove the active policy:

```console
$ pm policy clear
Policy cleared.
```

## Policy enforcement

### During entry creation

When adding a new password entry, APM validates the password against the active policy:

```console
$ pm add
? Select category: Password
? Account name: Production DB
? Password: weak

Policy violation: Password must be at least 14 characters.
Policy violation: Password must contain uppercase letters.
Policy violation: Password must contain digits.
Policy violation: Password must contain symbols.
```

### During health audits

The `pm health` command reports policy violations across your entire vault:

```console
$ pm health
Security Score: 72/100

Violations:
  - 3 passwords below minimum length
  - 5 passwords older than 90 days
  - 2 passwords missing required symbols
```

## Next steps

See the [sessions concept](./sessions.md) for details on session management, or learn about
[cloud synchronization](./cloud-sync.md).
