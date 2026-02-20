# Policies reference

Policy files are YAML documents that define security standards enforced by APM's
[policy engine](../concepts/policy-engine.md).

## Full schema

```yaml
name: <string>
version: <semver>

password:
  min_length: <integer>
  max_length: <integer>
  require_uppercase: <boolean>
  require_lowercase: <boolean>
  require_digits: <boolean>
  require_symbols: <boolean>
  max_age_days: <integer>
  disallow_reuse: <integer>

audit:
  require_rotation_check: <boolean>
  alert_on_weak: <boolean>
  alert_on_duplicate: <boolean>
  alert_on_expired: <boolean>
```

## Field reference

### Top-level fields

| Field     | Type   | Required | Description      |
| :-------- | :----- | :------- | :--------------- |
| `name`    | string | Yes      | Policy name      |
| `version` | string | Yes      | Semantic version |

### password

| Field               | Type    | Default | Description                                     |
| :------------------ | :------ | :------ | :---------------------------------------------- |
| `min_length`        | integer | 8       | Minimum password length                         |
| `max_length`        | integer | 128     | Maximum password length                         |
| `require_uppercase` | boolean | false   | Require at least one uppercase letter           |
| `require_lowercase` | boolean | false   | Require at least one lowercase letter           |
| `require_digits`    | boolean | false   | Require at least one digit                      |
| `require_symbols`   | boolean | false   | Require at least one symbol                     |
| `max_age_days`      | integer | None    | Maximum password age before rotation warning    |
| `disallow_reuse`    | integer | 0       | Number of previous passwords to check for reuse |

### audit

| Field                    | Type    | Default | Description                                 |
| :----------------------- | :------ | :------ | :------------------------------------------ |
| `require_rotation_check` | boolean | false   | Flag expired passwords during health audits |
| `alert_on_weak`          | boolean | false   | Flag passwords below policy requirements    |
| `alert_on_duplicate`     | boolean | false   | Flag duplicate passwords across entries     |
| `alert_on_expired`       | boolean | false   | Flag entries past `max_age_days`            |

## Example policies

### Minimal (personal use)

```yaml
name: personal
version: 1.0

password:
  min_length: 12
  require_digits: true
```

### Corporate standard

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
  alert_on_duplicate: true
  alert_on_expired: true
```

### High-security

```yaml
name: high-security
version: 1.0

password:
  min_length: 20
  require_uppercase: true
  require_lowercase: true
  require_digits: true
  require_symbols: true
  max_age_days: 30
  disallow_reuse: 10

audit:
  require_rotation_check: true
  alert_on_weak: true
  alert_on_duplicate: true
  alert_on_expired: true
```
