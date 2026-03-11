# Policies Reference

YAML policy schema for the APM policy engine.

---

## Schema

```yaml
name: string (required)
description: string (optional)

password_policy:
  min_length: integer (default: 8)
  require_uppercase: boolean (default: false)
  require_numbers: boolean (default: false)
  require_symbols: boolean (default: false)

rotation_policy:
  rotate_every_days: integer (default: 0, 0 = disabled)
  notify_before_days: integer (default: 0)

classification:
  entry_name: privilege_level
  # privilege_level: critical | root | admin | elevated | normal
```

---

## Field Details

### `password_policy`

| Field               | Type   | Default | Description                         |
| :------------------ | :----- | :------ | :---------------------------------- |
| `min_length`        | `int`  | 8       | Minimum characters                  |
| `require_uppercase` | `bool` | false   | At least one uppercase letter (A-Z) |
| `require_numbers`   | `bool` | false   | At least one digit (0-9)            |
| `require_symbols`   | `bool` | false   | At least one special character      |

### `rotation_policy`

| Field                | Type  | Default | Description                      |
| :------------------- | :---- | :------ | :------------------------------- |
| `rotate_every_days`  | `int` | 0       | Rotation interval (0 = disabled) |
| `notify_before_days` | `int` | 0       | Pre-rotation notification window |

### `classification`

Maps entry names to privilege levels. Used by the trust scoring system:

| Level      | Trust Penalty | Description            |
| :--------- | :------------ | :--------------------- |
| `critical` | −15           | Highest privilege      |
| `root`     | −15           | Root-level access      |
| `admin`    | −12           | Administrative access  |
| `elevated` | −8            | Above-normal privilege |
| `normal`   | 0             | Standard access        |

---

## Loading Policies

```bash
pm policy load ./policies/
```

Loads all `.yaml` and `.yml` files from the directory. Multiple files are merged in filesystem order.

---

## Examples

### Minimal Policy

```yaml
name: basic
password_policy:
  min_length: 12
```

### Enterprise Policy

```yaml
name: enterprise
description: Corporate security standard

password_policy:
  min_length: 16
  require_uppercase: true
  require_numbers: true
  require_symbols: true

rotation_policy:
  rotate_every_days: 60
  notify_before_days: 14

classification:
  aws_root_key: critical
  production_db: critical
  staging_api: elevated
  ci_token: normal
```

### Developer Team Policy

```yaml
name: dev-team
description: Balanced policy for development teams

password_policy:
  min_length: 12
  require_uppercase: true
  require_numbers: true
  require_symbols: false

rotation_policy:
  rotate_every_days: 180
  notify_before_days: 30

classification:
  prod_ssh_key: critical
  dev_api_key: normal
```