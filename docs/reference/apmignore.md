# .apmignore reference

`.apmignore` controls vault data excluded from cloud upload payloads.

## Resolution order

APM searches for `.apmignore` in:

1. current working directory
2. vault directory

First matching file is used.

## Syntax

Sections:

- `[spaces]`
- `[entries]`
- `[vocab]`
- `[cloud-specific-ignore]`
- `[misc]`

Comments:

- `#` inline and full-line comments supported

Patterns:

- supports `*`, `?`, `[]` wildcard syntax

## Entry rule formats

### Entries

```ini
space:type:name
```

### Cloud-specific entries

```ini
provider:space:type:name
```

## Type normalization examples

- `notes`, `secure-notes` -> `note`
- `apikey`, `api-keys` -> `api-key`
- `otp` -> `totp`
- `image` -> `photo`

## Misc flags

### `ignore:vocab`

Strips compressed vocab from cloud-uploaded vault payload.

## Examples

See `examples/.apmignore`.
