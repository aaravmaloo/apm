# Using .apmignore

`.apmignore` controls what APM excludes from cloud uploads.

## File location

Place `.apmignore` in:

- current working directory, or
- same directory as your vault file

## Sections

## `[spaces]`

Ignore whole spaces.

```ini
[spaces]
private_space
archive_*
```

## `[entries]`

Ignore by `space:type:name` with wildcards.

```ini
[entries]
work:notes:*
*:password:*token*
```

## `[vocab]`

Case-sensitive word ignore list for vocabulary export filtering.

```ini
[vocab]
'cause
A
```

## `[cloud-specific-ignore]`

Ignore only for one provider (`provider:space:type:name`).

```ini
[cloud-specific-ignore]
dropbox:work:password:legacy_admin
GitHub:personal:note:journal
```

## `[misc]`

Special flags.

```ini
[misc]
ignore:vocab
```

`ignore:vocab` strips compressed vocab data from cloud-uploaded vault payloads.

## Example

Full example file:

- `examples/.apmignore`

## Type aliases

Common type aliases are normalized:

- `notes` -> `note`
- `apikey` -> `api-key`
- `otp` -> `totp`
- `image` -> `photo`

## Wildcards

Supported pattern syntax:

- `*` any sequence
- `?` single char
- `[]` character class

## Validation tips

1. Start with one rule and run `pm cloud sync`.
2. Add provider-specific rules only when needed.
3. Keep vocab ignore separate from entry ignore to avoid confusion.
