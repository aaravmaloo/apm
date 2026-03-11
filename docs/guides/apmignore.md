# Using .apmignore

`.apmignore` controls what APM excludes from cloud upload payloads. It is evaluated during `pm cloud sync` before encryption and upload.

## File location

Place `.apmignore` in the current working directory or next to your vault file. APM loads the nearest applicable file.

## Sections

- `[spaces]` ignores whole spaces.
- `[entries]` ignores `space:type:name` patterns with wildcards.
- `[vocab]` ignores words from vocabulary export.
- `[cloud-specific-ignore]` ignores entries only for a provider.
- `[misc]` contains flags such as `ignore:vocab`.

## Example

```ini
[spaces]
private
archive_*

[entries]
work:notes:*token*
*:password:*legacy*

[cloud-specific-ignore]
dropbox:work:password:legacy_admin

[misc]
ignore:vocab
```

## Notes

- Use `ignore:vocab` to strip the compressed vocabulary from cloud uploads.
- Keep vocab rules separate from entry rules to avoid confusion.
- Provider-specific ignores are useful for multi-cloud strategies.