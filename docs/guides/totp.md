# Generating TOTP codes

APM supports interactive and direct TOTP retrieval.

## Show all codes

```console
$ pm totp
```

Behavior:

- lists all TOTP entries in current space
- refreshes code countdown continuously
- `Enter` copies selected code
- `1-9` copies by visible index
- `Shift+Up` / `Shift+Down` reorders entries and persists priority

## Fast copy by entry name

```console
$ pm totp github
```

If a match is found, the code is copied directly to clipboard.

## Domain links for autofill

Link an existing TOTP entry to a domain:

```console
$ pm autocomplete link-totp
domain: https://www.github.com
link-totp-id: 4
```

This improves intelligent autofill matching for OTP prompts.

## Troubleshooting

- Ensure system clock is accurate.
- Verify secret was added correctly.
- If multiple similar entries exist, reorder frequently used ones to top.
