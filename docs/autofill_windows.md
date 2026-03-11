# APM Autofill on Windows

APM autofill on Windows is daemon-based and works system-wide without a browser extension.

## Command model

- `pm autofill start|stop|status|list-profiles`
- `pm autocomplete enable` registers daemon autostart on login (Windows) and starts now
- `pm autocomplete start|stop` manual daemon control
- `pm autocomplete window enable|disable` toggles popup hints
- `pm unlock` unlocks both the CLI session and autofill daemon vault state
- `pm lock` locks both the CLI session and autofill daemon vault state
- `pm autocomplete link-totp` links an existing TOTP entry to a domain

The legacy `pm vault unlock|lock` workflow is removed from normal usage.

## Hotkey

Default hotkey: `CTRL+SHIFT+L`

You can override it when starting the daemon:

```console
$ pm autofill start --hotkey CTRL+SHIFT+L
```

## Runtime behavior

When the daemon is running, it continuously watches the active window context.

If a credential-like form is detected, APM shows a transient popup:

- `Detected an entry. Press CTRL+SHIFT+L to add it to the vault`

If a matching vault entry is found for the active context, APM shows:

- `Autocomplete found for the website. Press CTRL+SHIFT+L for completion`

On hotkey press, APM resolves the best match and auto-types using secure key injection.

## Popup UX

On Windows, the daemon renders a native WPF popup with:

- black background
- rounded corners
- fade-in / fade-out animation
- close `x` button
- 5 second auto-dismiss

Disable popup hints:

```console
$ pm autocomplete window disable
```

## TOTP linking

To bind an existing TOTP to a domain:

```console
$ pm autocomplete link-totp
domain: https://www.github.com
link-totp-id: 4
```

This mapping applies to the domain and subdomain matching flow used by intelligent autofill.

## Security model

- Vault starts locked.
- Requests are rejected while locked (`VaultLockedError`).
- Decrypted data is held in memory only.
- Secrets are wiped on lock or daemon shutdown.
- Daemon IPC is loopback + bearer-token protected.
- Clipboard is not used by core autofill typing.

## Smoke test

```console
$ pm --vault C:\path\to\vault.dat autofill start
$ pm --vault C:\path\to\vault.dat unlock
# focus target login window
# press CTRL+SHIFT+L
$ pm --vault C:\path\to\vault.dat lock
$ pm --vault C:\path\to\vault.dat autofill stop
```
