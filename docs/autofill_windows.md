# APM Autofill on Windows

APM autofill on Windows is daemon-based and works system-wide without a browser extension.

## Command model

- `pm autofill start|stop|status|list-profiles`
- `pm autocomplete enable` registers daemon autostart on login and starts now
- `pm autocomplete start|stop` manual daemon control
- `pm autocomplete window enable|disable|status` toggles popup hints
- `pm unlock` unlocks both the CLI session and autofill daemon vault state
- `pm lock` locks both the CLI session and autofill daemon vault state
- `pm autocomplete link-totp` links an existing TOTP entry to a domain

## Hotkey

Default hotkey: `CTRL+SHIFT+L`. You can override it when starting the daemon.

## Runtime behavior

- The daemon watches the active window context.
- If a credential-like form is detected, it shows a popup hint.
- On hotkey press, it resolves a match and injects the sequence.
- The clipboard is not used for core typing.

## Security model

- Vault starts locked and rejects requests until unlocked.
- Decrypted data is held in memory only.
- Daemon IPC is loopback + bearer-token protected.

## TOTP linking

Use `pm autocomplete link-totp` to bind a TOTP entry to a domain. This helps the engine select the correct OTP when multiple TOTP entries exist.