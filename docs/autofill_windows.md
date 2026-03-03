# APM Autofill (Windows, System-Wide)

This implementation is system-wide only and does not require a browser extension.

## Architecture

```
pm CLI -> APM Autofill Daemon -> Windows System Autofill Engine
```

- `pm autofill start|stop|status` controls daemon lifecycle.
- `pm vault unlock|lock` controls daemon vault lock state.
- Hotkey presses are handled by the daemon and translated into secure auto-type actions.

## Security

- Vault starts locked.
- All autofill requests are refused when locked with `VaultLockedError`.
- Decrypted vault data remains in memory only.
- Passwords and TOTP secrets are never written to disk or logs.
- IPC is loopback-only and bearer-token authenticated.
- Clipboard is not used.

## System Autofill Behavior

- Global hotkey default: `CTRL+SHIFT+ALT+A`.
- On hotkey:
  1. Detect active window title and process.
  2. Read UI hints from Windows UI Automation:
     - fast focused-control read first
     - bounded subtree fallback only for login/OTP-like windows
     - hard timeout to avoid hotkey latency
  3. Intelligently search vault password + TOTP entries.
  4. Select a single deterministic match or return multiple-match state.
  5. Simulate user input with secure key injection.

### Intelligent Search

- Uses account/domain/title/process matching.
- Uses focused/email UI hints when available (for multi-account disambiguation).
- Supports TOTP-only flows (for example, 2FA pages).
- If window looks like OTP verification and TOTP is available, default sequence is `{TOTP}`.

### Sequence

Supported tokens:
- `{USERNAME}`
- `{PASSWORD}`
- `{TOTP}`
- `{TAB}`
- `{ENTER}`

Default login sequence:
- `{USERNAME}{TAB}{PASSWORD}{ENTER}`

## Commands

- `pm autofill start`
- `pm autofill stop`
- `pm autofill status`
- `pm autofill list-profiles`
- `pm vault unlock`
- `pm vault lock`

## Quick Test

1. Start daemon:
   - `pm --vault C:\path\to\vault.dat autofill start`
2. Unlock daemon vault:
   - `pm --vault C:\path\to\vault.dat vault unlock`
3. Focus target window (login or OTP screen).
4. Press `CTRL+SHIFT+ALT+A`.
5. Lock and stop when finished:
   - `pm --vault C:\path\to\vault.dat vault lock`
   - `pm --vault C:\path\to\vault.dat autofill stop`
