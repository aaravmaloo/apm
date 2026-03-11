# Generating TOTP Codes

APM supports **Time-Based One-Time Passwords** (TOTP) for two-factor authentication. You can store TOTP secrets alongside your credentials, view live codes with countdown timers, and link them to the autofill daemon.

---

## Adding a TOTP Entry

```bash
pm add
# Select type: 2 (TOTP)
# Account: github.com
# Secret: JBSWY3DPEHPK3PXP  (your TOTP secret key)
```

!!! tip
    Most services show the TOTP secret as a QR code during 2FA setup. Look for a "Can't scan? Show secret key" link to get the text secret for APM.

---

## Viewing TOTP Codes

### Interactive List

```bash
pm totp
```

Opens an interactive view showing all your TOTP entries with:

- **Live codes** that update every 30 seconds
- **Countdown timers** showing time until the next code
- **Persistent ordering** — reorder entries and the order is saved to your vault

Keyboard controls in the interactive TOTP view:

| Key       | Action                       |
| :-------- | :--------------------------- |
| ++enter++ | Copy the selected code       |
| ++up++    | Move selection up            |
| ++down++  | Move selection down          |
| ++u++     | Move entry up in the order   |
| ++d++     | Move entry down in the order |
| ++q++     | Quit the TOTP viewer         |

### Direct Copy

Copy a specific TOTP code without entering the interactive view:

```bash
pm totp github
```

This fuzzy-matches the entry name and copies the current code to your clipboard.

---

## TOTP Order Persistence

When you reorder entries in the interactive TOTP view (using ++u++ and ++d++ keys), the ordering is **persisted in your encrypted vault**. This means your most-used 2FA accounts stay at the top across sessions and devices (via cloud sync).

---

## Linking TOTP to Autofill (Windows)

If you use the autofill daemon, you can link a TOTP entry to a domain so that fill sequences can include the OTP code:

```bash
pm autocomplete link-totp
```

This interactive command lets you select a TOTP entry and bind it to a domain/service. When the autofill daemon fills credentials for that domain, it can include the TOTP code in the sequence using the `{TOTP}` token.

---

## How TOTP Works

APM generates TOTP codes using the standard [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) algorithm:

1. The TOTP secret is stored in the vault as a base32-encoded string
2. The current Unix timestamp is divided into 30-second intervals
3. An HMAC-SHA1 hash is computed using the secret and the interval counter
4. A 6-digit code is extracted from the hash using dynamic truncation

The code refreshes every 30 seconds. APM's display includes a countdown timer so you know when to expect a new code.

---

## Next Steps

- **[Autofill on Windows](../autofill_windows.md)** — Set up autofill with TOTP linking
- **[Vault Management](vault-management.md)** — Managing all entry types