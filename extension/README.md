# APM Passkeys (browser extension)

Save and use **WebAuthn passkeys** with the APM vault. When a website creates a
passkey, a popup asks which vault entry to save it to — like 1Password /
Bitwarden. Passkeys (including the private key, as a JWK) are stored encrypted
inside your vault, never in the browser.

## Architecture

```
┌─ Browser (Chromium) ──────────────────────────────┐    ┌─ APM desktop app ──┐
│ content_main.js  (MAIN world)                     │    │                    │
│   wraps navigator.credentials.create/get and      │    │  main.js bridge    │
│   completes the WHOLE ceremony in-page with       │    │  http://127.0.0.1: │
│   WebCrypto (P-256 keygen → attestationObject,    │    │        41417       │
│   pure-JS ECDSA signing for login)                │    │   · /api/info      │
│        │  CustomEvent                             │    │   · /api/entries   │
│ content.js  (isolated world)                      │    │   · /api/passkeys  │
│        │  chrome.runtime                          │    │   · /api/credentials│
│ background.js (service worker)                    │◄──►│                    │
│   · coordinates create/get captures               │    │  encrypted vault   │
│   · captures privateKey JWK after create          │    │  file + lgit audit │
│   · fetches saved creds from the bridge for login │    │                    │
│   · badge + notification → popup                  │    │                    │
│ popup/  (APM-styled "save to which entry?" UI)    │    │                    │
└───────────────────────────────────────────────────┘    └────────────────────┘
```

The ceremony is completed **inside the page** (the same approach Bitwarden's
extension uses). No `chrome.debugger`, no CDP virtual authenticators — which
means no DevTools conflicts, no debugging banner, and no race with Chrome's
native macOS/Windows passkey sheet: the page gets a fully-formed
`PublicKeyCredential` back before the browser ever starts its own flow, so the
OS sheet never appears.

The extension **cannot decrypt the vault** — argon2id isn't available in
browsers. Instead it talks to the running APM app over a loopback HTTP bridge
(127.0.0.1:41417), authenticated with a **bearer token you pair once**. This is
the same pattern as KeePassXC-Browser.

## Install (Chromium: Chrome, Edge, Arc, Brave)

1. Build/run the APM desktop app (`GUI/`).
2. Open **Settings → Passkeys** in APM and copy the pairing token.
3. Open `chrome://extensions` → enable **Developer mode** → **Load unpacked** →
   select this `extension/` folder.
4. Pin **APM Passkeys**, click it, paste the token → **Connect**.

## How it behaves

- **Create a passkey** on any site: the page's `navigator.credentials.create`
  is answered in-page — the engine generates an ECDSA P-256 keypair, builds a
  spec-correct attestation object (CBOR, `fmt: none`, `authData` with rpIdHash
  + flags + counter + AAGUID + credentialId + COSE key), and returns a complete
  `PublicKeyCredential` to the site. The private key (JWK) is captured and the
  extension shows a badge + notification. Open the popup → search entries (or
  add a new one) → **Save**. The passkey lands in the vault under that entry
  and an audit event + lgit commit are written.
- **Use a passkey to log in** (button-triggered `credentials.get`, not
  conditional UI): the background fetches matching saved credentials from the
  bridge and the engine signs the assertion (pure-JS ECDSA over
  `authData || SHA256(clientDataJSON)`, DER signature, signCount incremented).
  If no match, the native flow is untouched.
- If APM is **locked**, the popup tells you to unlock first — nothing is saved
  until then, and the capture waits (badge stays).
- If anything fails (not paired, timeout), the engine transparently falls
  through to the native flow — sites are never broken.

## Permissions

Only `storage` and `notifications` — no `debugger`, no `tabs`, no host
permissions beyond the localhost bridge. Install shows no scary warnings.

## Security

- Bridge is loopback-only (`127.0.0.1`) and bearer-token protected; the token is
  generated once and stored with `0600` perms next to the vault config.
- `/api/entries` never returns secrets — only names/subtitles for the picker.
- The passkey private key is stored inside the encrypted vault file; its
  security is the vault's security. The extension holds a capture in
  `chrome.storage.session` only until you save or dismiss it.
- **Known limitation:** the CLI's Go parser drops unknown JSON fields, so a CLI
  write (e.g. `apm set`) after a passkey save would discard `passkeys`. Keep
  passkey operations in the GUI (which preserves them) until the CLI learns the
  field.

## Limitations (v1)

- Chromium only (no Firefox/Safari yet).
- Conditional UI (the inline "sign in with a passkey" dropdown) isn't
  intercepted yet — explicit button-triggered flows are.
- **ES256 only**: the engine can mint ECDSA P-256 (alg `-7`) credentials.
  Sites that only accept RS256 (alg `-257`) are left to the native flow.
- Create ceremonies that require platform attestation (`attestation:
  "platform"`/`"enterprise"` with a strict challenge) are answered with
  `fmt: none` — most sites accept this; a few strict enterprise ones won't.
- The `min`/`max`/`excludeCredentials` hints of a create ceremony are ignored
  (same as most managers).
- Sites that do a strict `credential instanceof PublicKeyCredential` check
  (rare) will reject the returned plain object — most sites, including
  webauthn.io, use the object shape only.
- Icons are generated by `scripts/gen-icons.mjs` (zero deps).

## Test it

- `node --check src/*.js src/popup/popup.js` — syntax check.
- `node test/webauthn-core.test.cjs` — unit tests: the pure-JS ECDSA signer is
  cross-verified against `node:crypto`, and the registration/assertion
  structure is decoded and validated end-to-end (CBOR, authData, signatures).
- Try a real ceremony on https://webauthn.io (Register), then check the entry
  in APM, and log in again on the same site with **Login** — the second flow
  uses the saved passkey.
