// APM Passkeys — background service worker.
//
// The WebAuthn ceremony itself runs INSIDE the page (see content_main.js —
// WebCrypto keygen + attestation object, the Bitwarden approach). This worker
// is only responsible for:
//   1. Receiving completed ceremonies ('create-result') and staging the private
//      key for the "save to which entry?" popup.
//   2. Serving saved passkeys to pages for login ('get-intent').
//   3. Talking to the APM desktop app over the loopback bridge (127.0.0.1:41417,
//      bearer token) to list entries and persist passkeys.
'use strict';

const BRIDGE_PORT = 41417;
const BRIDGE_BASE = 'http://127.0.0.1:' + BRIDGE_PORT;

// ── Loopback bridge client ────────────────────────────────────────────────────
const bridge = {
  token: null,

  async loadToken() {
    const r = await chrome.storage.local.get('apmBridgeToken');
    this.token = (r && r.apmBridgeToken) || null;
    return this.token;
  },

  async saveToken(token) {
    this.token = token || null;
    await chrome.storage.local.set({ apmBridgeToken: this.token });
  },

  async request(path, options = {}) {
    const headers = Object.assign(
      { 'Content-Type': 'application/json' },
      options.headers || {}
    );
    if (this.token) headers['X-APM-Token'] = this.token;
    let res;
    try {
      res = await fetch(BRIDGE_BASE + path, Object.assign({}, options, { headers }));
    } catch (_) {
      return { status: 0, body: null };
    }
    let body = null;
    try { body = await res.json(); } catch (_) {}
    return { status: res.status, body };
  },

  async info() {
    return this.request('/api/info');
  },

  async entries() {
    return this.request('/api/entries');
  },

  async credentialsFor(rpId) {
    return this.request('/api/credentials?rpId=' + encodeURIComponent(rpId));
  },

  async savePasskey(payload) {
    return this.request('/api/passkeys', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async markUsed(payload) {
    return this.request('/api/passkeys/use', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async passkeys() {
    return this.request('/api/passkeys');
  },

  async removePasskey(credentialId) {
    return this.request('/api/passkeys/remove', {
      method: 'POST',
      body: JSON.stringify({ credentialId }),
    });
  },

  async renamePasskey(credentialId, label) {
    return this.request('/api/passkeys/rename', {
      method: 'POST',
      body: JSON.stringify({ credentialId, label }),
    });
  },
};

// ── State ─────────────────────────────────────────────────────────────────────
let pendingCapture = null; // { rpId, credentialId, userHandle, signCount, privateKey, ... }
let lastIntentError = null; // surfaced in the popup so failures aren't silent
// Per-credential assertion counter. The vault stores the LAST count used; each
// login must sign with a strictly larger one or the RP rejects the response
// ("sign count was not greater than current count"). This map is the extension's
// own record of the next counter, so a failed bridge write can never make us
// reuse a count. Survives worker restarts via chrome.storage.session.
let signCounts = {};

// MV3 chrome.* APIs return promises; some calls (e.g. action.openPopup outside
// a user gesture) legitimately reject. try/catch can't catch promise rejections,
// so route every fire-and-forget chrome.* call through this.
function noop(p) { if (p && typeof p.catch === 'function') p.catch(() => {}); }

// ── Capture bookkeeping ───────────────────────────────────────────────────────

function stageCapture(capture) {
  if (!capture || !capture.credentialId || !capture.privateKey) {
    lastIntentError = 'Page returned an incomplete passkey (credentialId/privateKey missing).';
    return;
  }
  lastIntentError = null;
  pendingCapture = capture;
  noop(chrome.storage.session.set({ apmPendingCapture: capture }));
  noop(chrome.action.setBadgeBackgroundColor({ color: '#0a84ff' }));
  noop(chrome.action.setBadgeText({ text: '1' }));
  notifyCapture();
}

async function clearCapture() {
  pendingCapture = null;
  await chrome.storage.session.remove('apmPendingCapture');
  noop(chrome.action.setBadgeText({ text: '' }));
}

function notifyCapture() {
  try {
    noop(chrome.notifications.create('apm-passkey-capture', {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/icon-128.png'),
      title: 'Passkey created',
      message: 'Save it to an APM entry?',
      priority: 2,
    }));
  } catch (_) {}
  // chrome.action.openPopup() ONLY works from a real user gesture (notification
  // or badge click). Calling it from a timer always rejects — that was the
  // "Browser window has no toolbar" unhandled error. The blue badge and the
  // notification are the click targets that open the popup.
}

chrome.notifications.onClicked.addListener((id) => {
  if (id !== 'apm-passkey-capture') return;
  noop(chrome.notifications.clear(id));
  try {
    noop(chrome.action.openPopup());
  } catch (_) {}
});

// ── Message routing ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (!msg) return sendResponse({ ok: false });

      // Page ceremony messages (relayed by content.js).
      if (msg.type === 'paired?') {
        await bridge.loadToken();
        return sendResponse({ ok: true, payload: { paired: !!bridge.token } });
      }
      if (msg.type === 'create-result') {
        stageCapture(msg.capture);
        return sendResponse({ ok: true, payload: {} });
      }
      if (msg.type === 'get-intent') {
        await bridge.loadToken();
        if (!bridge.token || !msg.rpId) return sendResponse({ ok: true, payload: { ok: false } });
        let creds = null;
        try {
          const r = await bridge.credentialsFor(msg.rpId);
          creds = r.body && r.body.ok ? r.body.credentials : null;
        } catch (_) {}
        if (!creds || creds.length === 0) {
          return sendResponse({ ok: true, payload: { ok: false } });
        }
        // Respect the site's allowCredentials filter when present: only pick a
        // credential the page explicitly permitted.
        if (msg.allowCredentials && msg.allowCredentials.length > 0) {
          const allowed = new Set(msg.allowCredentials);
          creds = creds.filter((c) => allowed.has(c.credentialId));
          if (creds.length === 0) {
            return sendResponse({ ok: true, payload: { ok: false } });
          }
        }
        const picked = creds[0];
        // Re-read the persisted map before computing, so a cold-starting worker
        // never derives a count from a half-loaded map. Merge with max: a
        // counter value can never be lowered.
        try {
          const sr = await chrome.storage.session.get('apmSignCounts');
          if (sr && sr.apmSignCounts) {
            for (const [k, v] of Object.entries(sr.apmSignCounts)) {
              signCounts[k] = Math.max(signCounts[k] || 0, v || 0);
            }
          }
        } catch (_) {}
        // WebAuthn sign counters must strictly increase per credential or the RP
        // rejects the assertion. The vault holds the LAST count used, so this
        // login signs with last+1. We track it here (not just in the vault) so a
        // failed bridge write can never make the next login reuse a count.
        const nextCount = Math.max(
          signCounts[picked.credentialId] || 0,
          picked.signCount || 0
        ) + 1;
        signCounts[picked.credentialId] = nextCount;
        // Await the in-memory write before answering: if the worker is killed
        // right after this point, the increment is already durable, so the next
        // login still computes a strictly larger count.
        try { await chrome.storage.session.set({ apmSignCounts: signCounts }); } catch (_) {}
        bridge.markUsed({
          credentialId: picked.credentialId,
          signCount: nextCount,
        }).catch(() => {}); // best-effort vault sync; the local map covers failures
        return sendResponse({
          ok: true,
          payload: {
            ok: true,
            credential: {
              credentialId: picked.credentialId,
              userHandle: picked.userHandle || '',
              signCount: nextCount,
              privateKey: picked.privateKey,
            },
          },
        });
      }

      // Passkey management (popup's "Manage passkeys" view).
      if (msg.type === 'list-passkeys') {
        await bridge.loadToken();
        if (!bridge.token) return sendResponse({ ok: true, payload: { ok: false, passkeys: [] } });
        const r = await bridge.passkeys();
        return sendResponse({
          ok: true,
          payload: {
            ok: !!(r.body && r.body.ok),
            passkeys: (r.body && r.body.passkeys) || [],
            error: (r.body && r.body.error) || null,
          },
        });
      }
      if (msg.type === 'remove-passkey') {
        await bridge.loadToken();
        if (!bridge.token || !msg.credentialId) return sendResponse({ ok: true, payload: { ok: false } });
        const r = await bridge.removePasskey(msg.credentialId);
        return sendResponse({
          ok: true,
          payload: { ok: !!(r.body && r.body.ok), error: (r.body && r.body.error) || null },
        });
      }
      if (msg.type === 'rename-passkey') {
        await bridge.loadToken();
        if (!bridge.token || !msg.credentialId) return sendResponse({ ok: true, payload: { ok: false } });
        const r = await bridge.renamePasskey(msg.credentialId, msg.label || '');
        return sendResponse({
          ok: true,
          payload: { ok: !!(r.body && r.body.ok), error: (r.body && r.body.error) || null },
        });
      }

      // Popup <-> worker.
      if (msg.type === 'pair') {
        await bridge.saveToken(msg.token);
        // /api/info is intentionally public, so validate the token against an
        // authenticated endpoint: 401 = wrong token, 423 = valid but locked,
        // 200 = valid and unlocked.
        const check = await bridge.entries();
        if (check.status === 401 || check.status === 0) {
          await bridge.saveToken(null); // roll back a bad token
          const err = check.status === 401
            ? 'That token was rejected. Copy it again from APM → Settings → Passkeys.'
            : 'Could not reach the APM app on 127.0.0.1:' + BRIDGE_PORT;
          return sendResponse({ ok: false, error: err });
        }
        const info = await bridge.info();
        return sendResponse({
          ok: true,
          unlocked: check.status === 200,
          version: (info.body && info.body.version) || null,
          error: null,
        });
      }
      if (msg.type === 'forget-pairing') {
        await bridge.saveToken(null);
        return sendResponse({ ok: true });
      }
      if (msg.type === 'get-state') {
        await bridge.loadToken();
        const state = {
          ok: true,
          paired: !!bridge.token,
          unlocked: false,
          version: null,
          pending: pendingCapture,
          entries: [],
          intentError: lastIntentError,
        };
        if (bridge.token) {
          const info = await bridge.info();
          state.unlocked = !!(info.body && info.body.ok && info.body.unlocked);
          state.version = info.body && info.body.version;
          if (state.unlocked && pendingCapture) {
            const entries = await bridge.entries();
            state.entries = entries.body && entries.body.ok ? entries.body.entries : [];
          }
        }
        return sendResponse(state);
      }
      if (msg.type === 'save-passkey') {
        if (!pendingCapture) return sendResponse({ ok: false, error: 'No pending passkey.' });
        const r = await bridge.savePasskey({
          ref: msg.ref || null,
          newEntry: msg.newEntry || null,
          passkey: pendingCapture,
        });
        if (r.body && r.body.ok) {
          const saved = r.body.entryName || '';
          await clearCapture();
          return sendResponse({ ok: true, entryName: saved });
        }
        return sendResponse({ ok: false, error: (r.body && r.body.error) || 'Bridge error (' + r.status + ')' });
      }
      if (msg.type === 'dismiss-capture') {
        await clearCapture();
        return sendResponse({ ok: true });
      }
      return sendResponse({ ok: false, error: 'Unknown message' });
    } catch (e) {
      return sendResponse({ ok: false, error: String((e && e.message) || e) });
    }
  })();
  return true; // keep the channel open for the async response
});

// Refresh pairing + pending capture from storage on worker startup.
bridge.loadToken().then(() => {
  console.info('[APM] worker started; paired =', !!bridge.token);
}).catch(() => {});
chrome.storage.session.get('apmPendingCapture').then((r) => {
  if (r && r.apmPendingCapture) {
    pendingCapture = r.apmPendingCapture;
    noop(chrome.action.setBadgeText({ text: '1' }));
  }
}).catch(() => {});
chrome.storage.session.get('apmSignCounts').then((r) => {
  if (r && r.apmSignCounts) signCounts = r.apmSignCounts;
}).catch(() => {});
