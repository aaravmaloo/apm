// APM Passkeys — isolated-world relay.
//
// The MAIN-world hook can't reach chrome.runtime, so this script listens for
// its CustomEvents, forwards them to the service worker, and echoes the
// worker's reply back into the page's main world.
(() => {
  'use strict';

  if (!globalThis.chrome || !chrome.runtime) return;

  const INTENT = 'apm-webauthn-intent';
  const REPLY = 'apm-webauthn-reply';

  // Relay one message to the service worker; retries once on a dead-context /
  // worker-restart race (sendMessage can fail when the MV3 worker is waking up
  // or the extension was reloaded). On final failure, answers the page fast with
  // a relayError instead of letting its timeout expire silently.
  function relay(d, attempt) {
    const done = (payload) => {
      // Page-side ask() resolves e.detail.payload, so wrap it.
      window.dispatchEvent(new CustomEvent(REPLY, { detail: { payload } }));
    };
    try {
      chrome.runtime.sendMessage(
        Object.assign({ target: 'apm-webauthn', url: location.href }, d),
        (resp) => {
          const err = chrome.runtime.lastError;
          if (err) {
            if (attempt === 0) { setTimeout(() => relay(d, 1), 300); return; }
            done({ ok: false, relayError: err.message || 'worker unreachable' });
            return;
          }
          if (resp && resp.payload) done(resp.payload);
        }
      );
    } catch (e) {
      if (attempt === 0) { setTimeout(() => relay(d, 1), 300); return; }
      done({ ok: false, relayError: String((e && e.message) || e) });
    }
  }

  window.addEventListener(INTENT, (e) => {
    const d = e.detail || {};
    if (!d.type) return;
    relay(d, 0);
  });
})();
