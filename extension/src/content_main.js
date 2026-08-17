// APM Passkeys — MAIN-world WebAuthn ceremony engine.
//
// This is the Bitwarden-style approach: we complete the ENTIRE WebAuthn
// ceremony inside the page with WebCrypto (no chrome.debugger, no CDP — so
// there's nothing to race with Chrome's native passkey sheet and DevTools
// being open doesn't matter):
//
//   create → generate an ECDSA P-256 keypair, build the attestation object
//            (CBOR), hand a fully-formed PublicKeyCredential back to the site,
//            and send the private key to the extension for vault storage.
//   get    → sign the assertion with a passkey saved in the vault (pure-JS
//            ECDSA, so the signature covers authData || SHA-256(clientDataJSON)
//            exactly as the WebAuthn spec requires).
//
// If the extension isn't paired (or anything throws), we transparently fall
// through to the original native flow so sites are never broken.
(() => {
  'use strict';

  if (typeof window === 'undefined') return;
  const nav = window.navigator;
  if (!nav || !nav.credentials) return;
  const creds = nav.credentials;
  if (creds.__apmHooked) return;
  if (typeof creds.create !== 'function' && typeof creds.get !== 'function') return;

  creds.__apmHooked = true;
  const realCreate = typeof creds.create === 'function' ? creds.create.bind(creds) : null;
  const realGet = typeof creds.get === 'function' ? creds.get.bind(creds) : null;

  const INTENT = 'apm-webauthn-intent';
  const REPLY = 'apm-webauthn-reply';

  // ── Bridge to the extension (via the isolated-world content script) ────────

  const ask = (msg, timeoutMs) =>
    new Promise((resolve) => {
      let done = false;
      const onReply = (e) => {
        if (done) return;
        done = true;
        window.removeEventListener(REPLY, onReply);
        resolve(e.detail && e.detail.payload);
      };
      window.addEventListener(REPLY, onReply);
      try {
        window.dispatchEvent(new CustomEvent(INTENT, { detail: msg }));
      } catch (_) {
        done = true;
        window.removeEventListener(REPLY, onReply);
        resolve(null);
      }
      setTimeout(() => {
        if (done) return;
        done = true;
        window.removeEventListener(REPLY, onReply);
        resolve(null);
      }, timeoutMs);
    });

  const tell = (msg) => {
    try {
      window.dispatchEvent(new CustomEvent(INTENT, { detail: msg }));
    } catch (_) {}
  };

  // A cold-started MV3 service worker can take a moment to wake, and a reloaded
  // extension invalidates already-injected content scripts. A dropped round-trip
  // must never silently fall through to the native OS sheet, so retry once and
  // let the caller surface a warning when it does.
  async function askWithRetry(msg, timeoutMs, attempts) {
    let last = null;
    for (let i = 0; i < attempts; i++) {
      last = await ask(msg, timeoutMs);
      if (last) return last;
    }
    return last;
  }

  // ── Small encoding helpers ──────────────────────────────────────────────────

  const utf8 = (s) => new TextEncoder().encode(s);
  const toU8 = (b) => (b instanceof Uint8Array ? b : new Uint8Array(b));
  const concat = (...parts) => {
    const u8 = parts.map(toU8);
    const out = new Uint8Array(u8.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of u8) { out.set(p, o); o += p.length; }
    return out;
  };
  const b64url = (buf) => {
    const u8 = toU8(buf);
    let s = '';
    for (let i = 0; i < u8.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const b64urlToU8 = (s) => {
    let b = s.replace(/-/g, '+').replace(/_/g, '/');
    if (b.length % 4) b += '='.repeat(4 - (b.length % 4));
    const bin = atob(b);
    const u = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  };
  const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest('SHA-256', toU8(data)));

  // ── Minimal CBOR encoder (ints, strings, bytes, arrays, maps) ───────────────

  function cbor(obj) {
    const out = [];
    const push16 = (v) => { out.push((v >> 8) & 0xff, v & 0xff); };
    const push32 = (v) => { out.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff); };
    const enc = (v) => {
      if (v === null) out.push(0xf6);
      else if (v === true) out.push(0xf5);
      else if (v === false) out.push(0xf4);
      else if (typeof v === 'number') {
        if (Number.isInteger(v)) {
          if (v >= 0) {
            if (v < 24) out.push(v);
            else if (v < 0x100) { out.push(0x18, v); }
            else if (v < 0x10000) { out.push(0x19); push16(v); }
            else { out.push(0x1a); push32(v); }
          } else {
            const n = -1 - v;
            if (n < 24) out.push(0x20 + n);
            else if (n < 0x100) { out.push(0x38, n); }
            else if (n < 0x10000) { out.push(0x39); push16(n); }
            else { out.push(0x3a); push32(n); }
          }
        } else {
          throw new Error('CBOR: float unsupported');
        }
      } else if (typeof v === 'string') {
        const b = utf8(v);
        const l = b.length;
        if (l < 24) out.push(0x60 + l);
        else if (l < 0x100) { out.push(0x78, l); }
        else if (l < 0x10000) { out.push(0x79); push16(l); }
        else { out.push(0x7a); push32(l); }
        out.push(...b);
      } else if (v instanceof Uint8Array || v instanceof ArrayBuffer) {
        const b = toU8(v);
        const l = b.length;
        if (l < 24) out.push(0x40 + l);
        else if (l < 0x100) { out.push(0x58, l); }
        else if (l < 0x10000) { out.push(0x59); push16(l); }
        else { out.push(0x5a); push32(l); }
        out.push(...b);
      } else if (Array.isArray(v)) {
        const l = v.length;
        if (l < 24) out.push(0x80 + l);
        else if (l < 0x100) { out.push(0x98, l); }
        else if (l < 0x10000) { out.push(0x99); push16(l); }
        else { out.push(0x9a); push32(l); }
        v.forEach(enc);
      } else if (v && typeof v === 'object') {
        encMap(Object.entries(v).map(([k, val]) => [k, val]));
      } else {
        throw new Error('CBOR: unsupported ' + typeof v);
      }
    };
    const encMap = (pairs) => {
      const l = pairs.length;
      if (l < 24) out.push(0xa0 + l);
      else if (l < 0x100) { out.push(0xb8, l); }
      else if (l < 0x10000) { out.push(0xb9); push16(l); }
      else { out.push(0xba); push32(l); }
      for (const [k, v] of pairs) { enc(k); enc(v); }
    };
    enc(obj);
    return new Uint8Array(out);
  }

  // Mark pre-encoded CBOR bytes for inline embedding inside cborPairs values.
  const rawCbor = (bytes) => ({ __apmCborRaw: bytes });

  // Encode a CBOR MAP from [key, value] pairs (keys may be ints, e.g. COSE).
  function cborPairs(pairs) {
    const out = [];
    const push16 = (v) => { out.push((v >> 8) & 0xff, v & 0xff); };
    const push32 = (v) => { out.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff); };
    const enc = (v) => {
      if (v === null) out.push(0xf6);
      else if (v === true) out.push(0xf5);
      else if (v === false) out.push(0xf4);
      else if (typeof v === 'number' && Number.isInteger(v)) {
        if (v >= 0) {
          if (v < 24) out.push(v);
          else if (v < 0x100) out.push(0x18, v);
          else if (v < 0x10000) { out.push(0x19); push16(v); }
          else { out.push(0x1a); push32(v); }
        } else {
          const n = -1 - v;
          if (n < 24) out.push(0x20 + n);
          else if (n < 0x100) { out.push(0x38, n); }
          else if (n < 0x10000) { out.push(0x39); push16(n); }
          else { out.push(0x3a); push32(n); }
        }
      } else if (typeof v === 'string') {
        const b = utf8(v);
        const l = b.length;
        if (l < 24) out.push(0x60 + l);
        else if (l < 0x100) { out.push(0x78, l); }
        else if (l < 0x10000) { out.push(0x79); push16(l); }
        else { out.push(0x7a); push32(l); }
        out.push(...b);
      } else if (v instanceof Uint8Array || v instanceof ArrayBuffer) {
        const b = toU8(v);
        const l = b.length;
        if (l < 24) out.push(0x40 + l);
        else if (l < 0x100) { out.push(0x58, l); }
        else if (l < 0x10000) { out.push(0x59); push16(l); }
        else { out.push(0x5a); push32(l); }
        out.push(...b);
      } else if (v && v.__apmCborRaw) {
        // Embed pre-encoded CBOR inline (nested maps).
        out.push(...v.__apmCborRaw);
      } else {
        throw new Error('cborPairs: unsupported value');
      }
    };
    const l = pairs.length;
    if (l < 24) out.push(0xa0 + l);
    else if (l < 0x100) { out.push(0xb8, l); }
    else if (l < 0x10000) { out.push(0xb9); push16(l); }
    else { out.push(0xba); push32(l); }
    for (const [k, v] of pairs) { enc(k); enc(v); }
    return new Uint8Array(out);
  }

  // ── Pure-JS ECDSA P-256 (so assertions sign exactly authData||SHA256(cj)) ──

  const CURVE = {
    p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    a: -3n,
    b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
    n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
    gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  };
  const mod = (a, m) => ((a % m) + m) % m;
  const modInverse = (a, m) => {
    let oldR = mod(a, m), r = m, oldS = 1n, s = 0n;
    while (r !== 0n) {
      const q = oldR / r;
      [oldR, r] = [r, oldR - q * r];
      [oldS, s] = [s, oldS - q * s];
    }
    return mod(oldS, m);
  };
  const pointAdd = (p1, p2) => {
    if (!p1) return p2;
    if (!p2) return p1;
    const [x1, y1] = p1, [x2, y2] = p2;
    if (x1 === x2 && mod(y1 + y2, CURVE.p) === 0n) return null;
    const lam = x1 === x2 && y1 === y2
      ? mod((3n * x1 * x1 + CURVE.a) * modInverse(2n * y1, CURVE.p), CURVE.p)
      : mod((y2 - y1) * modInverse(x2 - x1, CURVE.p), CURVE.p);
    const x3 = mod(lam * lam - x1 - x2, CURVE.p);
    return [x3, mod(lam * (x1 - x3) - y1, CURVE.p)];
  };
  const scalarMult = (k, pt) => {
    let result = null, addend = pt;
    let bits = k;
    while (bits > 0n) {
      if (bits & 1n) result = pointAdd(result, addend);
      addend = pointAdd(addend, addend);
      bits >>= 1n;
    }
    return result;
  };
  const u8ToBig = (u8) => {
    let v = 0n;
    for (const byte of u8) v = (v << 8n) | BigInt(byte);
    return v;
  };
  const bigToU32 = (v) => {
    const out = new Uint8Array(32);
    for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
  };
  const randBig = () => {
    const r = new Uint8Array(32);
    crypto.getRandomValues(r);
    return u8ToBig(r);
  };
  function ecdsaSign(msgHash, d) {
    const z = u8ToBig(msgHash.slice(0, 32));
    let r = 0n, s = 0n, k = 0n;
    do {
      k = mod(randBig(), CURVE.n - 1n) + 1n;
      const R = scalarMult(k, [CURVE.gx, CURVE.gy]);
      if (!R) continue;
      r = mod(R[0], CURVE.n);
      s = mod(modInverse(k, CURVE.n) * (z + r * d), CURVE.n);
    } while (r === 0n || s === 0n);
    return concat(bigToU32(r), bigToU32(s));
  }
  function derEncodeSig(raw) {
    const r = raw.slice(0, 32), s = raw.slice(32);
    const int = (b) => {
      let i = 0;
      while (i < b.length - 1 && b[i] === 0) i++;
      b = b.slice(i);
      if (b[0] & 0x80) b = [0, ...b];
      return [0x02, b.length, ...b];
    };
    const ri = int(r), si = int(s);
    return new Uint8Array([0x30, ri.length + si.length, ...ri, ...si]);
  }
  const bigFromJwkD = (d) => u8ToBig(b64urlToU8(d));

  // ── Registration (create) ───────────────────────────────────────────────────

  async function buildCreateResponse(pk) {
    const rpId = (pk.rp && pk.rp.id) || location.hostname;
    const userName = (pk.user && pk.user.name) || '';
    const userDisplayName = (pk.user && pk.user.displayName) || userName;

    const keys = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', keys.privateKey);
    const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey));
    const x = pubRaw.slice(1, 33);
    const y = pubRaw.slice(33, 65);
    const credentialId = new Uint8Array(32);
    crypto.getRandomValues(credentialId);

    const rpIdHash = await sha256(utf8(rpId));
    const aaguid = new Uint8Array(16); // zeros: "none" attestation
    const credIdLen = new Uint8Array([0, credentialId.length]);
    // Honor userVerification: 'required' from authenticatorSelection so RPs that
    // check the UV flag server-side don't reject the registration.
    const uvRequired = !!(pk.authenticatorSelection && pk.authenticatorSelection.userVerification === 'required');
    const flags = uvRequired ? 0x45 : 0x41; // UP|AT (+UV)
    // COSE_Key for ES256: kty=EC2(2), alg=ES256(-7), crv=P-256(1), x, y
    const coseKey = cborPairs([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]]);
    const authData = concat(rpIdHash, new Uint8Array([flags]), new Uint8Array([0, 0, 0, 0]), aaguid, credIdLen, credentialId, coseKey);

    const clientData = {
      type: 'webauthn.create',
      challenge: b64url(pk.challenge),
      origin: location.origin,
      crossOrigin: false,
    };
    const clientDataJSON = utf8(JSON.stringify(clientData));

    const attestationObject = cborPairs([
      ['attStmt', rawCbor(cborPairs([]))],
      ['authData', authData],
      ['fmt', 'none'],
    ]);

    const rawId = credentialId.slice();
    const credential = {
      id: b64url(rawId),
      rawId,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: { clientDataJSON, attestationObject },
      getClientExtensionResults: () => ({}),
    };

    return {
      credential,
      capture: {
        rpId,
        userName,
        userDisplayName,
        credentialId: b64url(credentialId),
        userHandle: pk.user && pk.user.id ? b64url(pk.user.id) : '',
        signCount: 0,
        privateKey: jwk,
      },
    };
  }

  // ── Assertion (get) ─────────────────────────────────────────────────────────

  async function buildAssertion(pk, saved) {
    const rpId = pk.rpId || location.hostname;
    const rpIdHash = await sha256(utf8(rpId));
    // The background owns the counter: it tracks the last-used count and hands
    // us the exact next value (last+1). We use it verbatim so the count strictly
    // increases across every assertion — RPs reject equal or decreasing
    // counters ("sign count was not greater than current count").
    const signCount = Math.max(1, saved.signCount || 1);
    // UV flag when the site requires user verification (see buildCreateResponse).
    const flags = pk.userVerification === 'required' ? 0x05 : 0x01; // UP (+UV)
    const authData = concat(rpIdHash, new Uint8Array([flags]), new Uint8Array([
      (signCount >>> 24) & 0xff, (signCount >>> 16) & 0xff, (signCount >>> 8) & 0xff, signCount & 0xff,
    ]));

    const clientData = {
      type: 'webauthn.get',
      challenge: b64url(pk.challenge),
      origin: location.origin,
      crossOrigin: false,
    };
    const clientDataJSON = utf8(JSON.stringify(clientData));
    const clientDataHash = await sha256(clientDataJSON);

    const d = bigFromJwkD(saved.privateKey.d);
    const rawSig = ecdsaSign(await sha256(concat(authData, clientDataHash)), d);
    const signature = derEncodeSig(rawSig);

    return {
      id: saved.credentialId,
      rawId: b64urlToU8(saved.credentialId),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON,
        authenticatorData: authData,
        signature,
        userHandle: saved.userHandle ? b64urlToU8(saved.userHandle) : undefined,
      },
      getClientExtensionResults: () => ({}),
    };
  }

  // ── Hooks ───────────────────────────────────────────────────────────────────

  if (realCreate) {
    creds.create = async function (opts) {
      const pk = opts && opts.publicKey;
      if (!pk) return realCreate(opts);
      // We can only mint ES256 (alg -7) credentials. If the site demands a
      // different algorithm, let the native flow handle it.
      if (pk.pubKeyCredParams && Array.isArray(pk.pubKeyCredParams) &&
          !pk.pubKeyCredParams.some((p) => p && p.type === 'public-key' && p.alg === -7)) {
        return realCreate(opts);
      }
      try {
        const r = await askWithRetry({ type: 'paired?' }, 4000, 2);
        if (!r || !r.paired) {
          // Not paired, or the extension worker is unreachable. Never break the
          // site: fall through to the native flow. Only surface a warning when
          // the relay actually failed (worker unreachable / stale content
          // script) - 'not paired' is the expected default and stays silent.
          if (r && r.relayError) {
            console.warn('[APM] passkey interception skipped (' + r.relayError +
              ') - reload the extension and refresh this page, or native flow is used.');
          }
          return realCreate(opts);
        }
        const built = await buildCreateResponse(pk);
        tell({ type: 'create-result', capture: built.capture });
        return built.credential;
      } catch (e) {
        console.warn('[APM] create interception error:', e && e.message);
        return realCreate(opts);
      }
    };
  }

  if (realGet) {
    creds.get = async function (opts) {
      const pk = opts && opts.publicKey;
      // v1: skip conditional-mediation page-load probes.
      if (!pk || (opts && opts.mediation === 'conditional')) return realGet(opts);
      try {
        const allowed = (pk.allowCredentials || [])
          .filter((c) => c && c.type === 'public-key' && c.id)
          .map((c) => typeof c.id === 'string' ? c.id : b64url(c.id));
        const r = await askWithRetry({ type: 'get-intent', rpId: pk.rpId || location.hostname, allowCredentials: allowed, userVerification: pk.userVerification }, 6000, 2);
        if (r && r.ok && r.credential) {
          return buildAssertion(pk, r.credential);
        }
        if (r && r.relayError) {
          console.warn('[APM] login interception skipped (' + r.relayError +
            ') - reload the extension and refresh this page, or native flow is used.');
        }
      } catch (e) {
        console.warn('[APM] get interception error:', e && e.message);
      }
      return realGet(opts); // no saved passkey -> native flow
    };
  }

  try {
    console.info('[APM] passkey engine installed on', location.origin);
  } catch (_) {}

  // Test hook (never set in production): lets unit tests drive the engine.
  if (window.__APM_TEST__) {
    window.__apmCore = { cbor, cborPairs, rawCbor, b64url, b64urlToU8, u8ToBig, ecdsaSign, derEncodeSig, buildCreateResponse, buildAssertion };
  }
})();
