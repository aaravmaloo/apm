// Unit tests for the in-page WebAuthn ceremony engine (content_main.js).
// Loads the ACTUAL shipped file through its __APM_TEST__ hook and cross-checks
// the pure-JS ECDSA signer against node:crypto, plus CBOR/attestation structure.
'use strict';

const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');

// ── Minimal DOM shim so content_main.js can load in Node ─────────────────────
globalThis.window = globalThis;
Object.defineProperty(globalThis, 'navigator', {
  value: { credentials: { create() {}, get() {} } },
  configurable: true,
});
globalThis.location = { origin: 'https://example.com', hostname: 'example.com' };
globalThis.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
globalThis.atob = (s) => Buffer.from(s, 'base64').toString('binary');
Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
globalThis.__APM_TEST__ = true;

require('../src/content_main.js');
const core = globalThis.__apmCore;
assert.ok(core, 'engine should expose its test hook');

// ── Tiny CBOR reader (for assertions only) ───────────────────────────────────
function cborRead(u8) {
  let i = 0;
  const next = () => u8[i++];
  const readLen = (major, ib) => {
    let n = ib;
    if (ib < 24) return n;
    if (ib === 24) return next();
    if (ib === 25) return (next() << 8) | next();
    if (ib === 26) return ((next() << 24) | (next() << 16) | (next() << 8) | next()) >>> 0;
    throw new Error('long length');
  };
  const readItem = () => {
    const b = next();
    const major = b >> 5, ib = b & 0x1f;
    if (major === 0) return readLen(0, ib);
    if (major === 1) return -1 - readLen(1, ib);
    if (major === 2 || major === 3) {
      // Read the length FIRST (it may consume length-indicator bytes),
      // then slice from the current position. Doing `slice(i, (i += len))`
      // uses the pre-increment start and drifts on long items.
      const len = readLen(major, ib);
      const s = u8.slice(i, i + len);
      i += len;
      return major === 2 ? s : Buffer.from(s).toString('utf8');
    }
    if (major === 4) {
      const n = readLen(4, ib), arr = [];
      for (let k = 0; k < n; k++) arr.push(readItem());
      return arr;
    }
    if (major === 5) {
      const n = readLen(5, ib), map = new Map();
      for (let k = 0; k < n; k++) map.set(readItem(), readItem());
      return map;
    }
    if (b === 0xf4) return false;
    if (b === 0xf5) return true;
    if (b === 0xf6) return null;
    throw new Error('cbor read unsupported');
  };
  const out = readItem();
  return { value: out, end: i };
}

function utf8(s) { return new TextEncoder().encode(s); }
async function sha256(data) { return new Uint8Array(await webcrypto.subtle.digest('SHA-256', data)); }

// ── Pure-JS P-256 verify (plumbing check; signer itself is node-verified) ────
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
const mod = (a, m) => ((a % m) + m) % m;
const modInverse = (a, m) => {
  let oR = mod(a, m), r = m, oS = 1n, s = 0n;
  while (r !== 0n) { const q = oR / r; [oR, r] = [r, oR - q * r]; [oS, s] = [s, oS - q * s]; }
  return mod(oS, m);
};
const add = (p1, p2) => {
  if (!p1) return p2; if (!p2) return p1;
  const [x1, y1] = p1, [x2, y2] = p2;
  if (x1 === x2 && mod(y1 + y2, P) === 0n) return null;
  const lam = x1 === x2 && y1 === y2 ? mod((3n * x1 * x1 - 3n) * modInverse(2n * y1, P), P) : mod((y2 - y1) * modInverse(x2 - x1, P), P);
  const x3 = mod(lam * lam - x1 - x2, P);
  return [x3, mod(lam * (x1 - x3) - y1, P)];
};
const mul = (k, pt) => { let r = null, a = pt; while (k > 0n) { if (k & 1n) r = add(r, a); a = add(a, a); k >>= 1n; } return r; };
const u8ToBig = (u) => { let v = 0n; for (const b of u) v = (v << 8n) | BigInt(b); return v; };

function ecdsaVerify(msgHash, sig, pubPoint) {
  const r = u8ToBig(sig.slice(0, 32));
  const s = u8ToBig(sig.slice(32));
  const z = u8ToBig(msgHash.slice(0, 32));
  const w = modInverse(s, N);
  const u1 = mod(z * w, N), u2 = mod(r * w, N);
  const R = add(mul(u1, [GX, GY]), mul(u2, pubPoint));
  return !!R && mod(R[0], N) === mod(r, N);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

async function main() {
  // 1) ECDSA signer cross-checked against node:crypto.
  {
    const keyPair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const jwk = await webcrypto.subtle.exportKey('jwk', keyPair.privateKey);
    const msg = webcrypto.getRandomValues(new Uint8Array(97));
    const h = await sha256(msg);
    const d = u8ToBig(core.b64urlToU8(jwk.d));
    const sig = core.ecdsaSign(h, d);
    assert.equal(sig.length, 64, 'raw sig is 64 bytes');
    const ok = await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.publicKey, sig, msg);
    assert.ok(ok, 'node:crypto verifies the pure-JS signature');
    console.log('  ✓ ECDSA signer verified by node:crypto');
  }

  // 2) CBOR basics.
  {
    assert.deepEqual([...core.cborPairs([])], [0xa0], 'empty map is 0xa0');
    const m = core.cborPairs([['fmt', 'none']]);
    assert.equal(m[0], 0xa1);
    assert.deepEqual([...m], [0xa1, 0x63, 0x66, 0x6d, 0x74, 0x64, 0x6e, 0x6f, 0x6e, 0x65]);
    console.log('  ✓ CBOR map encoding');
  }

  // 3) Registration: structure + full CBOR decode.
  {
    const challenge = webcrypto.getRandomValues(new Uint8Array(32));
    const pk = {
      rp: { id: 'example.com', name: 'Example' },
      user: { id: utf8('user-1'), name: 'bob', displayName: 'Bob' },
      challenge,
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    };
    const { credential, capture } = await core.buildCreateResponse(pk);
    assert.equal(credential.type, 'public-key');
    assert.equal(credential.id, core.b64url(credential.rawId));
    assert.equal(capture.credentialId, credential.id);
    assert.ok(capture.privateKey.kty === 'EC' && capture.privateKey.crv === 'P-256', 'JWK is EC P-256');

    const cj = JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON));
    assert.equal(cj.type, 'webauthn.create');
    assert.equal(cj.origin, 'https://example.com');
    assert.equal(cj.challenge, core.b64url(challenge));

    const { value: att } = cborRead(new Uint8Array(credential.response.attestationObject));
    assert.equal(att.get('fmt'), 'none', 'attestation fmt is none');
    assert.deepEqual([...att.get('attStmt').keys()], [], 'attStmt is empty map');
    const authData = new Uint8Array(att.get('authData'));
    assert.ok(authData.length > 37 + 16 + 2 + 32, 'authData covers rpIdHash+flags+counter+AAGUID+credId+COSE');
    assert.equal(authData[32], 0x41, 'flags = UP|AT');
    assert.deepEqual([...authData.slice(0, 32)], [...await sha256(utf8('example.com'))], 'rpIdHash correct');
    const credLen = (authData[53] << 8) | authData[54];
    assert.equal(credLen, 32, 'credentialId length field');
    // COSE key: map of 5 with int keys 1,3,-1,-2,-3
    const coseStart = 37 + 16 + 2 + 32;
    const { value: cose } = cborRead(authData.slice(coseStart));
    assert.equal(cose.size, 5, 'COSE key has 5 entries');
    assert.deepEqual([...cose.keys()], [1, 3, -1, -2, -3], 'COSE keys: kty, alg, crv, x, y');
    assert.equal(cose.get(1), 2); // EC2
    assert.equal(cose.get(3), -7); // ES256
    assert.equal(cose.get(-1), 1); // P-256
    assert.equal(cose.get(-2).length, 32);
    assert.equal(cose.get(-3).length, 32);
    console.log('  ✓ registration structure + CBOR decode');
  }

  // 4) Assertion: structure + signature verifies over authData||clientDataHash.
  {
    const keyPair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const jwk = await webcrypto.subtle.exportKey('jwk', keyPair.privateKey);
    const pubRaw = new Uint8Array(await webcrypto.subtle.exportKey('raw', keyPair.publicKey));
    const pubPoint = [u8ToBig(pubRaw.slice(1, 33)), u8ToBig(pubRaw.slice(33, 65))];

    const saved = {
      credentialId: core.b64url(webcrypto.getRandomValues(new Uint8Array(32))),
      userHandle: core.b64url(utf8('user-1')),
      // The background hands the page the exact counter to sign with (it owns
      // the increment so it never repeats a count across logins).
      signCount: 6,
      privateKey: jwk,
    };
    const challenge = webcrypto.getRandomValues(new Uint8Array(32));
    const credential = await core.buildAssertion({ rpId: 'example.com', challenge }, saved);

    const cj = JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON));
    assert.equal(cj.type, 'webauthn.get');
    assert.equal(cj.challenge, core.b64url(challenge));

    const ad = new Uint8Array(credential.response.authenticatorData);
    assert.equal(ad[32], 0x01, 'flags = UP');
    const counter = (ad[33] << 24) | (ad[34] << 16) | (ad[35] << 8) | ad[36];
    assert.equal(counter, 6, 'signCount used verbatim (background owns the increment)');

    // Counter floors at 1 — a 0/undefined count is never signed (server expects >= 1).
    const c0 = await core.buildAssertion({ rpId: 'example.com', challenge }, { ...saved, signCount: 0 });
    const ad0 = new Uint8Array(c0.response.authenticatorData);
    assert.equal((ad0[33] << 24) | (ad0[34] << 16) | (ad0[35] << 8) | ad0[36], 1, 'counter floor of 1');

    const clientDataHash = await sha256(credential.response.clientDataJSON);
    const sig = Buffer.from(credential.response.signature);
    assert.equal(sig[0], 0x30, 'signature is DER (WebAuthn ES256 contract)');
    // Verify the FULL WebAuthn contract: signature over authData || SHA256(clientDataJSON),
    // DER-encoded, using the same public key the saved JWK belongs to.
    const { createVerify, createPublicKey } = require('node:crypto');
    const pubJwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
    const verifier = createVerify('SHA256');
    verifier.update(Buffer.from([...ad, ...clientDataHash]));
    assert.ok(verifier.verify(createPublicKey({ key: pubJwk, format: 'jwk' }), sig), 'assertion signature verifies over authData||clientDataHash (node:crypto)');
    console.log('  ✓ assertion structure + signature');
  }

  console.log('\nAll webauthn-core tests passed.');
}

main().catch((e) => { console.error('TEST FAILURE:', e); process.exit(1); });
