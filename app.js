'use strict';

const $ = (id) => document.getElementById(id);
const utf8 = new TextEncoder();
const STORAGE_KEY = 'passkey-p256-demo';
const ES256 = -7; // COSE algorithm id for ECDSA P-256 with SHA-256

// ---------------------------------------------------------------------------
// Encoding helpers

function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(str) {
  const s = atob(str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function concat(...arrays) {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function equal(a, b) {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

// ---------------------------------------------------------------------------
// Synchronous SHA-256.
//
// iOS Safari only allows navigator.credentials.* while the click's user
// activation is still live, so the challenge is computed synchronously
// instead of awaiting crypto.subtle.digest() before the call.

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const ror = (x, n) => (x >>> n) | (x << (32 - n));

function sha256(data) {
  const len = data.length;
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
  padded.set(data);
  padded[len] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(len / 0x20000000));
  view.setUint32(padded.length - 4, len << 3);

  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const W = new Uint32Array(64);

  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = ror(W[i - 15], 7) ^ ror(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = ror(W[i - 2], 17) ^ ror(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
      const t2 = ((ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  H.forEach((v, i) => outView.setUint32(i * 4, v));
  return out;
}

// ---------------------------------------------------------------------------
// Minimal CBOR decoder: enough for a WebAuthn attestationObject and COSE key.

function cborDecode(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let pos = 0;

  function length(info) {
    if (info < 24) return info;
    if (info === 24) return view.getUint8(pos++);
    if (info === 25) { const v = view.getUint16(pos); pos += 2; return v; }
    if (info === 26) { const v = view.getUint32(pos); pos += 4; return v; }
    throw new Error('Unsupported CBOR length encoding');
  }

  function item() {
    const initial = view.getUint8(pos++);
    const major = initial >> 5;
    const info = initial & 0x1f;
    switch (major) {
      case 0: return length(info);
      case 1: return -1 - length(info);
      case 2: { const n = length(info); const v = bytes.slice(pos, pos + n); pos += n; return v; }
      case 3: { const n = length(info); const v = new TextDecoder().decode(bytes.subarray(pos, pos + n)); pos += n; return v; }
      case 4: { const n = length(info); const arr = []; for (let i = 0; i < n; i++) arr.push(item()); return arr; }
      case 5: { const n = length(info); const map = new Map(); for (let i = 0; i < n; i++) { const k = item(); map.set(k, item()); } return map; }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
    }
    throw new Error('Unsupported CBOR item');
  }

  return item();
}

// Extracts the uncompressed P-256 public key (0x04 || x || y) from the
// attestationObject returned by navigator.credentials.create().
function publicKeyFromAttestation(attestationObject) {
  const authData = cborDecode(new Uint8Array(attestationObject)).get('authData');
  // rpIdHash(32) | flags(1) | signCount(4) | aaguid(16) | credIdLen(2) | credId | COSE key
  const credIdLen = (authData[53] << 8) | authData[54];
  const cose = cborDecode(authData.subarray(55 + credIdLen));
  if (cose.get(1) !== 2 || cose.get(3) !== ES256 || cose.get(-1) !== 1) {
    throw new Error('Authenticator did not return an ES256 / P-256 key');
  }
  return concat([0x04], cose.get(-2), cose.get(-3));
}

// WebAuthn returns ASN.1 DER signatures; WebCrypto wants raw r || s.
function derToRaw(der) {
  if (der[0] !== 0x30) throw new Error('Signature is not DER encoded');
  const out = new Uint8Array(64);
  let pos = 2;
  for (let i = 0; i < 2; i++) {
    if (der[pos] !== 0x02) throw new Error('Malformed DER signature');
    const len = der[pos + 1];
    let int = der.subarray(pos + 2, pos + 2 + len);
    pos += 2 + len;
    while (int.length > 32 && int[0] === 0) int = int.subarray(1);
    out.set(int, i * 32 + 32 - int.length);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Credential storage (public keys only)

function loadCreds() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || {}; } catch { return {}; }
}

function saveCreds(creds) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(creds)); } catch { /* private mode */ }
}

function renderCreds() {
  const list = $('cred-list');
  list.replaceChildren();
  const entries = Object.entries(loadCreds());
  if (!entries.length) {
    const li = document.createElement('li');
    li.className = 'empty';
    li.textContent = 'None yet.';
    list.append(li);
  }
  for (const [id, c] of entries) {
    const li = document.createElement('li');
    li.textContent = `${c.username} — ${id.slice(0, 16)}… (${new Date(c.created).toLocaleString()})`;
    list.append(li);
  }
}

// ---------------------------------------------------------------------------
// Output rendering

function show(target, ok, message, fields = []) {
  const el = $(target);
  el.replaceChildren();
  const status = document.createElement('p');
  status.className = `status ${ok ? 'ok' : 'bad'}`;
  status.textContent = message;
  el.append(status);
  for (const [label, value] of fields) {
    const field = document.createElement('div');
    field.className = 'field';
    const l = document.createElement('div');
    l.className = 'field-label';
    l.textContent = label;
    const v = document.createElement('div');
    v.className = 'field-value';
    v.textContent = value;
    field.append(l, v);
    el.append(field);
  }
}

function errorMessage(err) {
  if (err && err.name === 'NotAllowedError') return 'Cancelled or not allowed.';
  return `${err && err.name ? err.name + ': ' : ''}${err && err.message ? err.message : err}`;
}

// ---------------------------------------------------------------------------
// Register

async function register() {
  const username = $('username').value.trim() || 'demo-user';
  try {
    // Called synchronously from the click handler (no await before it).
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { name: 'Passkey P-256 Demo' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: username, displayName: username },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: 'public-key', alg: ES256 }],
        authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
        attestation: 'none',
        timeout: 120000,
      },
    });

    const id = b64url(new Uint8Array(cred.rawId));
    const publicKey = publicKeyFromAttestation(cred.response.attestationObject);
    const jwk = await crypto.subtle.exportKey(
      'jwk',
      await crypto.subtle.importKey('raw', publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']),
    );

    const creds = loadCreds();
    creds[id] = { username, publicKey: b64url(publicKey), created: Date.now() };
    saveCreds(creds);
    renderCreds();

    show('register-out', true, 'Passkey created.', [
      ['Credential ID (base64url)', id],
      ['Public key (uncompressed, hex)', hex(publicKey)],
      ['Public key (JWK)', JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, null, 2)],
    ]);
  } catch (err) {
    show('register-out', false, `Registration failed. ${errorMessage(err)}`);
  }
}

// ---------------------------------------------------------------------------
// Sign + verify

async function sign() {
  const payload = $('payload').value;
  const challenge = sha256(utf8.encode(payload));
  const creds = loadCreds();

  let cred;
  try {
    // Called synchronously from the click handler (no await before it).
    cred = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: Object.keys(creds).map((id) => ({ type: 'public-key', id: fromB64url(id) })),
        userVerification: 'required',
        timeout: 120000,
      },
    });
  } catch (err) {
    show('sign-out', false, `Signing failed. ${errorMessage(err)}`);
    return;
  }

  const id = b64url(new Uint8Array(cred.rawId));
  const authData = new Uint8Array(cred.response.authenticatorData);
  const clientDataJSON = new Uint8Array(cred.response.clientDataJSON);
  const derSignature = new Uint8Array(cred.response.signature);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));

  const fields = [
    ['Payload', payload],
    ['SHA-256(payload) = challenge (hex)', hex(challenge)],
    ['Credential ID', id],
    ['clientDataJSON', JSON.stringify(clientData, null, 2)],
    ['authenticatorData (hex)', hex(authData)],
    ['Signature (DER, base64url)', b64url(derSignature)],
  ];

  try {
    const stored = creds[id];
    if (!stored) throw new Error('Unknown credential: its public key was not saved in this browser.');

    const checks = [
      ['clientData.type is webauthn.get', clientData.type === 'webauthn.get'],
      ['clientData.challenge = SHA-256(payload)', clientData.challenge === b64url(challenge)],
      ['clientData.origin is this page', clientData.origin === location.origin],
      ['rpIdHash = SHA-256(hostname)', equal(authData.subarray(0, 32), sha256(utf8.encode(location.hostname)))],
      ['User present flag', (authData[32] & 0x01) !== 0],
      ['User verified flag', (authData[32] & 0x04) !== 0],
    ];

    const rawSignature = derToRaw(derSignature);
    const signedData = concat(authData, sha256(clientDataJSON));
    const key = await crypto.subtle.importKey(
      'raw', fromB64url(stored.publicKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
    );
    const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, rawSignature, signedData);
    checks.push(['ECDSA P-256 signature', valid]);

    fields.push(
      ['Signature (raw r || s, hex)', hex(rawSignature)],
      ['Signed data = authenticatorData || SHA-256(clientDataJSON) (hex)', hex(signedData)],
      ['Public key (hex)', hex(fromB64url(stored.publicKey))],
      ['Checks', checks.map(([name, ok]) => `${ok ? '✓' : '✗'} ${name}`).join('\n')],
    );

    const allOk = checks.every(([, ok]) => ok);
    show('sign-out', allOk, allOk ? 'Signed and verified.' : 'Signed, but verification FAILED.', fields);
  } catch (err) {
    show('sign-out', false, `Signed, but could not verify. ${errorMessage(err)}`, fields);
  }
}

// ---------------------------------------------------------------------------
// Init

async function checkSupport() {
  const notice = $('support');
  if (!window.isSecureContext) {
    notice.textContent = 'Passkeys need a secure context (HTTPS or localhost).';
  } else if (!window.PublicKeyCredential) {
    notice.textContent = 'This browser does not support WebAuthn / passkeys.';
  } else {
    try {
      if (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()) return;
      notice.textContent = 'No platform authenticator found. You may still be able to use a phone or security key.';
    } catch {
      return;
    }
  }
  notice.hidden = false;
}

$('register').addEventListener('click', register);
$('sign').addEventListener('click', sign);
$('clear').addEventListener('click', () => {
  saveCreds({});
  renderCreds();
});

renderCreds();
checkSupport();
