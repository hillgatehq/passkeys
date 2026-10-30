# Passkey P-256 Signing Demo

A tiny static site (plain HTML/CSS/JS, no dependencies) that shows how to use a
passkey to sign an arbitrary payload with ECDSA P-256 (WebAuthn `ES256`), and
verifies the signature in the browser with WebCrypto. Works on iOS Safari
(iOS 16+), macOS, Android and desktop browsers.

## How it works

1. **Create passkey**: `navigator.credentials.create()` with `alg: -7` (ES256).
   The P-256 public key is pulled out of the `attestationObject` (minimal CBOR
   decoder) and saved in `localStorage`.
2. **Sign**: `challenge = SHA-256(payload)` is passed to
   `navigator.credentials.get()`. The authenticator signs
   `authenticatorData || SHA-256(clientDataJSON)`, and `clientDataJSON` holds
   the challenge, so the signature is bound to the payload.
3. **Verify**: the page checks the challenge, origin, RP ID hash and UP/UV flags,
   converts the DER signature to raw `r || s`, and checks it with
   `crypto.subtle.verify`.

The challenge hash is computed with a small synchronous SHA-256 so that the
WebAuthn call runs straight from the button tap. iOS Safari can reject the call
if the user activation has expired.

## Deploy to GitHub Pages

Settings → Pages → Build and deployment → *Deploy from a branch* → `main` / `/ (root)`.

Passkeys need HTTPS (GitHub Pages gives you that) or `localhost`. The passkey is
tied to the hostname it was created on.

## Run locally

```bash
python3 -m http.server 8000
```

Then open http://localhost:8000.
