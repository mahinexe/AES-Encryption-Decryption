# AES Encryption & Decryption

Client-side AES-GCM tool (HTML5, Tailwind CDN, vanilla JS, Web Crypto API). No backend, no build step.

## Run
Web Crypto needs a secure context, so use a local server:

```bash
cd aes-encryption-tool
python3 -m http.server 8000   # then open http://localhost:8000
```

## Format
- AES-128 / 192 / 256 (default 256), random key and 12-byte nonce from `crypto.getRandomValues`
- UTF-8 plaintext, 128-bit authentication tag, Base64 ciphertext / nonce / key
- Web Crypto appends the GCM authentication tag to the ciphertext. Decryption verifies it automatically and rejects modified data.
- The exported JSON uses `algorithm: "AES-GCM"`, `keySize`, `ciphertext`, `iv` (the nonce), and `key`.

## Privacy
Everything runs in the browser. Nothing is uploaded or logged. Only the theme choice is stored in `localStorage`.

## Notes
- AES-GCM provides authenticated encryption and does not need PKCS#7 padding.
- A unique nonce must be generated for every encryption. The nonce is not secret and is stored with the ciphertext.
- Shortcuts: `Ctrl/Cmd + Enter` runs the current mode, `Esc` dismisses toasts.

## Files
`index.html`, `script.js`, `style.css`
