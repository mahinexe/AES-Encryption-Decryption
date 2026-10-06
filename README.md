# AES Encryption & Decryption

<p align="center">
  <strong>A private, browser-based AES-GCM encryption utility</strong><br>
  Encrypt and decrypt text locally without sending sensitive data to a server.
</p>

<p align="center">
  <a href="https://github.com/mahinexe/AES-Encryption-Decryption">Repository</a>
  ·
  <a href="https://mahinexe.vercel.app/">Author website</a>
</p>

## Overview

This project is a lightweight client-side encryption tool built with standard web technologies and the Web Crypto API. It lets you encrypt text with authenticated AES-GCM, export the ciphertext and encryption details, and decrypt the data again whenever you have the correct key and nonce.

There is no backend, account system, database, or build process. Encryption and decryption happen inside the browser.

> **Important:** This tool does not store or recover encryption keys. If you lose the key, the encrypted data cannot be decrypted.

## Features

- AES-128, AES-192, and AES-256 encryption
- AES-GCM authenticated encryption with a 128-bit authentication tag
- Cryptographically secure random keys and 12-byte nonces
- UTF-8 text support, including multilingual text and emoji
- Base64 output for ciphertext, nonce, and key
- Decryption authentication that detects incorrect or modified data
- Import previously exported encryption data from JSON
- Export results as JSON or plain text
- Copy individual values or the complete encryption package
- Light and dark themes with persisted theme preference
- Drag-and-drop JSON import
- Keyboard shortcuts:
  - `Ctrl`/`Cmd` + `Enter` — run the active operation
  - `Esc` — dismiss visible notifications
- Responsive layout with accessible form labels, tabs, alerts, and controls

## How AES-GCM works

1. A random AES key is generated using `crypto.getRandomValues`.
2. A unique 12-byte nonce is generated for the encryption operation.
3. The plaintext is encoded as UTF-8 and encrypted with AES-GCM.
4. The authentication tag is appended to the ciphertext by the Web Crypto API.
5. The ciphertext, nonce, and key are displayed as Base64 values.
6. During decryption, AES-GCM verifies the authentication tag before returning plaintext.

The nonce does not need to be secret, but it must be kept with the ciphertext. The encryption key must remain private.

## Quick start

### Run locally

Web Crypto features require a secure context. `localhost` is treated as secure by modern browsers, so serve the project with any local static server:

```bash
git clone https://github.com/mahinexe/AES-Encryption-Decryption.git
cd AES-Encryption-Decryption
python3 -m http.server 8000
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

You can also use another static server, such as VS Code Live Server or:

```bash
npx serve .
```

### Use the application

#### Encrypt text

1. Open the **Encrypt** tab.
2. Select an AES key size.
3. Enter the plaintext.
4. Select **Encrypt Data**.
5. Store the generated key, nonce, and ciphertext together in a secure location.

#### Decrypt text

1. Open the **Decrypt** tab.
2. Enter or import the Base64 ciphertext, nonce, and encryption key.
3. Select **Decrypt Data**.
4. The plaintext is shown only after authentication succeeds.

## Export format

The JSON export contains the following fields:

```json
{
  "algorithm": "AES-GCM",
  "keySize": 256,
  "ciphertext": "Base64-encoded ciphertext and authentication tag",
  "iv": "Base64-encoded 12-byte nonce",
  "key": "Base64-encoded AES key"
}
```

The `keySize` value may be `128`, `192`, or `256`. The `iv` field is the AES-GCM nonce; it is named `iv` for compatibility with common encryption formats.

## Privacy and security

- Plaintext, ciphertext, keys, and nonces are processed locally in the browser.
- The application does not send encryption data to a server.
- No backend or analytics service is included.
- Only the selected light/dark theme is stored in `localStorage`.
- AES-GCM authentication rejects modified ciphertext, nonce, or key material.
- A fresh nonce is generated for every encryption operation.

### Security considerations

- Treat the generated key like a password. Anyone who has it can decrypt the data.
- Do not paste keys or plaintext into untrusted websites or shared computers.
- Use HTTPS when hosting the application publicly.
- Verify the downloaded source and hosting environment before using the tool for highly sensitive information.
- This project is a browser utility, not a replacement for a managed secrets vault or key-management system.

## Technical details

| Item | Value |
| --- | --- |
| Algorithm | AES-GCM |
| Key sizes | 128, 192, or 256 bits |
| Default key size | 256 bits |
| Authentication tag | 128 bits |
| Nonce size | 96 bits / 12 bytes |
| Text encoding | UTF-8 |
| Binary encoding | Base64 |
| Runtime | Modern browser with Web Crypto API |
| Dependencies | Tailwind CSS CDN and Google Fonts |

## Browser support

Use a current version of Chrome, Edge, Firefox, or Safari with Web Crypto API support. The application should be served from `localhost` or an HTTPS origin; opening the file directly may prevent cryptographic APIs from working.

## Project structure

```text
.
├── index.html   # Application markup and accessibility structure
├── script.js    # Encryption, decryption, validation, and UI behavior
├── style.css    # Theme, layout, component, and animation styles
└── README.md    # Project documentation
```

## Development

The project has no build step or package installation requirement. Edit the files directly and reload the local server.

Before opening a pull request:

1. Run the app from a local server.
2. Test encryption with each key size.
3. Test decryption with valid and invalid data.
4. Confirm modified ciphertext fails authentication.
5. Check the layout in both themes and on mobile-sized screens.

## License

No license has been added to this repository yet. Until a license is provided, all rights remain with the copyright holder.

## Author

Created and developed by [Mohammodullah Al Mahin](https://mahinexe.vercel.app/).
