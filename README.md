Password Generator

A small static web app that generates secure passwords with options for length, character sets, and an integrated notepad to save passwords with names. Notes are stored in browser localStorage.

Files
- index.html — main UI
- styles.css — styling
- script.js — logic and localStorage for notes

How to run (Windows PowerShell):

1. Open the folder in Explorer and double-click `index.html`, or run:

```powershell
Start-Process index.html
```

2. The app will open in your default browser.

# Password Generator

A small static web app that generates secure passwords with options for length, character sets, and an integrated notepad to save passwords with names. Notes are stored in browser localStorage.

## Files
- `index.html` — main UI
- `styles.css` — styling
- `script.js` — logic, localStorage, export/import and optional encryption
- `tests.html` — simple browser-based smoke tests

## How to run (Windows PowerShell):

1. Open the folder in Explorer and double-click `index.html`, or run:

```powershell
Start-Process 'c:\Users\shali\OneDrive\Desktop\Password Generator\index.html'
```

2. The app will open in your default browser.

## Features
- Auto-generates a password on load and when controls change
- Copy password to clipboard
- Strength meter
- Save current password to the corner notepad with a name
- Persisted notes in localStorage (per browser/profile)

## Advanced features added
- Export notes to JSON (optionally encrypted with a passphrase using AES-GCM via Web Crypto)
- Import notes from JSON (supports encrypted payloads exported by this app)
- Password history (records saved passwords and offers filtering by text, minimum length and strength)
- Accessibility improvements: focus outlines, ARIA attributes, keyboard-friendly controls
- Small browser-based test page: `tests.html` for quick smoke checks

## Running tests
Open `tests.html` in the same folder to run a few quick browser checks that validate encryption and localStorage. From PowerShell:

```powershell
Start-Process 'c:\Users\shali\OneDrive\Desktop\Password Generator\tests.html'
```

## Privacy & Security
- Exported encrypted files are protected with the passphrase you provide; the app uses PBKDF2 + AES-GCM. The encryption is only as strong as your passphrase and device security.
- Passwords stored in localStorage are not encrypted by default. Use the encrypted export or a dedicated password manager for highly sensitive secrets.

## Next steps
- Add a proper import UI that supports merging and conflict resolution
- Provide optional encrypted localStorage with passphrase-protected sessions
- Add automated unit tests and a CI pipeline (ESLint, basic browser tests)
