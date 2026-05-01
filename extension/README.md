# VaultCore browser extension

Manifest V3 extension that pulls credentials from your local VaultCore vault
via a native messaging host.

## Architecture

```
content.ts ─┐
popup.ts ───┼─► background.ts ─stdio─► vault-mh ─pipe─► VaultDesktop.exe
             │
             └  chrome.runtime.sendMessage
```

The extension never sees any keys. The native host is stateless. The desktop
app holds the unlocked session and answers IPC queries.

## Build

```sh
npm install
npm run build
```

Output goes to `dist/`. Load it as an unpacked extension:
- Chrome / Edge: `chrome://extensions` → Developer mode → "Load unpacked" → pick `dist/`
- Firefox: `about:debugging` → "This Firefox" → "Load Temporary Add-on" → pick `dist/manifest.json`

## Wire up the native host

After loading the extension, copy its ID from the extensions page, then:

```sh
# Linux/macOS
./src/Vault.Host/install.sh <extension-id> /full/path/to/vault-mh

# Windows (PowerShell)
.\src\Vault.Host\install.ps1 -ExtensionId <extension-id> -HostPath C:\full\path\vault-mh.exe
```

Restart the browser. Click the extension icon: it should report "Vault unlocked"
when the desktop app is running with an unlocked vault.

## Security model

- Autofill is opt-in: the extension overlays a small badge on password fields,
  user clicks it to fill. No silent autofill on page load.
- URL matching uses Public Suffix List on the desktop side. The extension
  passes the page URL untouched; matching happens with full vault context.
- Native messaging origins are gated by Chrome's allowed_origins list in the
  manifest installed by `install.sh`/`install.ps1`. Only the registered
  extension ID can launch the host.
- The pipe between host and desktop is per-user (`vaultcore-{username}`), so
  another local user can't talk to your desktop session.

## Limitations

- No iframe-cross-origin form support beyond the same registrable domain
- TOTP autofill is heuristic (autocomplete="one-time-code", or input name/id matching `otp|totp|2fa|code|verification|token`); on unusual sites use the popup "Copy TOTP" button
- Signup detection is heuristic: `autocomplete="new-password"` or two password inputs in scope. False positives mean a "Save new credentials" banner where login was meant; harmless
