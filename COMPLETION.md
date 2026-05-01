# VaultCore — completion notes

Public, MIT-licensed. See [LICENSE](LICENSE).

## What's in this build

A complete personal password manager:

- **Crypto core** (`Vault.Crypto`): AES-256-GCM, Argon2id, HKDF, TOTP (RFC 6238), HIBP check
- **Vault format** (`Vault.Core`): single-file, AEAD per-item + global HMAC, format v3 with audit + tombstones
- **CLI** (`Vault.Cli`): every operation scriptable
- **Desktop GUI** (`Vault.Desktop`): Avalonia 11, MVVM, all views (unlock, list, detail, add/edit, audit, settings, sync setup)
- **IPC layer** (`Vault.Ipc`): native messaging framing + named pipe transport + PSL matching
- **Native messaging host** (`Vault.Host`): AOT-compiled `vault-mh` proxy
- **Browser extension** (`extension/`): Manifest V3, TypeScript, Vite-built. Click-to-fill, save-on-submit, TOTP autofill (single + 6-cell)
- **Sync layer** (`Vault.Sync`): S3-compatible (AWS / B2 / MinIO / R2 / Wasabi), optimistic concurrency, item+tombstone merge, audit log union
- **Tests** (`tests/`): crypto vectors, file format, merger scenarios, IPC framing

## Build

```sh
# Backend
dotnet build
dotnet test

# AOT-compiled native messaging host
dotnet publish src/Vault.Host -c Release -r linux-x64
# (or win-x64, osx-arm64, osx-x64)

# Desktop
dotnet run --project src/Vault.Desktop

# Extension
cd extension && npm install && npm run build
```

## Wire-up checklist

1. `dotnet publish src/Vault.Host -c Release -r <rid>` → produces `vault-mh` binary
2. `cd extension && npm run build` → produces `extension/dist/`
3. Load `extension/dist/` as unpacked extension in Chrome/Edge → note the extension ID
4. Run install script with that ID:
   - Linux/macOS: `./src/Vault.Host/install.sh <ext-id> /full/path/to/vault-mh`
   - Windows: `.\src\Vault.Host\install.ps1 -ExtensionId <ext-id> -HostPath C:\full\path\vault-mh.exe`
5. Restart browser
6. Run desktop app: `dotnet run --project src/Vault.Desktop`
7. Create vault on first run, **WRITE DOWN THE SECRET KEY**
8. (Optional) "Sync setup..." button → S3-compatible remote credentials
9. (Optional) Settings → enable background sync
10. Browser extension popup should now show "Vault unlocked" and pull credentials per-site

## Pre-production checklist

Things to do before relying on this for real credentials:

- [ ] Replace `src/Vault.Ipc/public_suffix_list.dat` with the full official PSL from
      <https://publicsuffix.org/list/public_suffix_list.dat> (~280 KB). Without it, multi-suffix
      TLDs like `.co.uk` / `.com.au` won't match correctly.
- [ ] Run an audit: review all IPC handlers, all sync paths, all decrypt paths for error masking.
- [ ] Test the full unlock → sync → lock cycle on each OS you'll use.
- [ ] Test merge against a deliberately-tampered remote vault (HMAC failure should bail).
- [ ] Configure your S3-compatible bucket with object versioning ON for backup/recovery.
- [ ] Configure a bucket lifecycle policy if storage cost matters (the vault file rewrites entirely on every sync).
- [ ] Use a bucket-scoped IAM policy for the access keys, never root credentials.
- [ ] Back up the vault file and the secret key offline (paper, encrypted USB) — without the secret key,
      the vault is permanently unrecoverable even with the master password.

## Known limitations (deliberate, won't be fixed in v1)

| Area | Limitation | Workaround |
|------|-----------|-----------|
| Quick-unlock | No biometric / OS-keychain unlock | Use a strong master password, accept the daily Argon2 cost |
| Item types | Only Login has GUI add/edit; SecureNote/Card/Identity/SshKey via CLI | `vault add-login` then edit JSON field via... actually use CLI for now |
| Sync | No tombstone GC tracking sync vector | Manual `vault tombstone-prune <days>`; verify all devices synced first |
| Multi-vault | One vault per desktop session | Switch path on unlock screen |
| iframe forms | Cross-origin iframes (different registrable domain) won't get badge | Open the iframe URL directly |
| 6-cell TOTP in shadow DOM | Closed shadow roots block content script | Use popup "Copy TOTP" button |

## Threat model — what this protects against

- Adversary with the .vault file and no credentials: AEAD + Argon2id with strong master password and 34-bit Secret Key resist offline brute force well past the heat death of the sun.
- Adversary in transit during sync: TLS to the S3 endpoint, plus the vault is opaque ciphertext — server-side breach exposes no secrets.
- Malicious S3 server returning altered vault: HMAC over the full file body catches tampering at unlock.
- Malicious browser extension on the same browser: cannot launch the native host (allowed_origins is gated by Chrome on the registered extension ID), cannot read the pipe (per-user pipe ACL).
- Other OS user on the same machine: pipe ACL + 0600 file mode keep both vault and sync state private.

## What this does NOT protect against

- Malware running as the same user with debugger / memory access while the vault is unlocked. (No defense possible without OS-level enclaves.)
- Phishing pages mimicking a real site you have credentials for. PSL matching helps if the attacker uses a different domain; same-domain XSS would defeat it.
- Adversary with both the vault file and the master password but no Secret Key: structurally impossible to brute-force without it (Secret Key adds 128-bit entropy outside the KDF).
- Compromise of the device that creates a vault before you've written the Secret Key down.
