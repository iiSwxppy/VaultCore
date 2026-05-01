# VaultCore

[![CI](https://github.com/iiSwxppy/VaultCore/actions/workflows/ci.yml/badge.svg)](https://github.com/iiSwxppy/VaultCore/actions/workflows/ci.yml)
[![CodeQL](https://github.com/iiSwxppy/VaultCore/actions/workflows/codeql.yml/badge.svg)](https://github.com/iiSwxppy/VaultCore/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Personal password vault. Crypto core + CLI + Avalonia desktop client + browser extension via native messaging.

## Quick start

### Docker (CLI only)

```sh
docker run --rm -it \
  -v $HOME/vaults:/vaults \
  -e VAULT_SECRET_KEY="A1-..." \
  ghcr.io/YOUR_USER/vaultcore-cli:latest list /vaults/my.vault
```

### From source

```sh
# Backend
dotnet build
dotnet test
dotnet run --project src/Vault.Desktop

# Extension
cd extension && npm install && npm run build
```

See [COMPLETION.md](COMPLETION.md) for the full wire-up checklist.

## Status

Implemented:

1. Crypto primitives (Argon2id, AES-256-GCM, HKDF, TOTP)
2. Vault file format v2 with HMAC integrity + audit log section
3. CLI with full feature surface
4. CRUD operations + master password rotation (without re-encrypting items)
5. HIBP breach check
6. Import: Bitwarden JSON, 1Password .1pux
7. Export: encrypted backup (file copy) + plaintext JSON (with double confirmation)
8. Encrypted append-only audit log per vault
9. Avalonia 11 desktop client with unlock + vault view + Add/Edit/Delete dialogs +
   audit viewer + settings + clipboard auto-clear + idle auto-lock + failed-attempt rate limiting
10. **Native messaging host** (`vault-mh`) — stateless proxy between extension and desktop
11. **Browser extension** (Manifest V3, TypeScript) — opt-in click-to-fill on password fields, popup with status & quick-copy
12. **Public Suffix List** based registrable-domain matching for autofill
13. **S3-compatible sync layer** with optimistic concurrency, item-level merge, audit log union — works with AWS, Backblaze B2, MinIO, R2, Wasabi
14. **Tombstones** for delete propagation across synced devices, with resurrection rule
15. **KeePass 2.x XML import**
16. **Sync button in desktop** with credential prompt
17. **Background sync** (opt-in) — interval timer + FileSystemWatcher debounced trigger
18. **Save-on-submit** in browser extension — form submit detection + save banner, distinguishes signup from login
19. **TOTP autofill** directly into one-time-code inputs (single input or 6-cell cluster), with fallback to popup copy
20. **Sync remote configuration UI** in desktop with test-connection button, no longer CLI-only
21. **Tombstone GC** via `vault tombstone-list` / `vault tombstone-prune`
22. **Scriptable sync** with `vault sync --quiet` and `VAULT_MASTER_PASSWORD` / `VAULT_SECRET_KEY` env vars (cron-friendly)

## Layout

```
src/
  Vault.Crypto/        primitives
  Vault.Core/          vault format, items, audit, import, export, session
  Vault.Cli/           AOT-compiled `vault` CLI binary
  Vault.Desktop/       Avalonia 11 GUI
  Vault.Ipc/           shared IPC contracts + native-messaging framing + PSL
  Vault.Host/          AOT-compiled `vault-mh` native messaging host
  Vault.Sync/          S3-compatible sync (push/pull/merge with optimistic concurrency)
extension/             TypeScript MV3 extension (Vite-built)
tests/
  Vault.Crypto.Tests/
  Vault.Core.Tests/
  Vault.Ipc.Tests/
  Vault.Sync.Tests/
```

## Browser flow (end-to-end)

```
[Page] form with password input
   │
   ▼
content.ts ── chrome.runtime.sendMessage({find_credentials, url}) ──► background.ts
                                                                       │ chrome.runtime.connectNative
                                                                       ▼
                                                                     vault-mh (stdio JSON)
                                                                       │ named pipe vaultcore-{user}
                                                                       ▼
                                                                  VaultDesktop.exe
                                                                  (PipeServerService)
                                                                       │
                                                              uses unlocked VaultSession to
                                                              compute matches by registrable domain
```

The extension never sees keys or item ciphertext. The host is stateless. Only
the desktop holds the unlocked session.

## Build

Requires .NET 10 SDK + Node.js 20+ for the extension.

```sh
# Backend
dotnet build
dotnet test

# Native messaging host (AOT-compiled, single binary)
dotnet publish src/Vault.Host -c Release -r linux-x64    # or win-x64, osx-arm64

# Desktop
dotnet run --project src/Vault.Desktop

# Extension
cd extension
npm install
npm run build
```

## Wire up extension + native host

1. Build the extension (`npm run build`); load `extension/dist` as unpacked in
   Chrome/Edge (Developer mode).
2. Note the extension ID shown by the browser.
3. Build the host: `dotnet publish src/Vault.Host -c Release -r <rid>`. The
   binary is `vault-mh` (Linux/macOS) or `vault-mh.exe` (Windows).
4. Register the host:
   ```sh
   ./src/Vault.Host/install.sh <extension-id> /full/path/to/vault-mh
   ```
   Windows:
   ```pwsh
   .\src\Vault.Host\install.ps1 -ExtensionId <id> -HostPath C:\path\vault-mh.exe
   ```
5. Restart the browser. Open the extension popup — should report "Vault unlocked"
   while VaultDesktop is running.

## Crypto pipeline

```
master password ──► Argon2id(salt, ad=accountId) ──► MUK (32B)
                                                       │
                       Secret Key (string) ──SHA256──► salt
                                                       │
                                            HKDF-SHA256
                                                       │
                                                      AUK (32B)
                                                       │
                          ┌────────────────────────────┼──────────────────────┐
                          ▼                            ▼                      ▼
                   AES-GCM("vault-verify-v1")   AES-GCM(VaultKey)      (used only at unlock)

VaultKey ─ HKDF("vault-hmac-v1")        ──► HmacKey
       ─ HKDF("vault-audit-v1")       ──► AuditKey
       ─ HKDF("vault-item-v1" || uuid)──► ItemKey
```

## CLI

```
vault init <path>                       Create a new vault
vault unlock <path>                     Verify password (test unlock)
vault list <path>                       List item titles
vault search <path> <query>             Search items by title/username/url
vault find-url <path> <url>             Find logins matching a URL (eTLD+1)
vault get <path> <id>                   Show one item (decrypted, audit-logged)
vault add-login <path>                  Add a login interactively
vault delete <path> <id>                Delete an item
vault change-password <path>            Rotate master password
vault import-bitwarden <path> <file>    Import Bitwarden JSON export
vault import-1pux <path> <file>         Import 1Password .1pux archive
vault import-keepass-xml <path> <file>  Import KeePass 2.x XML export
vault export-encrypted <path> <out>     Backup vault (still encrypted)
vault export-plaintext <path> <out>     DANGEROUS: dump everything as JSON
vault audit <path> [--all]              Show audit log (last 50, or all)
vault audit-truncate <path> <keep>      Drop all but most recent N entries
vault tombstone-list <path>             Show pending deletes
vault tombstone-prune <path> <days>     Drop tombstones older than N days
vault sync-configure <path>             Set up S3-compatible remote
vault sync <path> [--quiet]             Pull, merge, push (optimistic concurrency)
vault sync-status <path>                Show last-known sync state
vault genpass [--len N] [--no-symbols]
vault totp <base32-secret>              Print current TOTP code
vault check-pwned                       Check a password against HIBP
```

## Sync

S3-compatible bucket. Tested mentally against AWS, Backblaze B2, MinIO, R2, Wasabi —
the SDK handles the dialect differences via `ForcePathStyle` + custom endpoint.

### Setup (Backblaze B2 example)

```sh
vault sync-configure ./my.vault
# Endpoint URL (e.g. https://s3.us-west-002.backblazeb2.com): https://s3.us-west-002.backblazeb2.com
# Region [us-east-1]: us-west-002
# Bucket name: my-vault-bucket
# Object key [vault.bin]: vault.bin
# Access key ID: 0021xxxx
# Secret access key: ********
# Force path style? [Y/n]: Y
```

State written to `./my.vault.sync` (next to the vault file). Contains the
remote config + last known ETag — no secret material from the vault itself.

### Sync flow

```sh
vault sync ./my.vault
```

1. HEAD remote → current ETag
2. If ETag matches `LastKnownETag` → push local with `If-Match`, done.
3. Otherwise pull remote, decrypt with same password+SecretKey, compare
   VaultKey fingerprints. Refuse if they differ (different vaults).
4. Merge: union of items (newer UpdatedAt wins on collision), audit log
   concatenated and sorted by timestamp.
5. Push merged file with `If-Match=current_remote_etag`.
6. On conflict (someone pushed during step 4): retry up to 3 times.

### What CAN sync

- Item add / update on either device merges deterministically
- Audit log stays union-of-events across devices
- Master password rotation propagates (the new manifest is on the merged file;
  next sync from the other device will reject the old password — user has to
  unlock with new password locally before next sync)

### Tombstones

Format v3 adds a tombstones section. When you delete an item, a small record
`(itemId, deletedAt)` is added. The merger uses tombstones to drop the item
on remote when their UpdatedAt &lt; tombstone DeletedAt.

**Resurrection**: if remote has the item with UpdatedAt &gt; DeletedAt (you
re-created it explicitly after deleting), the tombstone is dropped and the
item is kept. Otherwise the deletion propagates.

Tombstones are stored plaintext (just UUID + timestamp) — they leak only that
"some item used to exist". The vault HMAC binds them to the rest of the file,
so deletion of a tombstone (to revive a deleted item) breaks the file integrity.

### What CAN'T sync (yet)

- **Schema upgrades** are file-format-version-bumped (v3 now), so devices
  must be on compatible builds. v1/v2 files open as v3 read-only-style and
  upgrade on next save.
- Sync is manual via the CLI or the desktop "Sync" button. No background
  daemon yet.
- Tombstones never auto-GC. They're tiny (~24 bytes each), so for a personal
  vault this is fine — but a future cleanup tool could prune tombstones older
  than N days IF the user confirms all devices have synced past that date.

## Audit semantics

Autofill from the extension logs once per `find_credentials` call when
matches are returned, with details `autofill request for <domain>, N match(es)`.
Individual credential decrypts during search are NOT logged (would flood).

## Security notes

- **Click-to-fill, never auto-fill on load.** The extension overlays a small
  badge on password fields. Filling is an explicit user action.
- **PSL-based matching.** A login for `https://accounts.google.com` will match
  `https://mail.google.com` because they share registrable domain `google.com`,
  but won't match `google-impostor.com`. Replace
  `src/Vault.Ipc/public_suffix_list.dat` with the full
  https://publicsuffix.org/list/public_suffix_list.dat for production.
- **Per-user pipe.** The named pipe is `vaultcore-{username}`, isolating
  multi-user systems.
- **Native host gated by browser.** Only extensions whose ID is in
  `allowed_origins` (from the install script) can launch `vault-mh`.
- **Host is stateless.** A compromised host process leaks only one in-flight
  request/response pair.

### Background sync

Optional, off by default. When enabled in Settings, the master password and
secret key entered at unlock are kept in process memory (SecureBytes) for the
session. The service then syncs:

- On a configurable interval (default 5 minutes)
- 30 seconds after any local vault file change (debounced FileSystemWatcher)

Lock or app close zeroes the credentials and stops the watchers. Trade-off:
this is weaker than the default (credentials only briefly during unlock). For
single-user multi-device convenience it's reasonable; for shared workstations
or hostile environments, leave it off.

### Save-on-submit

The content script listens for form submissions on pages with password
fields, plus Enter keypresses in password / text / email inputs (covers SPAs
without `<form>`). On submit:

- Capture username + password
- If matching credentials already exist for this site, do nothing
- Otherwise show a save banner (auto-dismisses after 30s)
- User clicks Save → `add_credential` IPC → desktop creates a Login item

The page URL is sent untrimmed; the desktop derives title from the host.

## Not yet implemented

- **OS-keychain / biometric quick-unlock.** Per-platform (DPAPI on Windows,
  libsecret on Linux, Keychain on macOS, Hello/TouchID for biometric) — kept
  out for now to avoid platform-specific dependencies.
- **Sync test connection from CLI.** Available in desktop "Sync setup..." but
  not as a standalone CLI command yet.
- **Add/Edit dialogs for non-Login item types in desktop GUI.** SecureNote /
  CreditCard / Identity / SshKey / TotpSeed are CLI only.
- **6-cell TOTP cluster fill on shadow-DOM-encapsulated inputs.** Some banks
  use closed shadow roots; the extension's content script can't pierce those.
- **Auto-prune of tombstones.** Manual via `vault tombstone-prune`. A daemon
  could schedule pruning when all known devices have synced past a watermark,
  but tracking that requires a sync-state-vector field, not implemented.
- **Multi-vault support in desktop.** UnlockView assumes one vault path at a
  time. Switching vaults = change the path field, unlock again.

