# Security policy

## Reporting a vulnerability

Open a private Security Advisory on GitHub:
1. Go to the repository's Security tab
2. Click "Report a vulnerability"
3. Describe the issue with reproduction steps

Do **not** open a regular issue. Public disclosure of an unfixed
vulnerability harms users.

A maintainer will respond within 7 days. Coordinated disclosure timeline
is negotiable based on severity.

## Scope

In scope:
- Vulnerabilities in `Vault.Crypto`, `Vault.Core`, `Vault.Sync`, `Vault.Ipc`
- Vulnerabilities in the native messaging host or browser extension that
  could leak vault contents or credentials
- Any path that allows reading the master password, secret key, or
  decrypted vault contents from outside the application
- Any cryptographic flaw in the file format or sync merge logic

Out of scope:
- Issues that require physical access to an unlocked vault
- Issues that require malware running as the same OS user (no defense
  possible without OS-level enclaves)
- Phishing / social engineering
- Denial of service against the desktop app
- Issues in third-party dependencies (report upstream first; we'll bump
  the dependency once the fix lands)

## Threat model

See [README.md](README.md) "Threat model" section. Summary:

- The vault file is opaque ciphertext. Loss of `vault.bin` alone is fine.
- The Secret Key is required for decryption, even with the master password.
  Loss of both = recovery. Loss of the Secret Key alone = irrecoverable.
- Sync remotes (S3) see only ciphertext.
- Local memory of the unlocked process is **not** protected against
  same-user malware. This is a deliberate choice; OS-keychain integration
  is on the roadmap.

## Security-relevant defaults

| Setting | Default | Why |
|---------|---------|-----|
| Auto-lock | 5 min | Reasonable trade-off for personal use |
| Clipboard auto-clear | 30 s | Limits accidental paste exposure |
| Background sync | OFF | Keeps credentials in memory; opt-in |
| Failed-attempt rate limit | 5 fails / 60 s → 5 min lockout | Slows online brute force |
| Argon2id memory | 64 MiB | Resists offline brute force on consumer hardware |

## Public Suffix List

`src/Vault.Ipc/public_suffix_list.dat` is bundled. The bundled copy may
become stale. Replace with the current copy from
<https://publicsuffix.org/list/public_suffix_list.dat> for production use.
A stale PSL doesn't allow site spoofing but may cause matches to miss on
multi-suffix TLDs (e.g. `.co.uk`).
