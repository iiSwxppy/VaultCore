# Contributing to VaultCore

Thanks for your interest. A few notes before you open a PR.

## Scope

VaultCore is a personal-use password manager. It's not trying to be a
multi-user service. Features that conflict with that scope (multi-tenancy,
shared vaults, account recovery via email, etc.) are out of scope.

## Areas where contributions are welcome

- Additional KDF parameter sets / migration paths
- Importers for other password managers (KeePass kdbx binary, Dashlane, LastPass)
- Bug fixes in the merger or sync layer
- Test coverage gaps
- Documentation, especially threat-model write-ups
- Cross-platform polish (macOS unlock UX, Linux file mode hardening)
- New tests around the IPC layer / extension protocol

## Areas where contributions need design discussion first

- Anything touching the on-disk format (open an issue with a design proposal)
- Anything touching the crypto pipeline (same)
- Adding new IPC message types (extension <-> desktop contract)
- New item types (impacts JSON contracts and import/export)

Please open an issue describing the design before writing the code.

## Development setup

```sh
# Backend
dotnet restore
dotnet build
dotnet test

# Extension
cd extension
npm install
npm run build
```

Format:
- C#: keep nullable enabled. Treat warnings as errors except where the
  project file already overrides (auto-generated MVVM source-gen output).
- TypeScript: strict mode, no `any`, no implicit returns.

## Testing requirements

Any change touching crypto / file format / merger / sync must have at least
one new test. Bug fixes should include a regression test that fails before
the fix and passes after.

```sh
dotnet test
```

## Security issues

Do **not** open public issues for vulnerabilities. See SECURITY.md.

## Commit hygiene

- Short subject line, imperative mood ("Fix tombstone resurrection edge case",
  not "Fixed" or "Fixing")
- Body explaining the *why*, not the *what* — the diff shows what
- One logical change per commit; squash before opening the PR if needed
