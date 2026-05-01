# Publishing to GitHub

A checklist to take this from local repo to public GitHub repo with working CI.

## Pre-flight

```sh
# From the repo root
git init
git add .
git status
```

Review `git status` — confirm no `.vault`, `.vault.sync`, or `node_modules`
are staged. If anything sensitive shows up, add it to `.gitignore` first.

## Initial commit

```sh
git add .
git commit -m "Initial commit"
```

## Create the GitHub repo

1. Go to <https://github.com/new>
2. Name: `VaultCore`
3. Public
4. **Do NOT** initialize with README, .gitignore, or license — we have ours

## Push

```sh
git branch -M main
git remote add origin git@github.com:YOUR_USER/VaultCore.git
git push -u origin main
```

(Use HTTPS URL `https://github.com/YOUR_USER/VaultCore.git` if you don't have SSH set up.)

## Replace placeholders

Search for `YOUR_USER` across the repo and replace with your actual GitHub
username:

```sh
# Linux/macOS
grep -rl "YOUR_USER" --include="*.md" --include="*.yml"
# Edit each file, replace YOUR_USER with the real username

# Windows PowerShell
Get-ChildItem -Recurse -Include *.md,*.yml | Select-String "YOUR_USER"
```

Files that need updating:
- `README.md` — badge URLs and Docker pull URL
- `.github/ISSUE_TEMPLATE/config.yml` — security advisory link

Commit and push:

```sh
git add .
git commit -m "Set GitHub username in templates"
git push
```

## Configure repo settings on GitHub

After the first push, on the repo's GitHub page:

1. **Settings → General**
   - "Issues" enabled
   - "Discussions" optional but recommended
   - "Sponsorships" up to you

2. **Settings → Branches** → Add branch protection rule for `main`:
   - Require a pull request before merging
   - Require approvals: 1 (or 0 if you're solo)
   - Require status checks: `Build & test (.NET)`, `Build extension (Node)`, `Analyze (csharp)`, `Analyze (javascript-typescript)`

3. **Settings → Actions → General**
   - Workflow permissions: "Read and write permissions" (so the release
     workflow can create releases and push images)

4. **Settings → Security → Code security and analysis**
   - Dependabot alerts: ON
   - Dependabot security updates: ON
   - CodeQL: already configured by `.github/workflows/codeql.yml`

5. **Packages**
   - The first time the release workflow pushes to `ghcr.io/YOUR_USER/vaultcore-cli`,
     a new package appears under your profile. Make it public:
     Profile → Packages → vaultcore-cli → Package settings → "Change visibility" → Public

## First release

Releases are triggered by tags matching `v*`:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The release workflow will:
- Build CLI / native messaging host / desktop binaries for linux-x64, win-x64, osx-arm64
- Build the extension
- Push the Docker image to `ghcr.io/YOUR_USER/vaultcore-cli:0.1.0` and `:latest`
- Create a GitHub release with all artifacts attached

## What's tracked vs what isn't

In the repo:
- All source code (`src/`, `extension/src/`, `tests/`)
- Build configs (`*.csproj`, `package.json`, `vite.config.ts`, etc.)
- Solution file
- Docs (`README.md`, `COMPLETION.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`)
- CI workflows (`.github/`)
- Dockerfile + .dockerignore
- `Directory.Build.props`, `.editorconfig`
- Public Suffix List bundled snapshot
- Extension icons (PNG + source SVG)

NOT in the repo (filtered by `.gitignore`):
- Compiled artifacts (`bin/`, `obj/`, `publish/`, `dist/`, `node_modules/`)
- Vault files (`*.vault`, `*.vault.sync`)
- Local secrets (`.env`, `*.key`)
- Local native messaging manifests with absolute paths
- IDE settings

## After the first release

Update `README.md` to mention the latest release version near the top, and
keep the `COMPLETION.md` "Pre-production checklist" section honest.
