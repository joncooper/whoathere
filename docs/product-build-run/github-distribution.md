# GitHub Distribution Runbook

This runbook publishes the macOS local beta to GitHub so a clean Apple Silicon Mac can install it
from a release archive.

The current distribution shape is private by default:

- source pushed to `main`
- one GitHub Release per signed preview archive
- versioned archive assets for auditability
- stable `whoathere-macos-arm64-preview-latest.tar.gz` assets for installer convenience
- authenticated GitHub CLI access for clean Mac installs

Do not make the repository or release public until we intentionally decide to expose the beta.

## Current Local Artifact

The current signed and notarized artifact available in `dist/` is:

```text
dist/whoathere-macos-arm64-preview-a212742.tar.gz
dist/whoathere-macos-arm64-preview-a212742.tar.gz.sha256
dist/whoathere-macos-arm64-preview-a212742-notarization.zip.notarytool.json
dist/whoathere-macos-arm64-preview-a212742-runtime-qualification.json
```

The notarization receipt for that artifact reports `Accepted`.

## One-Time GitHub Setup

Authenticate the GitHub CLI:

```sh
gh auth login -h github.com
gh auth status
```

Create the private repository and push this local repo:

```sh
gh repo create joncooper/whoathere --private --source=. --remote=origin --push
```

If the repository already exists:

```sh
git remote add origin git@github.com:joncooper/whoathere.git
git push -u origin main
```

The test Mac must authenticate with GitHub before downloading the private release.

## Publish The Current Preview

Publish the existing signed archive:

```sh
scripts/whoathere-publish-github-release.sh \
  --repo joncooper/whoathere \
  --tag macos-local-beta-a212742 \
  --version a212742
```

The publisher uploads:

- `whoathere-macos-arm64-preview-a212742.tar.gz`
- `whoathere-macos-arm64-preview-a212742.tar.gz.sha256`
- `whoathere-macos-arm64-preview-latest.tar.gz`
- `whoathere-macos-arm64-preview-latest.tar.gz.sha256`
- notarization and runtime qualification receipts when present

## Install From A Clean Apple Silicon Mac

Install a specific release from the private repo:

```sh
gh auth login -h github.com
gh repo clone joncooper/whoathere
cd whoathere
scripts/whoathere-install-from-github.sh --private \
  --repo joncooper/whoathere \
  --tag macos-local-beta-a212742 \
  --prefix "$HOME/.whoathere"
```

Install the latest private GitHub Release from an existing checkout:

```sh
scripts/whoathere-install-from-github.sh --private \
  --repo joncooper/whoathere \
  --prefix "$HOME/.whoathere"
```

Then:

```sh
export PATH="$HOME/.whoathere/bin:$PATH"
whoathere doctor --json
```

## Validation

Before treating the GitHub release as usable:

```sh
shasum -a 256 -c dist/whoathere-macos-arm64-preview-a212742.tar.gz.sha256
gh release view macos-local-beta-a212742 --repo joncooper/whoathere
gh release download macos-local-beta-a212742 --repo joncooper/whoathere --pattern 'whoathere-macos-arm64-preview-latest.tar.gz*' --dir /tmp/whoathere-release-check
cd /tmp/whoathere-release-check
shasum -a 256 -c whoathere-macos-arm64-preview-latest.tar.gz.sha256
```

On the clean test Mac, the first useful checks are:

```sh
whoathere --help
whoathere doctor --json
whoathere scanners list --json
```

Then continue with `macos-local-beta-fresh-user-test-plan.md`.
