# Publishing to GitHub

The release package can be published under the suggested repository name:

```text
Amaraciuri/model-upload-guard
```

## Fastest method with GitHub CLI

Install and authenticate GitHub CLI, then run from this repository:

```bash
gh auth login
gh repo create Amaraciuri/model-upload-guard \
  --public \
  --description "Model-agnostic safety boundary for sharing code with AI agents" \
  --source . \
  --remote origin \
  --push

git push origin v0.1.0
```

Create the first release:

```bash
gh release create v0.1.0 \
  --title "Model Upload Guard v0.1.0" \
  --notes-file CHANGELOG.md
```

## GitHub website method

1. Create a new empty public repository named `model-upload-guard` under `Amaraciuri`.
2. Do not initialize it with a README, license, or `.gitignore` because they already exist here.
3. Run:

```bash
git remote add origin git@github.com:Amaraciuri/model-upload-guard.git
git push -u origin main
git push origin v0.1.0
```

## Before announcing it publicly

- Enable GitHub secret scanning and push protection where available.
- Enable branch protection for `main`.
- Require the test workflow to pass.
- Enable private vulnerability reporting.
- Publish release checksums and, in a later release, signed artifacts.
- Replace the `main` installer example with a pinned release tag in announcements.
