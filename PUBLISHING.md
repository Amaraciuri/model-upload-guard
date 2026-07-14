# Publishing

Repository: `Amaraciuri/model-upload-guard`

## Release (tag → GitHub + PyPI)

1. Bump `version` in `pyproject.toml` and `mug/__init__.py`.
2. Update `CHANGELOG.md`.
3. Commit, tag, push:

```bash
git tag -a v0.3.0 -m "Model Upload Guard v0.3.0"
git push origin main v0.3.0
```

The `release` workflow (`.github/workflows/release.yml`) on tag push:

- builds sdist + wheel;
- writes `SHA256SUMS.txt`;
- creates a GitHub Release with artifacts;
- publishes to PyPI via Trusted Publishing (when configured).

## PyPI Trusted Publishing (one-time)

1. Create the project at https://pypi.org/manage/projects/ (name: `model-upload-guard`).
2. Add a Trusted Publisher: GitHub → `Amaraciuri/model-upload-guard` → workflow `release.yml` → environment `pypi` (optional).
3. Push a tag; the workflow publishes automatically.

Until PyPI is configured, the publish step is `continue-on-error: true` so GitHub releases still succeed.

## Manual PyPI publish (fallback)

```bash
python -m pip install build twine
python -m build
twine upload dist/*
```

## Before announcing publicly

- Enable GitHub secret scanning and push protection where available.
- Enable branch protection for `main` (require `test` workflow).
- Enable private vulnerability reporting.
- Pin installer examples to a release tag, not `main`.
