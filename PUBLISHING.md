# Publishing

Repository: `Amaraciuri/model-upload-guard`

## Release checklist (definitive)

1. Bump `version` in `pyproject.toml` and `mug/__init__.py`.
2. Update `CHANGELOG.md` and README install pin (`MUG_REF=…`).
3. Commit and push `main`.
4. Tag and push:

```bash
git tag -a v0.3.1 -m "Model Upload Guard v0.3.1"
git push origin main v0.3.1
```

5. Confirm the **release** workflow produced:
   - GitHub Release with `source.zip`, wheels, `SHA256SUMS.txt`
   - Optional PyPI publish (Trusted Publishing)

6. Verify install:

```bash
curl -fsSL https://raw.githubusercontent.com/Amaraciuri/model-upload-guard/v0.3.1/install.sh | MUG_REF=v0.3.1 bash
mug --version   # 0.3.1
```

## GitHub repo hygiene (one-time)

- Settings → Code security → enable **private vulnerability reporting**
- Settings → Branches → protect `main` (require `test` + `lint` checks)
- Settings → General → disable force-push to default branch

## PyPI Trusted Publishing (one-time)

1. Create project `model-upload-guard` on https://pypi.org
2. Add Trusted Publisher: GitHub → `Amaraciuri/model-upload-guard` → workflow `release.yml`
3. Next tagged release publishes automatically

Until PyPI is configured, the publish step is `continue-on-error: true` so GitHub releases still succeed. README and `mug doctor` prefer GitHub installs while PyPI returns 404.

## Manual PyPI fallback

```bash
python -m pip install build twine
python -m build
twine upload dist/*
```
