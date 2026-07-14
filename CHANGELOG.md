# Changelog

## 0.3.1 - 2026-07-14

Make installs trustworthy and apply git-aware.

- **Verified installer**: defaults to tag `v0.3.1`, downloads release `source.zip`, verifies SHA256 (`MUG_ALLOW_UNVERIFIED=1` escape hatch).
- **Release assets**: workflow ships `source.zip` + `SHA256SUMS.txt` on every tag.
- **Git-aware apply**: refuses when original HEAD moved or the tree is dirty (override with `--force`).
- Workspace registry seals `git_head` when available.
- Scanner: Vercel, Supabase, Railway, Cloudflare, Firebase assignment, DigitalOcean tokens.
- Docs: `docs/agent-workflow.md`; SECURITY.md supported-versions table; README install is honest about PyPI.
- CI: Docker end-to-end smoke (`workspace` → `mug run` → `diff` → `apply --dry-run`).
- `mug doctor` reports PyPI availability and a correct install hint.

## 0.3.0 - 2026-07-14

Per-finding baselines, self-update, transactional apply, and an agent-ready sandbox.

- `.mug-baseline.json`: accept individually reviewed findings with `mug scan --update-baseline` instead of the all-or-nothing `--allow-findings`. Fingerprints bind rule+path+content, so any change re-triggers blocking. The baseline is never exported and cannot be modified through a workspace.
- `mug update`: self-update from GitHub (`--check` to only compare versions, `--ref` to pin). Explicit action only — mug never phones home on its own.
- Transactional apply: a mid-apply failure now rolls back automatically to the pre-apply state; the snapshot is kept either way.
- Sandbox: writable tmpfs `HOME=/home/agent` (nothing persists after exit) so agent CLIs work as non-root with a read-only root filesystem. Configurable via `sandbox.home_tmpfs` / `sandbox.home_size`.
- Sandbox profiles: `sandbox.profile` presets (`default`, `agent-shell`, `python-dev`, `node-dev`) set a base image/stack; explicit `[sandbox]` keys override the preset.
- Scanner: warns when a gitignored file would still be exported (`gitignored-file`, medium) — gitignored files are often local-only configs holding secrets.
- CI: ruff lint job; release workflow builds artifacts with SHA256 checksums and supports PyPI Trusted Publishing.

## 0.2.2 - 2026-07-14

Terminal UX: interactive menu, progress bars, and clearer guidance.

- `mug` / `mug menu` open an interactive guide (scan, pack, workspace, diff, apply, …).
- `mug guide` prints the typical safe workflow; cheat sheet available from the menu.
- Progress bars on `scan` / `pack` / `workspace` (stderr, TTY-only; disable with `MUG_NO_PROGRESS=1` or `CI=1`).
- Colorized findings/summary when the terminal supports it (`NO_COLOR=1` to disable).

## 0.2.1 - 2026-07-14

Scanner calibration: quieter false positives, clearer large-file guidance.

- Skip high-entropy findings in dependency lockfiles and checksum/integrity lines (npm, yarn, cargo, go.sum, etc.).
- Default export excludes add `.DS_Store`, `.vexp`, `.gradle`, IDE junk (`.idea`, `.vscode`), and common editor backups.
- `mug scan` prints a severity/rule summary plus tips for `unscanned-large` and `high-entropy`.
- Large-file findings include actionable remediation text.
- Reject KEY=VALUE-style entropy matches; exclude common audio (`.m4a`, `.ogg`, …) and `.jar` by default.

## 0.2.0 - 2026-07-14

Hardened fail-closed release for public/self-hosted use (still MIT, no paid features).

- Fail-closed configuration: export/protected defaults always apply; short `exclude` lists can no longer drop secret patterns.
- Immutable exclude/protected patterns cannot be removed even with weaken flags.
- Content scanner blocks unscanned binary/large files by default; adds entropy checks and more provider rules.
- Common media/binary extensions are excluded by default so image/font assets do not silently block export.
- Workspace manifests are sealed in the private local registry; tampering fails closed on diff/apply.
- `mug diff` shows unified patches; `mug apply --dry-run` previews without writing.
- Sandbox runs as non-root by default; network requires dual confirmation (`sandbox.network=true` and `--allow-network`).
- `mug doctor` reports posture warnings (network weaken, root user, weaken-defaults).

## 0.1.0 - 2026-07-14

- Initial alpha release.
- Secret and sensitive-file scanning.
- Sanitized ZIP export.
- Sanitized AI workspace creation.
- Docker/Podman sandbox with no network by default.
- Review, deletion thresholds, protected paths, snapshots, and confirmation-gated apply.
- Recovery snapshot and restore commands.
- Destructive-command preflight checks.
