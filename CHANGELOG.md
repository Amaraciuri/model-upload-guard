# Changelog

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
