# Changelog

## 0.3.4 - 2026-07-22

Install/status/recovery UX: verified updates, local history, clearer first-run.

- **`mug status`**: install root, state dir, snapshot count, last/recent runs (`--offline`, `--json`).
- **Local history**: scan/pack/workspace/diff/apply/snapshot/restore append to private `history.json` under the state dir (never uploaded).
- **`mug update` verifies SHA256** like `install.sh`; `--allow-unverified` for git-archive fallback.
- **Recovery**: richer `mug snapshots` (reason/time/size), `mug restore --latest ../dir --yes`, menu **r) Recovery**.
- **`mug doctor --offline`**: skip GitHub/PyPI; surface PATH / state_dir / install_root.
- Installer PATH cliff fixed (absolute doctor hint + `hash -r`); uninstall prints state path.
- Next-step messages on init exists, clean scan, missing Docker, bad workspace/ZIP paths.

## 0.3.3 - 2026-07-16

Team scan rules, agent template, and richer interactive menu.

- **`[[scan.rules_add]]`**: add org/team secret regexes in `.mug.toml` (validated, additive to built-ins).
- **`scan.allowlist_paths`**: path globs whose findings are marked allowlisted and do not block export (shown separately from baselines).
- **`examples/AGENTS.md`** + menu **a) Agent rules** — write a fail-closed agent instructions file into the project.
- Menu UX: clear screen between screens, compact home after first paint, step headers, change preview with **path-by-path deletes** before allowing deletions.
- README threat model + SECURITY supply-chain checksum guidance; docs link the agent template.

## 0.3.2 - 2026-07-15

Apply policy visibility and menu navigation.

- **Apply policy surfaced**: `mug diff`, `mug apply` (incl. `--json`), and `mug doctor` show `max_changes` / `max_delete_ratio` / protected counts; errors point at `.mug.toml [apply]`.
- Interactive apply previews thresholds and this-run delete ratio before confirm; `--force` help text clarifies volume/git only (never protected paths).
- **Menu UX**: `b`/`back` returns to menu from any prompt; `q` quits; after each action, Enter returns to the home screen; Ctrl-C exits cleanly.
- Guide / cheat sheet document apply limits and force semantics.

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
