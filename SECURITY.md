# Security policy

Model Upload Guard is a defense-in-depth tool, not a guarantee that an AI model, plugin, IDE, operating system, container runtime, or uploaded archive is safe.

## Supported versions

| Version | Status |
|---|---|
| Latest tagged release on GitHub (`v*`) | Supported |
| `main` branch | Best-effort (may change) |
| Older tags | No guaranteed backports |

Security fixes land on `main` and ship in the next tagged release. For production use, pin a release tag and prefer checksum-verified installs (`install.sh` or release `source.zip` + `SHA256SUMS.txt`).

## Reporting a vulnerability

Open a **private GitHub security advisory** on [Amaraciuri/model-upload-guard](https://github.com/Amaraciuri/model-upload-guard/security/advisories/new) rather than a public issue.

Include:

- mug version (`mug --version`)
- OS / Python version
- Whether Docker or Podman was used
- Minimal reproduction (commands + redacted config)

We aim to acknowledge advisories within **7 days** (best effort for a free/MIT project).

## Security principles

- Deny sensitive files by default; immutable patterns cannot be removed by config.
- Treat short exclude/protected lists as additive, never as full replacements.
- Block export when secret-like, high-entropy, or unscanned content is found.
- Prefer per-finding baselines over blanket `--allow-findings`.
- Seal workspace file hashes (and git HEAD when available) in a private local registry.
- Never fall back from container isolation to direct host execution.
- Keep sandbox network dual-gated (`sandbox.network` plus `--allow-network`).
- Require review (`mug diff` / `--dry-run`) and explicit confirmation before applying changes.
- Refuse apply when the original git tree is dirty or HEAD moved (override only with `--force`).
- Create a private local snapshot before every apply; roll back on mid-apply failure.
- Refuse protected-path modifications and excessive deletions.
- Installer verifies release SHA256 when assets exist; unverified installs need an explicit opt-in.

## Threat model

See the README sections *How it works* and *Privacy & security*. mug reduces accidental secret export and unsafe apply; it does not stop a determined attacker with a compromised container runtime, malicious image, or an explicitly dual-gated network session.

## Supply-chain notes

- Runtime depends on the Python standard library only.
- Prefer GitHub Release artifacts with `SHA256SUMS.txt` over installing opaque `main` snapshots.
- PyPI publish (when enabled) uses Trusted Publishing from this repository's `release` workflow.
