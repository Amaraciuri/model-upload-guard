# Security policy

Model Upload Guard is a defense-in-depth tool, not a guarantee that an AI model, plugin, IDE, operating system, container runtime, or uploaded archive is safe.

## Supported version

Security fixes currently target the latest release on the default branch.

## Reporting a vulnerability

Please open a private GitHub security advisory rather than a public issue. Include a minimal reproduction, platform, Python version, and whether Docker or Podman was used.

## Security principles

- Deny sensitive files by default; immutable patterns cannot be removed by config.
- Treat short exclude/protected lists as additive, never as full replacements.
- Block export when secret-like, high-entropy, or unscanned content is found.
- Seal workspace file hashes in a private local registry outside the agent mount.
- Never fall back from container isolation to direct host execution.
- Keep sandbox network dual-gated (`sandbox.network` plus `--allow-network`).
- Require review (`mug diff` / `--dry-run`) and explicit confirmation before applying changes.
- Create a private local snapshot before every apply operation.
- Refuse protected-path modifications and excessive deletions.
