# Security policy

Model Upload Guard is a defense-in-depth tool, not a guarantee that an AI model, plugin, IDE, operating system, container runtime, or uploaded archive is safe.

## Supported version

Security fixes currently target the latest release on the default branch.

## Reporting a vulnerability

Please open a private GitHub security advisory rather than a public issue. Include a minimal reproduction, platform, Python version, and whether Docker or Podman was used.

## Security principles

- Deny sensitive files by default.
- Block export when secret-like content is found.
- Never fall back from container isolation to direct host execution.
- Keep network disabled in the sandbox unless the user explicitly changes configuration.
- Require review and explicit confirmation before applying changes.
- Create a private local snapshot before every apply operation.
- Refuse protected-path modifications and excessive deletions.
