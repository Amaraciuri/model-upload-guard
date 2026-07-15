"""Embedded templates shipped with the package."""

from __future__ import annotations

AGENTS_MD = """# Agent instructions (Model Upload Guard)

Work **only** inside a mug workspace — never the real repository.

## Hard rules

1. Do **not** read, create, or modify `.env`, `*.pem`, `*.key`, credentials, or `.git`.
2. Do **not** write outside the current workspace directory.
3. Prefer small, reviewable edits. Avoid mass deletes and rewrite-everything patches.
4. After you finish, tell the human to run:

```bash
mug diff <workspace>
mug apply <workspace> --dry-run
mug apply <workspace> --yes
```

5. Never ask the human to paste secrets into chat. Never disable mug safety flags casually
   (`--allow-findings`, `--force`, `--allow-network`).

## Context

- You are running on a **sanitized copy** created by `mug workspace`.
- Secrets and VCS were excluded on purpose. Missing `.env` / `.git` is expected.
- Network may be disabled. Do not require online installs unless the human enabled `--allow-network`.

## Good outcomes

- Diff is small and related to the requested task.
- Tests pass when a test runner is available.
- No protected paths (`.mug.toml`, `.mug-baseline.json`, etc.) are rewritten.
"""
