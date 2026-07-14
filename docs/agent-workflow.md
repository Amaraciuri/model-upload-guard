# Agent workflow with mug

This is the supported end-to-end path for Claude Code, Codex CLI, Gemini CLI, and similar tools.

## Goals

1. The agent never sees `.env`, keys, `.git`, or other secrets.
2. The agent never writes directly to your real repository.
3. You review a unified diff before anything is applied.
4. A failed apply leaves the repo unchanged (or restorable).

## Path A — Browser / chat upload

```bash
cd your-project
mug init
mug scan
mug pack . -o project-for-ai.zip
```

Upload **only** `project-for-ai.zip`. Paste the AI-returned files into a mug workspace later, or ask the AI for a unified diff and apply manually after review.

## Path B — Terminal agent in a sandbox (recommended)

### 1. Create a sanitized workspace

```bash
mug workspace . -o ../project-ai-workspace
```

### 2. Choose a sandbox image that contains your agent

mug ships profile presets. Put an agent binary in a custom image, or use a shell profile to explore:

```toml
# .mug.toml
[sandbox]
profile = "python-dev"          # or agent-shell / node-dev
# image = "your-org/coding-agent:latest"
network = false
home_tmpfs = true
```

Build a minimal agent image yourself (example):

```dockerfile
FROM python:3.12-slim
# Install your agent CLI here. Do NOT bake secrets into the image.
RUN useradd -m -u 65534 agent || true
WORKDIR /workspace
```

### 3. Run the agent (no network by default)

```bash
mug run ../project-ai-workspace --interactive -- sh
# or:
mug run ../project-ai-workspace -- your-agent
```

Network is dual-gated: `sandbox.network = true` **and** `--allow-network`. Prefer offline when possible.

### 4. Review and apply

```bash
mug diff ../project-ai-workspace
mug apply ../project-ai-workspace --dry-run
mug apply ../project-ai-workspace --yes
```

If the original git tree is dirty or HEAD moved since workspace creation, mug refuses apply unless you pass `--force` after review.

### 5. Recovery

```bash
mug snapshots .
mug restore ~/.local/state/model-upload-guard/snapshots/.../….tar.gz ../restored --yes
```

## Pair with a command guard

Use `mug` (data boundary) + a destructive-command guard (execution boundary). Neither replaces the other.

## Smoke checklist

- [ ] `mug doctor` shows `safe_sandbox_available: true`
- [ ] `mug scan` exits 0 (or findings are baselined intentionally)
- [ ] Workspace does **not** contain `.env` / `.git`
- [ ] `mug run … -- echo ok` returns 0
- [ ] `mug apply --dry-run` lists expected files only
- [ ] `mug apply --yes` creates a snapshot path in the output
