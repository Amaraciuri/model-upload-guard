<div align="center">

```
 ███╗   ███╗██╗   ██╗ ██████╗
 ████╗ ████║██║   ██║██╔════╝
 ██╔████╔██║██║   ██║██║  ███╗
 ██║╚██╔╝██║██║   ██║██║   ██║
 ██║ ╚═╝ ██║╚██████╔╝╚██████╔╝
 ╚═╝     ╚═╝ ╚═════╝  ╚═════╝
```

**The safety boundary for sharing code with AI.**

`git` protects history. `mug` protects **what leaves your machine**, **where the agent works**, and **what comes back**.

[![test](https://github.com/Amaraciuri/model-upload-guard/actions/workflows/test.yml/badge.svg)](https://github.com/Amaraciuri/model-upload-guard/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-3776ab?logo=python&logoColor=white)](./pyproject.toml)
[![Release](https://img.shields.io/github/v/release/Amaraciuri/model-upload-guard?include_prereleases&label=release)](https://github.com/Amaraciuri/model-upload-guard/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-27a644.svg)](./CONTRIBUTING.md)

[Quickstart](#quickstart) · [Install](#install) · [What it answers](#the-questions-your-workflow-cant-answer-today) ·
[How it works](#how-it-works) · [Agent workflow](./docs/agent-workflow.md) · [Compare](#how-it-compares) ·
[Commands](#commands) · [Security](./SECURITY.md) · [Changelog](./CHANGELOG.md)

</div>

---

AI coding tools are useful — and dangerous by default: they can upload `.env` files, read your whole home directory, rewrite the repo, or return a ZIP full of surprises.

**mug** is a model-agnostic, fail-closed boundary. It **sanitizes** what you share, **isolates** where agents work, **blocks** bad change sets, and **snapshots** before anything touches your real repository. No trust in the model required.

> Free & MIT. Stdlib-only runtime. Security-focused alpha — review every diff.

## Install

**Verified installer (recommended):** downloads the GitHub Release `source.zip` and checks SHA256.

```bash
curl -fsSL https://raw.githubusercontent.com/Amaraciuri/model-upload-guard/v0.3.4/install.sh | MUG_REF=v0.3.4 bash
```

**Verify (PATH):**

```bash
export PATH="$HOME/.local/bin:$PATH"   # if needed
hash -r
mug --version
mug doctor --offline
mug status
```

If the release assets are still propagating, allow an unverified archive of that tag (audit the tag first):

```bash
curl -fsSL https://raw.githubusercontent.com/Amaraciuri/model-upload-guard/v0.3.4/install.sh | MUG_REF=v0.3.4 MUG_ALLOW_UNVERIFIED=1 bash
```

**From a local clone:**

```bash
git clone https://github.com/Amaraciuri/model-upload-guard.git
cd model-upload-guard
./install.sh
```

**Manual verified install:**

```bash
curl -fsSL -O https://github.com/Amaraciuri/model-upload-guard/releases/download/v0.3.4/source.zip
curl -fsSL -O https://github.com/Amaraciuri/model-upload-guard/releases/download/v0.3.4/SHA256SUMS.txt
# macOS: shasum -a 256 -c SHA256SUMS.txt --ignore-missing
# Linux: sha256sum -c SHA256SUMS.txt --ignore-missing
pip install source.zip
```

**PyPI** (`pip install model-upload-guard`) is enabled when Trusted Publishing is configured; until then prefer the commands above. `mug doctor` tells you which path is live.

Update (SHA256-verified by default):

```bash
mug update --check
mug update
# mug update --allow-unverified   # only if release checksums are missing
```

## Quickstart

```bash
cd your-project
mug                              # interactive menu — or:
mug init
mug scan
mug pack . -o safe-for-ai.zip    # upload only this ZIP, never the raw repo
```

For a coding agent (Claude Code, Codex, Cursor, Gemini CLI, …) see **[docs/agent-workflow.md](./docs/agent-workflow.md)**:

```bash
mug workspace . -o ../project-ai-workspace
mug run ../project-ai-workspace -- your-agent
mug diff ../project-ai-workspace
mug apply ../project-ai-workspace --dry-run
mug apply ../project-ai-workspace --yes
```

That's the whole loop: **scan → export or workspace → review → apply**.

## What you need

| Piece | Needed for | Without it |
|---|---|---|
| **Python ≥ 3.11** | everything | (required) |
| **curl/wget** | remote installer | local clone |
| **Docker or Podman** | `mug run` (sandbox) | pack, workspace, scan, diff, apply still work |
| **git** | dirty/HEAD apply checks + gitignore warnings | apply still works; less context |

## The questions your workflow can't answer today

- *Am I about to upload secrets in this ZIP?*
- *Is the agent working on a copy — or my real `.git`?*
- *If it deletes 40 files, will I notice before it lands?*
- *Can someone tamper with the workspace manifest and trick `apply`?*
- *If apply fails halfway, is my repo left broken?*

mug answers all five, by design. Three answers are the core product:

### ① Export gate: nothing leaves dirty

`mug scan` finds sensitive filenames, provider tokens, high-entropy blobs, and unscanned binaries. **`mug pack` and `mug workspace` stop** unless you explicitly override. Review first, then ship a sanitized artifact.

```
HIGH     config.js:4 [github-token] GitHub token
         const token = '[REDACTED]';
Summary: 1 finding(s)
  tip: reviewed false positives? mug scan --update-baseline
```

### ② Isolation: agents don't touch the real repo

The agent gets a **sanitized workspace** — no `.git`, no `.env`, no keys. Optional **`mug run`** adds Docker/Podman: no network by default, read-only root, non-root user, writable ephemeral `HOME` for agent CLIs. Missing Docker? mug **refuses** a host fallback.

### ③ Reviewed return path: diff, thresholds, snapshot, rollback

Changes flow back through **`mug diff`** (unified patches), then **`mug apply --dry-run`**, then **`mug apply --yes`**. Deletions need `--allow-delete`. Protected paths (`.env`, keys, `.git`) cannot be introduced. A **local snapshot** is taken before every apply; mid-apply failures **roll back automatically**.

## Per-finding baseline (not `--allow-findings`)

False positive on one test fixture? Don't disable the whole scanner.

```bash
mug scan                              # review
mug scan --update-baseline            # accept specific findings only
git add .mug-baseline.json            # share with your team
mug pack . -o safe.zip                # export proceeds; baseline stays local
```

Fingerprints bind **rule + path + content**. Change the content → blocking returns. The baseline is **never exported** and **cannot be modified through a workspace**.

## How it works

mug never asks you to trust the model. It shrinks blast radius at three layers:

```
  YOUR REAL REPOSITORY                          AI (browser or agent)
  (.git, .env, keys, history)                         │
         │                                            │
         │  mug scan ──► findings + baseline           │
         │  mug pack ──► sanitized ZIP ──────────────┼──► chat upload
         │  mug workspace ──► sanitized copy           │
         │         │                                   │
         │         └── mug run (Docker/Podman) ────────┼──► agent works here
         │                    no network default       │         │
         │                    sealed manifest           │         │
         │                         │                   │         │
         │              mug diff ◄─┴───────────────────┘         │
         │              mug apply --dry-run                       │
         │              mug apply --yes (+ snapshot)               │
         ▼                                                        │
  REAL REPOSITORY ◄── only reviewed changes ──────────────────────┘
```

Principles that don't bend:

1. **Fail-closed config** — short `exclude` lists can't drop secret patterns; immutable patterns can't be removed.
2. **Sealed workspace registry** — file hashes live outside the agent mount; manifest tampering fails `diff`/`apply`.
3. **Explicit escape hatches** — `--allow-findings`, `--force`, `--allow-network` are audit signals, not "safe mode".
4. **No host fallback** — no Docker/Podman means no `mug run`, not silent execution on your machine.
5. **Local recovery** — snapshots stay on disk; never upload them to an AI service.

## How it compares

| | Upload repo ZIP | `.gitignore` only | Command guard (dcg) | **mug** |
|---|:---:|:---:|:---:|:---:|
| Strip secrets before upload | ✗ | ✗ | ✗ | ✅ |
| Agent works on sanitized copy | ✗ | ✗ | ✗ | ✅ |
| Review patches before apply | ✗ | ✗ | ✗ | ✅ |
| Block mass deletion / protected paths | ✗ | ✗ | partial | ✅ |
| Container isolation (`mug run`) | ✗ | ✗ | ✗ | ✅ |
| Per-finding false-positive baseline | ✗ | ✗ | ✗ | ✅ |
| Blocks destructive shell patterns | ✗ | ✗ | ✅ | ✅ (`mug guard`) |
| Model-agnostic | ✗ | ✅ | ✅ | ✅ |
| Stdlib-only, no runtime deps | — | — | varies | ✅ |

Use **both** mug and a command guard: mug controls *what leaves and returns*; dcg blocks *known destructive commands* at execution time.

## Commands

| Command | What it does |
|---|---|
| `mug` / `mug menu` | Interactive menu (status, quick actions) |
| `mug guide` | Print the safe workflow |
| `mug init` | Write deny-by-default `.mug.toml` |
| `mug scan` | Secret & sensitive scan (`--update-baseline` to accept reviewed findings) |
| `mug pack` | Sanitized ZIP for browser/chat upload |
| `mug workspace` | Sanitized copy for coding agents |
| `mug run` | Sandbox agent in Docker/Podman (`--allow-network` dual-gated) |
| `mug diff` | Path changes + unified patches |
| `mug apply` | Snapshot + apply (`--dry-run` first) |
| `mug guard` | Preflight destructive shell patterns |
| `mug doctor` | Python, config, sandbox posture (`--offline` skips network) |
| `mug status` | Install / state dir / last runs |
| `mug update` | Self-update from GitHub (SHA256; `--check` / `--allow-unverified`) |
| `mug snapshot` / `snapshots` / `restore` | Private local recovery (`restore --latest`) |

Add `--json` on inspection commands for CI. Progress bars on TTY only (`MUG_NO_PROGRESS=1` or `CI=1` to disable).

## Configuration snapshot

```toml
[scan]
fail_on = "high"
fail_on_unscanned = true
# allowlist_paths = ["fixtures/**"]
# [[scan.rules_add]]
# severity = "high"
# rule = "internal-token"
# pattern = 'myorg_[A-Za-z0-9]{20,}'
# message = "Internal org token"

[export]
exclude_add = ["private/"]
allow_weaken_defaults = false

[sandbox]
profile = "python-dev"   # default | agent-shell | python-dev | node-dev
network = false
user = "65534:65534"
read_only_root = true
home_tmpfs = true        # ephemeral HOME for agent CLIs
```

Project `.mug.toml` merges over `~/.config/mug/config.toml`. See [`examples/mug.toml`](./examples/mug.toml) and [`examples/AGENTS.md`](./examples/AGENTS.md).

## Privacy & security, by default

- **Export blocked on secrets** — scan runs before pack/workspace; unscanned binaries and large files refused by default.
- **Immutable excludes** — `.env`, keys, credentials patterns always enforced.
- **Dual-gated network** — `sandbox.network = true` **and** `mug run --allow-network`.
- **Transactional apply** — failed apply rolls back; pre-apply snapshot kept.
- **No phone-home** — `mug update` runs only when you ask; `doctor`/`status` network checks are optional (`--offline`).

## Threat model

mug assumes you want to reduce **accidental** secret export and **unreviewed** writes back into a repo. It helps when:

- You (or an agent) might upload a ZIP that still contains `.env` / keys.
- An agent edits a sanitized workspace and you want a gate before touching the real tree.

mug does **not** protect against:

- A compromised Docker/Podman runtime or a malicious sandbox image.
- An agent with dual-gated network that exfiltrates what it already sees.
- Malware already running on the host with access to your original files.
- Deliberate misuse of `--allow-findings`, `--force`, or `--allow-network`.

Verify installs with release `SHA256SUMS.txt` (or `install.sh`). Prefer pinned tags over opaque `main` checkouts. Details: [`SECURITY.md`](./SECURITY.md).

Honest limitations: mug reduces risk; it does not make arbitrary agent code safe.

## Development

```bash
python -m unittest discover -s tests -v
ruff check mug tests
mypy mug
python -m mug --version
```

49 tests · ruff + mypy in CI · release workflow publishes wheels + SHA256 checksums.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Security reports: private GitHub advisory ([SECURITY.md](./SECURITY.md)).

## License

[MIT](./LICENSE) © Davide Volpato and contributors. Free for personal and commercial use.
