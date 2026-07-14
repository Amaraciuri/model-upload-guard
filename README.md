# Model Upload Guard (`mug`)

**A model-agnostic safety boundary for sharing source code with AI tools and applying their changes without handing them your real repository.**

`mug` does not try to make an AI model trustworthy. It reduces what the model can see, limits where an agent can write, blocks dangerous change sets, and creates a recovery point before anything touches the original project.

> Status: security-focused alpha (**v0.2.2** fail-closed). Free/MIT. Use defense in depth, keep source control enabled, and review every diff.

## Why this exists

AI coding tools can be useful, but a prompt, tool bug, compromised dependency, or mistaken command can:

- upload `.env` files, private keys, cloud credentials, databases, or Git history;
- inspect unrelated files on the computer;
- delete or overwrite large parts of a project;
- rewrite Git history or destroy uncommitted work;
- return a modified archive containing unexpected files.

Command hooks such as `destructive_command_guard` are valuable because they intercept known dangerous commands. `mug` addresses a different layer: **what leaves the machine, where the agent works, and how its changes return to the original repository**.

## Core workflow

```text
REAL REPOSITORY
      │
      ├── mug scan       → detect sensitive names and secret-like content
      ├── mug pack       → sanitized ZIP for chat/browser upload
      └── mug workspace  → sanitized copy for coding agents
                               │
                               └── mug run → Docker/Podman, no network by default
                                                   │
                                                   ▼
                                           mug diff / mug apply
                                      review + thresholds + snapshot
                                                   │
                                                   ▼
                                           REAL REPOSITORY
```

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Amaraciuri/model-upload-guard/main/install.sh | bash
```

Pin a release tag (recommended):

```bash
curl -fsSL https://raw.githubusercontent.com/Amaraciuri/model-upload-guard/main/install.sh | MUG_REF=v0.2.2 bash
```

If `raw.githubusercontent.com/.../v0.2.2/install.sh` returns 404 right after a release, use the command above (`main` script + `MUG_REF` tag). Tag URLs usually catch up within a few minutes.

From a local clone:

```bash
git clone https://github.com/Amaraciuri/model-upload-guard.git
cd model-upload-guard
./install.sh
```

Requirements:

- Python 3.11+
- Linux, macOS, or Windows through WSL for the shell installer
- Docker or Podman only for `mug run`

The installer creates a dedicated virtual environment under `~/.local/share/model-upload-guard` and links `mug` into `~/.local/bin`. Re-running it upgrades in place (`pip install --upgrade`). No third-party runtime packages are required.

## Updating

Re-run the installer. It upgrades the existing venv.

**Latest release (pinned):**

```bash
curl -fsSL https://raw.githubusercontent.com/Amaraciuri/model-upload-guard/main/install.sh | MUG_REF=v0.2.2 bash
mug --version
mug doctor
```

**Always tracking `main`:**

```bash
curl -fsSL https://raw.githubusercontent.com/Amaraciuri/model-upload-guard/main/install.sh | bash
```

**From a local clone:**

```bash
cd model-upload-guard
git pull
./install.sh
```

Local recovery snapshots and workspace registry under `~/.local/state/model-upload-guard` are kept. `uninstall.sh` removes only the tool install, not those snapshots.

## What's new in 0.2.x

**Security (0.2.0)** — fail-closed defaults: immutable exclude/protected patterns, sealed workspace manifests, unscanned binary/large-file refusal, unified `mug diff` patches, `mug apply --dry-run`, dual-gated sandbox network, non-root sandbox user.

**Scanner (0.2.1)** — fewer false positives on lockfiles/checksums, clearer large-file tips, broader default excludes (IDE junk, audio, jars, …).

**Terminal UX (0.2.2)**

- `mug` / `mug menu` — interactive menu and quick start
- `mug guide` — print the safe workflow
- Progress bars on `scan` / `pack` / `workspace` (TTY only; disable with `MUG_NO_PROGRESS=1` or `CI=1`)
- Colorized findings/summary when the terminal supports it (`NO_COLOR=1` to disable)
- `--json` stays machine-readable (no progress noise)

## Five-minute usage

Inside a project:

```bash
mug                 # interactive menu + quick start
# or:
mug init
mug scan            # progress bar on TTY
mug pack . -o project-for-ai.zip
```

Prefer commands? `mug guide` prints the workflow; `mug --help` lists every subcommand.
The ZIP excludes `.git`, `.env*`, private keys, credential files, local databases, dependencies, build output, and other configured paths. Export stops when secret-like content is detected inside otherwise allowed source files.

For an AI coding agent:

```bash
mug workspace . -o ../project-ai-workspace
mug run ../project-ai-workspace -- sh
```

The container receives only the sanitized workspace. Defaults include:

- no network;
- read-only container root filesystem;
- only the sanitized workspace mounted writable;
- all Linux capabilities dropped;
- `no-new-privileges`;
- CPU, memory, process, and temporary-directory limits;
- no unsafe fallback to direct host execution.

After the agent finishes:

```bash
mug diff ../project-ai-workspace
mug apply ../project-ai-workspace --dry-run
mug apply ../project-ai-workspace --yes
```

Deletion is refused by default. To accept reviewed deletions:

```bash
mug apply ../project-ai-workspace --allow-delete --yes
```

Before applying, `mug` creates a private local recovery snapshot. Protected files such as `.git`, `.env`, keys, and credentials cannot be introduced or modified through the workspace.

## Commands

| Command | Purpose |
|---|---|
| `mug` / `mug menu` | Interactive menu and quick-start guide |
| `mug guide` | Print the typical safe workflow |
| `mug init` | Write a deny-by-default `.mug.toml` |
| `mug scan` | Find sensitive filenames and secret-like content |
| `mug pack` | Create a sanitized ZIP for browser/chat upload |
| `mug workspace` | Create a sanitized linked working copy |
| `mug run` | Run a command inside Docker/Podman isolation |
| `mug guard` | Preflight a command for obvious destructive patterns |
| `mug diff` | Show path changes plus unified patches |
| `mug apply` | Snapshot and apply a reviewed change set (`--dry-run` supported) |
| `mug snapshot` | Create a private local recovery archive |
| `mug snapshots` | List recovery archives for a project |
| `mug restore` | Restore an archive into a new empty directory |
| `mug doctor` | Check Python, configuration, and sandbox availability |

Machine-readable output is available through `--json` on the main inspection commands. Progress bars write to stderr and only appear on an interactive TTY.

## Configuration

Run `mug init`, then edit `.mug.toml`.

Security posture is fail-closed:

- immutable secret/credential patterns are always enforced and cannot be removed;
- `exclude` / `protected` keys only **add** patterns (a short list can no longer drop defaults);
- unscanned binary/large files block export by default;
- sandbox network requires both `sandbox.network = true` and `mug run --allow-network`.

```toml
[scan]
max_file_bytes = 1048576
fail_on = "high"
fail_on_unscanned = true
entropy_threshold = 4.5
entropy_min_length = 32

[export]
exclude_add = ["private/", "*.local.json"]
exclude_remove = []
allow_weaken_defaults = false

[apply]
max_changes = 200
max_delete_ratio = 0.05
protected_add = []
protected_remove = []

[sandbox]
engine = "auto"
image = "python:3.12-alpine"
network = false
memory = "2g"
cpus = "2"
pids_limit = 256
user = "65534:65534"
read_only_root = true
```

Project configuration merges over user-wide defaults stored at `~/.config/mug/config.toml`.

## Typical integrations

### Browser-based AI upload

```bash
mug scan
mug pack . -o safe-upload.zip
```

Upload only `safe-upload.zip`, never the original repository archive.

### Claude Code, Codex CLI, Gemini CLI, Grok Build, Cursor, or another terminal agent

Create the workspace first, then launch the tool through `mug run` using a container image that contains that agent. Do not mount your home directory, SSH directory, cloud configuration, Docker socket, or original repository into the container.

Example with a custom image:

```toml
[sandbox]
image = "my-company/coding-agent:latest"
network = false
```

```bash
mug run ../project-ai-workspace -- my-agent
```

Network is disabled by default. Enabling it is a dual-gated material security decision:

1. set `sandbox.network = true` in `.mug.toml`
2. pass `--allow-network` on `mug run`

### Pairing with Destructive Command Guard

Use both layers:

1. `mug` sanitizes uploads, isolates the working copy, reviews returned changes, and snapshots before apply.
2. A command hook such as `dcg` blocks known destructive shell, Git, database, cloud, container, and infrastructure commands before execution.

Neither layer makes arbitrary code safe. Together they reduce different failure modes.

## Threat model

### `mug` is designed to reduce

- accidental upload of common secret files;
- common hard-coded credentials and high-entropy secret-like blobs in text files;
- silent export of unscanned binary/large files;
- accidental weakening of exclude/protected defaults via short config lists;
- exposure of Git internals and unrelated home-directory content;
- direct writes from an agent to the original repository;
- workspace-manifest tampering during diff/apply (sealed local registry);
- accidental mass deletion in returned changes;
- modification of protected paths;
- irrecoverable apply operations without a local snapshot;
- obvious destructive commands launched through `mug run`;
- accidental sandbox network enablement without dual confirmation.

### `mug` does not guarantee protection from

- unknown secret formats or secrets carefully hidden to evade entropy/heuristics;
- malicious or vulnerable container images, kernels, runtimes, IDE extensions, browser extensions, or operating systems;
- a user manually mounting sensitive host paths or dual-confirming network access;
- an agent executed directly on the host outside `mug`;
- supply-chain attacks in dependencies installed inside or outside the sandbox;
- data already committed to Git history or already uploaded elsewhere;
- semantic backdoors that look like legitimate code changes;
- every possible destructive command or shell obfuscation.

Review diffs, use Git, protect credentials at the provider level, use short-lived tokens, and keep reliable backups.

## Safe defaults and escape hatches

Security controls are intentionally inconvenient to bypass:

- secret-like and unscanned findings block export unless `--allow-findings` is explicitly supplied;
- immutable exclude/protected patterns cannot be removed;
- apply requires `--yes` (use `--dry-run` first);
- deletions additionally require `--allow-delete`;
- high-volume changes and excessive deletion ratios require `--force`;
- protected-path changes cannot be forced;
- sandbox network requires config + `--allow-network`;
- missing Docker/Podman produces an error rather than direct host execution.

`--allow-findings`, `--force`, and `--allow-network` are audit signals, not proof of safety.

## Recovery

Create a snapshot manually:

```bash
mug snapshot .
mug snapshots .
```

Restore into a new empty directory:

```bash
mug restore ~/.local/state/model-upload-guard/snapshots/.../SNAPSHOT.tar.gz ../restored-copy --yes
```

Snapshots are local, include sensitive project files needed for recovery, and are stored with restrictive permissions where the operating system permits. Never upload snapshot archives to an AI service.

## Development

```bash
python -m unittest discover -s tests -v
python -m mug --version
```

The regression suite includes path normalization, fail-closed config merge, unscanned-binary refusal, manifest tamper detection, unified diffs, confirmation gates, deletion refusal, protected-path refusal, and pre-apply snapshot behavior.

## Roadmap

- signed release artifacts and checksum verification;
- native Windows PowerShell installer;
- richer allowlists for intentional test fixtures;
- OCI image profiles for popular coding agents;
- Git-aware patch export and three-way apply;
- optional integration adapters for agent hook systems;
- policy packs for WordPress, Firebase, Railway, cloud CLIs, and production databases;
- SBOM and reproducible releases.

## License

MIT. Free for personal and commercial use. Contributions and security reviews are welcome.
