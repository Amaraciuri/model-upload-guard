from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from .config import Config
from .utils import MugError
from .workspace import resolve_workspace


DANGEROUS_COMMANDS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:^|[;&|]\s*)rm\s+-[^\n]*r[^\n]*f[^\n]*(?:\s/|\s~(?:/|\s|$)|\s\.\.(?:/|\s|$))", re.I), "Recursive force deletion outside the workspace"),
    (re.compile(r"\bgit\s+reset\s+--hard\b", re.I), "git reset --hard can destroy uncommitted work"),
    (re.compile(r"\bgit\s+clean\s+-[^\s]*[fdx][^\s]*", re.I), "git clean can permanently delete untracked files"),
    (re.compile(r"\bgit\s+push\b[^\n]*(?:--force|-f)\b", re.I), "Forced push can rewrite remote history"),
    (re.compile(r"\b(?:drop\s+(?:database|table)|truncate\s+table)\b", re.I), "Destructive database operation"),
    (re.compile(r"\bdocker\s+system\s+prune\b[^\n]*-a", re.I), "Docker prune can remove unrelated data"),
    (re.compile(r"\bkubectl\s+delete\s+namespace\b", re.I), "Namespace deletion is destructive"),
    (re.compile(r"\bterraform\s+destroy\b", re.I), "Terraform destroy removes infrastructure"),
    (re.compile(r"\bmkfs(?:\.|\s)|\bdd\s+[^\n]*of=/dev/", re.I), "Disk formatting or raw device write"),
    (re.compile(r"\bchmod\s+-R\s+777\s+/", re.I), "Recursive permission change on filesystem root"),
    (re.compile(r"/var/run/docker\.sock|docker\.sock", re.I), "Docker socket access can escape the sandbox"),
    (re.compile(r"\bcurl\b[^\n]*\|\s*(?:ba)?sh\b", re.I), "Piping remote content into a shell"),
    (re.compile(r"\bwget\b[^\n]*\|\s*(?:ba)?sh\b", re.I), "Piping remote content into a shell"),
]


def inspect_command(command: str) -> list[str]:
    return [message for pattern, message in DANGEROUS_COMMANDS if pattern.search(command)]


def choose_engine(config: Config) -> str:
    requested = config.sandbox_engine.lower()
    if requested not in {"auto", "docker", "podman"}:
        raise MugError("sandbox.engine must be auto, docker, or podman")
    if requested in {"docker", "podman"}:
        if not shutil.which(requested):
            raise MugError(f"Sandbox engine not found: {requested}")
        return requested
    for engine in ("podman", "docker"):
        if shutil.which(engine):
            return engine
    raise MugError("No Docker or Podman installation found. MUG refuses an unsafe host fallback.")


def run_sandbox(
    workspace: Path,
    command: list[str],
    config: Config,
    interactive: bool = False,
    *,
    allow_network: bool = False,
) -> int:
    if not command:
        raise MugError("No command supplied after --")
    _, workspace, _ = resolve_workspace(workspace)
    command_text = " ".join(command)
    reasons = inspect_command(command_text)
    if reasons:
        raise MugError("Command blocked before sandbox launch: " + "; ".join(reasons))

    # Dual gate: config opt-in AND explicit CLI flag. Network is off by default.
    network_enabled = False
    if allow_network:
        if not config.sandbox_network:
            raise MugError(
                "Refusing --allow-network because sandbox.network is false. "
                "Enabling network is a material security decision: set sandbox.network = true in .mug.toml "
                "and pass --allow-network."
            )
        network_enabled = True
    elif config.sandbox_network:
        raise MugError(
            "sandbox.network = true requires an explicit --allow-network flag on `mug run` "
            "(dual confirmation for exfiltration risk)."
        )

    engine = choose_engine(config)
    args = [
        engine,
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={config.sandbox_pids_limit}",
        f"--memory={config.sandbox_memory}",
        f"--cpus={config.sandbox_cpus}",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=512m",
        "--mount",
        f"type=bind,src={workspace},dst=/workspace,rw",
        "--workdir=/workspace",
    ]
    if config.sandbox_read_only_root:
        args.append("--read-only")
    if config.sandbox_user:
        args.extend(["--user", config.sandbox_user])
    if network_enabled:
        # Still no host network aliasing; use default bridge only when dual-gated.
        pass
    else:
        args.extend(["--network=none"])
    if interactive:
        args.append("-it")
    args.append(config.sandbox_image)
    args.extend(command)
    completed = subprocess.run(args, check=False)
    return completed.returncode
