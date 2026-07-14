"""Git-awareness helpers for workspace create / apply."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .utils import MugError


def git_available() -> bool:
    return bool(shutil.which("git"))


def is_git_repo(root: Path) -> bool:
    return (root / ".git").exists() and git_available()


def git_rev_parse(root: Path) -> str | None:
    if not is_git_repo(root):
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip() or None


def git_status_porcelain(root: Path) -> list[str]:
    if not is_git_repo(root):
        return []
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    return [line for line in (proc.stdout or "").splitlines() if line.strip()]


def assert_apply_git_safe(root: Path, sealed_head: str | None, *, force: bool) -> list[str]:
    """Return warnings, or raise if apply is unsafe without --force."""
    warnings: list[str] = []
    if not is_git_repo(root):
        return warnings
    current = git_rev_parse(root)
    if sealed_head and current and sealed_head != current:
        msg = (
            f"Git HEAD moved since workspace creation "
            f"(was {sealed_head[:12]}, now {current[:12]}). "
            "Re-create the workspace or merge carefully before apply."
        )
        if force:
            warnings.append(msg)
        else:
            raise MugError(msg + " Pass --force only after reviewing `mug diff` and `git status`.")
    dirty = git_status_porcelain(root)
    if dirty:
        sample = ", ".join(line[3:] if len(line) > 3 else line for line in dirty[:5])
        suffix = "..." if len(dirty) > 5 else ""
        msg = (
            f"Original repository has uncommitted changes ({len(dirty)} path(s): {sample}{suffix}). "
            "Commit or stash before apply to avoid mixing agent and human edits."
        )
        if force:
            warnings.append(msg)
        else:
            raise MugError(msg + " Pass --force to override.")
    return warnings
