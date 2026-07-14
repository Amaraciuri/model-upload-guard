"""Terminal UI helpers (stdlib only): colors, progress, interactive menu."""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from typing import Callable


def _want_color(stream: object | None = None) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    target = stream if stream is not None else sys.stdout
    return bool(getattr(target, "isatty", lambda: False)())


def c(text: str, *codes: str, stream: object | None = None) -> str:
    if not codes or not _want_color(stream):
        return text
    return f"\033[{';'.join(codes)}m{text}\033[0m"


BOLD = "1"
DIM = "2"
RED = "31"
GREEN = "32"
YELLOW = "33"
CYAN = "36"


def banner(version: str) -> None:
    width = min(72, shutil.get_terminal_size((72, 20)).columns)
    title = f" Model Upload Guard  v{version} "
    line = "═" * width
    print(c(line, DIM, CYAN))
    print(c(title.center(width, "─"), BOLD, CYAN))
    print(c(" Protect what leaves your machine. Review what comes back. ".center(width), DIM))
    print(c(line, DIM, CYAN))
    print()


def info(msg: str) -> None:
    print(f"{c('›', CYAN, BOLD)} {msg}")


def ok(msg: str) -> None:
    print(f"{c('✓', GREEN, BOLD)} {msg}")


def warn(msg: str) -> None:
    print(f"{c('!', YELLOW, BOLD)} {msg}", file=sys.stderr)


def err(msg: str) -> None:
    print(f"{c('✗', RED, BOLD)} {msg}", file=sys.stderr)


class ProgressBar:
    """Single-line stderr progress bar. Silent when not a TTY or MUG_NO_PROGRESS=1."""

    def __init__(self, label: str, stream: object | None = None) -> None:
        self.label = label
        self.stream = stream if stream is not None else sys.stderr
        self.enabled = (
            bool(getattr(self.stream, "isatty", lambda: False)())
            and not os.environ.get("MUG_NO_PROGRESS")
            and not os.environ.get("CI")
        )
        self._width = 24

    def update(self, current: int, total: int, detail: str = "") -> None:
        if not self.enabled:
            return
        total = max(total, 0)
        current = max(0, min(current, total if total else current))
        pct = 100 if total == 0 else int(100 * current / total)
        filled = 0 if total == 0 else int(self._width * current / total)
        bar = "█" * filled + "░" * (self._width - filled)
        name = detail.replace("\n", " ")
        if len(name) > 36:
            name = "…" + name[-35:]
        colored = c(bar, CYAN, stream=self.stream) if _want_color(self.stream) else bar
        line = f"\r{self.label:<10} [{colored}] {pct:3d}% {current}/{total or '?'}  {name}"
        self.stream.write(line + "\033[K")
        self.stream.flush()

    def finish(self, message: str = "") -> None:
        if not self.enabled:
            if message:
                print(message, file=self.stream)
            return
        self.stream.write("\r\033[K")
        if message:
            self.stream.write(message + "\n")
        self.stream.flush()


ProgressCb = Callable[[int, int, str], None]


def make_progress(label: str, quiet: bool = False) -> tuple[ProgressBar | None, ProgressCb | None]:
    if quiet:
        return None, None
    bar = ProgressBar(label)

    def cb(current: int, total: int, detail: str = "") -> None:
        bar.update(current, total, detail)

    return bar, cb


@dataclass(frozen=True)
class MenuItem:
    key: str
    title: str
    blurb: str
    action: str


MENU_ITEMS: tuple[MenuItem, ...] = (
    MenuItem("1", "Quick start", "How mug protects your repo (2-minute guide)", "guide"),
    MenuItem("2", "Doctor", "Check Python, config, and sandbox readiness", "doctor"),
    MenuItem("3", "Init", "Create deny-by-default .mug.toml here", "init"),
    MenuItem("4", "Scan", "Find secrets / sensitive files in this project", "scan"),
    MenuItem("5", "Pack", "Build a sanitized ZIP for chat/browser upload", "pack"),
    MenuItem("6", "Workspace", "Create a sanitized copy for an AI coding agent", "workspace"),
    MenuItem("7", "Diff", "Review changes in an AI workspace", "diff"),
    MenuItem("8", "Apply", "Apply reviewed workspace changes (with snapshot)", "apply"),
    MenuItem("9", "Command cheat sheet", "Print every mug command with examples", "cheatsheet"),
    MenuItem("0", "Exit", "Leave the menu", "exit"),
)


def print_guide() -> None:
    print(c("Typical safe workflow", BOLD, CYAN))
    print()
    steps = [
        ("mug init", "Write local deny-by-default config (.mug.toml)"),
        ("mug scan", "See what would be blocked before anything leaves"),
        ("mug pack -o out.zip", "Sanitized ZIP for ChatGPT / Claude / browser tools"),
        ("mug workspace -o ../proj-ai", "Sanitized working copy for coding agents"),
        ("mug run ../proj-ai -- …", "Optional: run agent in Docker/Podman, no network"),
        ("mug diff ../proj-ai", "Review every add/modify/delete + patches"),
        ("mug apply ../proj-ai --dry-run", "Preview apply without writing"),
        ("mug apply ../proj-ai --yes", "Snapshot + apply only after you confirm"),
    ]
    for i, (cmd, why) in enumerate(steps, 1):
        print(f"  {c(str(i) + '.', DIM)} {c(cmd, BOLD, GREEN)}")
        print(f"     {c(why, DIM)}")
    print()
    print(c("Rule of thumb:", BOLD, YELLOW), "never point an agent at your real .git / .env.")
    print(c("Recovery:", BOLD), "mug snapshot · mug snapshots · mug restore <archive> <dir> --yes")
    print()


def print_cheatsheet() -> None:
    rows = [
        ("mug", "Open this interactive menu"),
        ("mug menu", "Same as above"),
        ("mug init", "Create .mug.toml"),
        ("mug scan [path]", "Secret / sensitive scan"),
        ("mug pack [path] -o out.zip", "Sanitized ZIP"),
        ("mug workspace [path] -o ../ws", "Sanitized agent workspace"),
        ("mug diff <workspace>", "Review changes + patches"),
        ("mug apply <ws> --dry-run", "Preview apply"),
        ("mug apply <ws> --yes", "Apply with confirmation"),
        ("mug run <ws> -- cmd…", "Sandbox run (Docker/Podman)"),
        ("mug guard -- <cmd>", "Destructive-command preflight"),
        ("mug doctor", "Local posture check"),
        ("mug snapshot / snapshots / restore", "Private recovery archives"),
    ]
    print(c("Command cheat sheet", BOLD, CYAN))
    print()
    width = max(len(cmd) for cmd, _ in rows)
    for cmd, desc in rows:
        print(f"  {c(cmd.ljust(width), BOLD, GREEN)}  {desc}")
    print()
    print(c("Tips", BOLD, YELLOW))
    print("  • JSON output: add --json to scan/pack/workspace/diff/apply/doctor")
    print("  • Quiet progress: MUG_NO_PROGRESS=1 or CI=1")
    print("  • Disable color: NO_COLOR=1")
    print()


def prompt(message: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try:
        raw = input(f"{c('?', CYAN, BOLD)} {message}{suffix}: ").strip()
    except EOFError:
        return default or ""
    if not raw and default is not None:
        return default
    return raw


def confirm(message: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    answer = prompt(f"{message} ({hint})", "").lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def render_menu() -> None:
    print(c("What do you want to do?", BOLD))
    print()
    for item in MENU_ITEMS:
        print(f"  {c(item.key, BOLD, CYAN)}) {c(item.title, BOLD)}  {c('— ' + item.blurb, DIM)}")
    print()


def read_menu_choice() -> str | None:
    raw = prompt("Choose", "1").strip().lower()
    if raw in {"q", "quit", "exit"}:
        return "exit"
    for item in MENU_ITEMS:
        if raw == item.key or raw == item.action or raw == item.title.lower():
            return item.action
    return None
