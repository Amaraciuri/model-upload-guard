"""Terminal UI helpers (stdlib only): colors, progress, interactive menu."""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TextIO


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
BLUE = "34"
MAGENTA = "35"
CYAN = "36"
WHITE = "37"

# Soft cyan / teal vibe similar to polished CLIs.
ACCENT = CYAN


LOGO_MUG = r"""
 ███╗   ███╗██╗   ██╗ ██████╗
 ████╗ ████║██║   ██║██╔════╝
 ██╔████╔██║██║   ██║██║  ███╗
 ██║╚██╔╝██║██║   ██║██║   ██║
 ██║ ╚═╝ ██║╚██████╔╝╚██████╔╝
 ╚═╝     ╚═╝ ╚═════╝  ╚═════╝
""".strip("\n")


def banner(version: str) -> None:
    """Legacy thin banner (used by non-menu commands)."""
    width = min(72, shutil.get_terminal_size((72, 20)).columns)
    title = f" Model Upload Guard  v{version} "
    line = "═" * width
    print(c(line, DIM, ACCENT))
    print(c(title.center(width, "─"), BOLD, ACCENT))
    print(c(" Protect what leaves your machine. Review what comes back. ".center(width), DIM))
    print(c(line, DIM, ACCENT))
    print()


def render_home(version: str, *, cwd: Path | None = None) -> None:
    """VEXP-style home: big logo, tagline, live status, then menu is separate."""
    cwd = cwd or Path.cwd()
    for line in LOGO_MUG.splitlines():
        print(c(line, BOLD, ACCENT), end="")
        # Put version on the middle logo row for a compact header.
        if "██╔████╔██║" in line:
            print(f"  {c(f'v{version}', DIM)}")
        else:
            print()
    print()
    print(c("  Model Upload Guard", BOLD, WHITE if _want_color() else BOLD))
    print(c("  Safety boundary for sharing code with AI agents", DIM))
    print()
    _print_status(cwd)
    print()


def _dot(ok_state: bool) -> str:
    return c("●", GREEN if ok_state else YELLOW, BOLD)


def _print_status(cwd: Path) -> None:
    config_path = cwd / ".mug.toml"
    has_config = config_path.is_file()
    docker = bool(shutil.which("docker"))
    podman = bool(shutil.which("podman"))
    sandbox_ok = docker or podman
    if podman and docker:
        sandbox_label = "podman + docker"
    elif podman:
        sandbox_label = "podman"
    elif docker:
        sandbox_label = "docker"
    else:
        sandbox_label = "missing (mug run unavailable)"

    try:
        short_cwd = str(cwd)
        home = str(Path.home())
        if short_cwd.startswith(home):
            short_cwd = "~" + short_cwd[len(home) :]
    except Exception:
        short_cwd = str(cwd)

    print(f"  {_dot(True)} {c('cwd', DIM)}     {c(short_cwd, BOLD)}")
    print(
        f"  {_dot(has_config)} {c('config', DIM)}  "
        + (c(".mug.toml", GREEN) if has_config else c("defaults (run Init)", DIM))
    )
    print(
        f"  {_dot(sandbox_ok)} {c('sandbox', DIM)} "
        + (c(sandbox_label, GREEN) if sandbox_ok else c(sandbox_label, YELLOW))
    )


def info(msg: str) -> None:
    print(f"{c('›', ACCENT, BOLD)} {msg}")


def ok(msg: str) -> None:
    print(f"{c('✓', GREEN, BOLD)} {msg}")


def warn(msg: str) -> None:
    print(f"{c('!', YELLOW, BOLD)} {msg}", file=sys.stderr)


def err(msg: str) -> None:
    print(f"{c('✗', RED, BOLD)} {msg}", file=sys.stderr)


class ProgressBar:
    """Single-line stderr progress bar. Silent when not a TTY or MUG_NO_PROGRESS=1."""

    def __init__(self, label: str, stream: TextIO | None = None) -> None:
        self.label = label
        self.stream: TextIO = stream if stream is not None else sys.stderr
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
        colored = c(bar, ACCENT, stream=self.stream) if _want_color(self.stream) else bar
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
    group: str = ""


MENU_ITEMS: tuple[MenuItem, ...] = (
    MenuItem("1", "Quick start", "2-minute guide to the safe workflow", "guide", "Learn"),
    MenuItem("2", "Cheat sheet", "Every command with examples", "cheatsheet", "Learn"),
    MenuItem("3", "Doctor", "Python, config, sandbox posture", "doctor", "Setup"),
    MenuItem("4", "Init", "Create deny-by-default .mug.toml", "init", "Setup"),
    MenuItem("u", "Update", "Update mug from GitHub", "update", "Setup"),
    MenuItem("5", "Scan", "Secrets & sensitive files here", "scan", "Export"),
    MenuItem("6", "Pack", "Sanitized ZIP for chat / browser AI", "pack", "Export"),
    MenuItem("7", "Workspace", "Sanitized copy for coding agents", "workspace", "Agent"),
    MenuItem("8", "Diff", "Review workspace changes + patches", "diff", "Agent"),
    MenuItem("9", "Apply", "Snapshot + apply after review", "apply", "Agent"),
    MenuItem("q", "Exit", "Leave the menu", "exit", ""),
)


def print_guide() -> None:
    print(c("Typical safe workflow", BOLD, ACCENT))
    print()
    steps = [
        ("mug init", "Write local deny-by-default config (.mug.toml)"),
        ("mug scan", "See what would be blocked before anything leaves"),
        ("mug scan --update-baseline", "Accept individually reviewed false positives"),
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
        ("mug scan --update-baseline", "Accept reviewed findings individually"),
        ("mug update [--check]", "Self-update from GitHub"),
        ("mug snapshot / snapshots / restore", "Private recovery archives"),
    ]
    print(c("Command cheat sheet", BOLD, ACCENT))
    print()
    width = max(len(cmd) for cmd, _ in rows)
    for cmd, desc in rows:
        print(f"  {c(cmd.ljust(width), BOLD, GREEN)}  {c(desc, DIM)}")
    print()
    print(c("Tips", BOLD, YELLOW))
    print("  • JSON output: add --json to scan/pack/workspace/diff/apply/doctor")
    print("  • Quiet progress: MUG_NO_PROGRESS=1 or CI=1")
    print("  • Disable color: NO_COLOR=1")
    print()


def prompt(message: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try:
        raw = input(f"{c('?', ACCENT, BOLD)} {message}{suffix}: ").strip()
    except EOFError:
        return default or ""
    if not raw and default is not None:
        return default
    return raw


def mug_prompt(default: str | None = None) -> str:
    """Primary menu prompt, styled like `vexp>`."""
    suffix = f" [{default}]" if default is not None else ""
    try:
        raw = input(f"{c('mug>', ACCENT, BOLD)}{c(suffix, DIM)} ").strip()
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
    print(c("  What do you want to do?", BOLD))
    print()
    current_group = object()
    title_width = max(len(item.title) for item in MENU_ITEMS)
    for item in MENU_ITEMS:
        if item.group and item.group != current_group:
            current_group = item.group
            print(f"  {c(item.group.upper(), DIM)}")
        if item.action == "exit":
            print()
            print(
                f"  {c(item.key, BOLD, RED)}) "
                f"{c(item.title.ljust(title_width), BOLD, RED)}  "
                f"{c(item.blurb, DIM)}"
            )
            continue
        print(
            f"  {c(item.key, BOLD, ACCENT)}) "
            f"{c(item.title.ljust(title_width), BOLD)}  "
            f"{c(item.blurb, DIM)}"
        )
    print()


def read_menu_choice() -> str | None:
    raw = mug_prompt("1").strip().lower()
    if raw in {"q", "quit", "exit", "0"}:
        return "exit"
    for item in MENU_ITEMS:
        if raw == item.key or raw == item.action or raw == item.title.lower():
            return item.action
    return None
