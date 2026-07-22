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


def clear_screen() -> None:
    """Clear the terminal when interactive (disable with MUG_NO_CLEAR=1)."""
    if os.environ.get("MUG_NO_CLEAR") or os.environ.get("CI"):
        return
    if not getattr(sys.stdout, "isatty", lambda: False)():
        return
    sys.stdout.write("\033[H\033[2J")
    sys.stdout.flush()


def wizard_header(title: str, step: int | None = None, total: int | None = None) -> None:
    width = min(72, shutil.get_terminal_size((72, 20)).columns)
    if step is not None and total is not None:
        label = f" {title}  ·  step {step}/{total} "
    else:
        label = f" {title} "
    print()
    print(c("─" * width, DIM, ACCENT))
    print(c(label, BOLD, ACCENT))
    print(c("─" * width, DIM, ACCENT))
    print()


def print_change_preview(changes: list[object], *, max_deletes: int = 40) -> None:
    """Pretty-print a short apply preview (used by the interactive menu)."""
    from .apply import Change

    typed = [item for item in changes if isinstance(item, Change)]
    if not typed:
        info("No changes in this workspace.")
        return
    counts = {"modify": 0, "add": 0, "delete": 0, "blocked": 0}
    for change in typed:
        counts[change.action] = counts.get(change.action, 0) + 1
    print(
        f"  {c('modify', GREEN)}={counts.get('modify', 0)}  "
        f"{c('add', CYAN)}={counts.get('add', 0)}  "
        f"{c('delete', YELLOW)}={counts.get('delete', 0)}  "
        f"{c('blocked', RED)}={counts.get('blocked', 0)}"
    )
    deletes = [change for change in typed if change.action == "delete"]
    if deletes:
        print()
        print(c("  Deletes (review carefully):", BOLD, YELLOW))
        for change in deletes[:max_deletes]:
            print(f"    {c('DELETE', YELLOW, BOLD)}  {change.path}")
        if len(deletes) > max_deletes:
            print(c(f"    … and {len(deletes) - max_deletes} more", DIM))
    blocked = [change for change in typed if change.action == "blocked"]
    if blocked:
        print()
        print(c("  Blocked / protected:", BOLD, RED))
        for change in blocked[:15]:
            print(f"    {c('BLOCKED', RED, BOLD)}  {change.path}  {c(change.reason, DIM)}")
        if len(blocked) > 15:
            print(c(f"    … and {len(blocked) - 15} more", DIM))
    print()


def print_agents_help() -> None:
    print(c("Agent rules template", BOLD, ACCENT))
    print()
    print("  Drop AGENTS.md (or paste into Cursor / Claude Code rules) so the agent:")
    print("  • only edits the mug workspace")
    print("  • never touches .env / .git / secrets")
    print("  • tells you to run mug diff → apply --dry-run → apply --yes")
    print()
    print(c("  Also see:", DIM), "docs/agent-workflow.md · examples/AGENTS.md")
    print()


def render_home(version: str, *, cwd: Path | None = None, compact: bool = False) -> None:
    """VEXP-style home: big logo (or compact bar), tagline, live status."""
    cwd = cwd or Path.cwd()
    if compact:
        width = min(72, shutil.get_terminal_size((72, 20)).columns)
        print(c("─" * width, DIM, ACCENT))
        print(c(f"  mug v{version}", BOLD, ACCENT), c("· Model Upload Guard", DIM))
        _print_status(cwd)
        print(c("─" * width, DIM, ACCENT))
        print()
        return
    for line in LOGO_MUG.splitlines():
        print(c(line, BOLD, ACCENT), end="")
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
    MenuItem("a", "Agent rules", "Copy AGENTS.md template for coding agents", "agents", "Learn"),
    MenuItem("3", "Doctor", "Python, config, sandbox posture", "doctor", "Setup"),
    MenuItem("s", "Status", "Install, state dir, last runs", "status", "Setup"),
    MenuItem("4", "Init", "Create deny-by-default .mug.toml", "init", "Setup"),
    MenuItem("u", "Update", "Update mug from GitHub (SHA256)", "update", "Setup"),
    MenuItem("5", "Scan", "Secrets & sensitive files here", "scan", "Export"),
    MenuItem("6", "Pack", "Sanitized ZIP for chat / browser AI", "pack", "Export"),
    MenuItem("7", "Workspace", "Sanitized copy for coding agents", "workspace", "Agent"),
    MenuItem("8", "Diff", "Review workspace changes + patches", "diff", "Agent"),
    MenuItem("9", "Apply", "Preview deletes → snapshot → apply", "apply", "Agent"),
    MenuItem("r", "Recovery", "List / restore local snapshots", "recovery", "Agent"),
    MenuItem("q", "Quit", "Leave the menu anytime", "exit", ""),
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
    print(
        c("Apply limits:", BOLD),
        "max_changes / max_delete_ratio / protected_add live in .mug.toml [apply]; "
        "menu only asks about deletions — it does not raise thresholds. "
        "--force skips volume/git checks only, never protected paths.",
    )
    print(
        c("Agents:", BOLD),
        "copy examples/AGENTS.md (or menu → Agent rules) into the workspace so the model stays fail-closed.",
    )
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
        ("mug status", "Install / state / last runs"),
        ("mug scan --update-baseline", "Accept reviewed findings individually"),
        ("mug update [--check]", "Self-update from GitHub (SHA256)"),
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
    print("  • Apply thresholds: .mug.toml [apply] max_changes / max_delete_ratio / protected_add")
    print("  • Team rules: [[scan.rules_add]] + scan.allowlist_paths in .mug.toml")
    print("  • Agents: examples/AGENTS.md (or mug menu → Agent rules)")
    print("  • --force: volume + git only — protected paths stay blocked")
    print("  • Quiet progress: MUG_NO_PROGRESS=1 or CI=1")
    print("  • Disable color: NO_COLOR=1 · keep menu chalk: MUG_NO_CLEAR=1")
    print()


BACK_TOKENS = frozenset({"b", "back", "-"})
QUIT_TOKENS = frozenset({"q", "quit", "exit"})


class MenuNav(Exception):
    """Raised from interactive prompts to leave a wizard step."""

    def __init__(self, kind: str) -> None:
        if kind not in {"back", "quit"}:
            raise ValueError(f"unknown MenuNav kind: {kind}")
        self.kind = kind
        super().__init__(kind)


def _nav_from_raw(raw: str) -> None:
    lowered = raw.strip().lower()
    if lowered in BACK_TOKENS:
        raise MenuNav("back")
    if lowered in QUIT_TOKENS:
        raise MenuNav("quit")


def prompt(
    message: str,
    default: str | None = None,
    *,
    allow_nav: bool = True,
    required: bool = False,
) -> str:
    """Ask for text. With allow_nav: b/back = menu, q = quit, empty without default = back."""
    if allow_nav:
        if default is not None:
            nav = " · b=back · q=quit"
            suffix = f" [{default}]{nav}"
        else:
            suffix = " [b=back · q=quit]"
    else:
        suffix = f" [{default}]" if default is not None else ""
    try:
        raw = input(f"{c('?', ACCENT, BOLD)} {message}{suffix}: ").strip()
    except EOFError:
        if allow_nav:
            raise MenuNav("back") from None
        return default or ""
    if allow_nav:
        if not raw:
            if default is not None:
                return default
            raise MenuNav("back")
        _nav_from_raw(raw)
    elif not raw and default is not None:
        return default
    if required and not raw:
        raise MenuNav("back")
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


def confirm(message: str, default: bool = False, *, allow_nav: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    nav = " · b=back" if allow_nav else ""
    answer = prompt(f"{message} ({hint}{nav})", "", allow_nav=False).strip().lower()
    if allow_nav:
        if not answer:
            return default
        if answer in BACK_TOKENS:
            raise MenuNav("back")
        if answer in QUIT_TOKENS:
            raise MenuNav("quit")
    if not answer:
        return default
    return answer in {"y", "yes"}


def wait_return() -> None:
    """Pause after an action so output is readable before redrawing the menu."""
    print()
    try:
        raw = input(
            f"{c('↵', ACCENT, BOLD)} {c('Back to menu', BOLD)} "
            f"{c('(Enter) · q=quit', DIM)} "
        ).strip().lower()
    except EOFError:
        return
    if raw in QUIT_TOKENS:
        raise MenuNav("quit")
    if raw in BACK_TOKENS or raw == "" or raw in {"menu", "m"}:
        return


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
    print(
        f"  {c('nav', DIM)}  "
        f"{c('1–9 / a / s / r / u', BOLD)}=run  ·  "
        f"{c('Enter', BOLD)}/{c('b', BOLD)}=refresh  ·  "
        f"{c('q', BOLD, RED)}/{c('0', BOLD, RED)}=quit  ·  "
        f"in prompts: {c('b', BOLD)}=back"
    )
    print()


def read_menu_choice() -> str | None:
    raw = mug_prompt().strip().lower()
    if raw in QUIT_TOKENS or raw == "0":
        return "exit"
    if raw in BACK_TOKENS or raw in {"menu", "m", ""}:
        return "home"
    for item in MENU_ITEMS:
        if raw == item.key or raw == item.action or raw == item.title.lower():
            return item.action
    return None
