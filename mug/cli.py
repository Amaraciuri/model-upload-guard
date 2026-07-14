from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

from . import __version__
from .apply import apply_changes, compute_changes
from .config import DEFAULT_CONFIG_TEXT, IMMUTABLE_EXCLUDES, load_config
from .sandbox import inspect_command, run_sandbox
from .scanner import blocks_export, scan_tree
from .snapshot import create_snapshot, list_snapshots, restore_snapshot
from .ui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    RED,
    YELLOW,
    banner,
    c,
    confirm,
    err,
    info,
    make_progress,
    ok,
    print_cheatsheet,
    print_guide,
    prompt,
    read_menu_choice,
    render_home,
    render_menu,
    warn,
)
from .utils import MugError, canonical_root
from .workspace import create_pack, create_workspace


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="mug",
        description="Protect code before sharing it with an AI model and apply returned changes safely.",
        epilog="Run `mug` or `mug menu` with no args for an interactive guide.",
    )
    root.add_argument("--version", action="version", version=f"mug {__version__}")
    sub = root.add_subparsers(dest="command", required=False)

    sub.add_parser("menu", help="Interactive menu and quick-start guide")
    sub.add_parser("guide", help="Print the typical safe workflow")

    init = sub.add_parser("init", help="Create a deny-by-default .mug.toml")
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--force", action="store_true")

    scan = sub.add_parser("scan", help="Find sensitive files and secret-like content")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--json", action="store_true")

    pack = sub.add_parser("pack", help="Create a sanitized ZIP safe to upload for review")
    pack.add_argument("path", nargs="?", default=".")
    pack.add_argument("-o", "--output")
    pack.add_argument("--allow-findings", action="store_true")
    pack.add_argument("--json", action="store_true")

    workspace = sub.add_parser("workspace", help="Create a sanitized working copy for an AI coding agent")
    workspace.add_argument("path", nargs="?", default=".")
    workspace.add_argument("-o", "--output")
    workspace.add_argument("--allow-findings", action="store_true")
    workspace.add_argument("--json", action="store_true")

    diff = sub.add_parser("diff", help="Review files added, modified, or deleted in a workspace")
    diff.add_argument("workspace")
    diff.add_argument("--json", action="store_true")
    diff.add_argument("--no-patch", action="store_true", help="Show only path-level changes")

    apply = sub.add_parser("apply", help="Apply reviewed workspace changes to the original repository")
    apply.add_argument("workspace")
    apply.add_argument("--yes", action="store_true", help="Required confirmation")
    apply.add_argument("--allow-delete", action="store_true")
    apply.add_argument("--force", action="store_true", help="Override change/deletion thresholds")
    apply.add_argument("--dry-run", action="store_true", help="Show the apply plan without writing")
    apply.add_argument("--json", action="store_true")

    snapshot = sub.add_parser("snapshot", help="Create a private local recovery snapshot")
    snapshot.add_argument("path", nargs="?", default=".")

    snapshots = sub.add_parser("snapshots", help="List private local recovery snapshots")
    snapshots.add_argument("path", nargs="?", default=".")

    restore = sub.add_parser("restore", help="Restore a snapshot into a new empty directory")
    restore.add_argument("archive")
    restore.add_argument("target")
    restore.add_argument("--yes", action="store_true")

    guard = sub.add_parser("guard", help="Check a command for obvious destructive operations")
    guard.add_argument("command_text", nargs=argparse.REMAINDER)
    guard.add_argument("--json", action="store_true")

    run = sub.add_parser("run", help="Run an agent or command inside a locked-down container")
    run.add_argument("workspace")
    run.add_argument("--interactive", "-i", action="store_true")
    run.add_argument(
        "--allow-network",
        action="store_true",
        help="Dual gate with sandbox.network=true; disabled by default",
    )
    run.add_argument("agent_command", nargs=argparse.REMAINDER)

    doctor = sub.add_parser("doctor", help="Check local prerequisites and safety posture")
    doctor.add_argument("path", nargs="?", default=".")
    doctor.add_argument("--json", action="store_true")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if not args.command:
            if sys.stdin.isatty() and sys.stdout.isatty():
                return run_menu()
            parser().print_help()
            return 0
        return dispatch(args)
    except MugError as exc:
        err(str(exc))
        return 2
    except KeyboardInterrupt:
        print()
        warn("interrupted")
        return 130


def dispatch(args: argparse.Namespace) -> int:
    command = args.command
    if command in {"menu"}:
        return run_menu()
    if command == "guide":
        banner(__version__)
        print_guide()
        return 0

    if command == "init":
        root = canonical_root(args.path)
        destination = root / ".mug.toml"
        if destination.exists() and not args.force:
            raise MugError(f"Configuration already exists: {destination}")
        destination.write_text(DEFAULT_CONFIG_TEXT, encoding="utf-8")
        ok(f"Wrote {destination}")
        info("Next: mug scan   then   mug pack -o project-for-ai.zip")
        return 0

    if command == "scan":
        root = canonical_root(args.path)
        config = load_config(root)
        quiet = bool(getattr(args, "json", False))
        bar, progress = make_progress("Scanning", quiet=quiet)
        findings = scan_tree(root, config, on_progress=progress)
        if bar is not None:
            bar.finish(c(f"✓ scanned {root.name}", GREEN) if not quiet else "")
        if args.json:
            print(json.dumps([item.to_dict() for item in findings], indent=2))
        else:
            _print_findings(findings)
        return 1 if blocks_export(findings, config.fail_on, config.fail_on_unscanned) else 0

    if command == "pack":
        root = canonical_root(args.path)
        config = load_config(root)
        output = Path(args.output or f"{root.name}-sanitized.zip")
        quiet = bool(getattr(args, "json", False))
        bar, progress = make_progress("Packing", quiet=quiet)
        result = create_pack(root, output, config, args.allow_findings, on_progress=progress)
        if bar is not None:
            bar.finish(c(f"✓ packed {result['files']} files → {result['output']}", GREEN) if not quiet else "")
        _print_result(result, args.json)
        return 0

    if command == "workspace":
        root = canonical_root(args.path)
        config = load_config(root)
        output = Path(args.output or f"{root.parent / (root.name + '-ai-workspace')}")
        quiet = bool(getattr(args, "json", False))
        bar, progress = make_progress("Workspace", quiet=quiet)
        result = create_workspace(root, output, config, args.allow_findings, on_progress=progress)
        if bar is not None:
            bar.finish(
                c(f"✓ workspace ready → {result['workspace']}", GREEN) if not quiet else ""
            )
        _print_result(result, args.json)
        return 0

    if command == "diff":
        workspace = Path(args.workspace)
        original, changes, _ = compute_changes(
            workspace,
            load_config(_workspace_original(workspace)),
            include_patches=not args.no_patch,
        )
        payload = {
            "original": str(original),
            "changes": [change.to_dict() for change in changes],
            "count": len(changes),
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"Original: {original}")
            if not changes:
                ok("No changes.")
            for change in changes:
                color = RED if change.action == "blocked" else (YELLOW if change.action == "delete" else GREEN)
                label = f"{change.action.upper():8}"
                print(f"{c(label, color, BOLD)} {change.path}  {change.reason}")
                if change.patch and not args.no_patch:
                    print(change.patch.rstrip())
                    print()
        return 1 if any(change.action == "blocked" for change in changes) else 0

    if command == "apply":
        workspace = Path(args.workspace)
        original = _workspace_original(workspace)
        config = load_config(original)
        result = apply_changes(
            workspace,
            config,
            yes=args.yes,
            allow_delete=args.allow_delete,
            force=args.force,
            dry_run=args.dry_run,
        )
        _print_result(result, args.json)
        return 0

    if command == "snapshot":
        archive = create_snapshot(canonical_root(args.path))
        ok(f"Snapshot: {archive}")
        return 0

    if command == "snapshots":
        root = canonical_root(args.path)
        archives = list_snapshots(root)
        if not archives:
            info("No snapshots yet. Create one with: mug snapshot")
            return 0
        for archive in archives:
            print(archive)
        return 0

    if command == "restore":
        if not args.yes:
            raise MugError("Restore is confirmation-gated. Re-run with --yes.")
        restore_snapshot(Path(args.archive), Path(args.target))
        ok(str(Path(args.target).expanduser().resolve()))
        return 0

    if command == "guard":
        text = " ".join(args.command_text).strip()
        if text.startswith("-- "):
            text = text[3:]
        reasons = inspect_command(text)
        payload = {"allowed": not reasons, "reasons": reasons, "command": text}
        if args.json:
            print(json.dumps(payload, indent=2))
        elif reasons:
            print(c("BLOCKED", RED, BOLD))
            for reason in reasons:
                print(f"- {reason}")
        else:
            print(c("ALLOWED", GREEN, BOLD))
        return 1 if reasons else 0

    if command == "run":
        workspace = Path(args.workspace)
        original = _workspace_original(workspace)
        config = load_config(original)
        command_list = list(args.agent_command)
        if command_list and command_list[0] == "--":
            command_list = command_list[1:]
        return run_sandbox(
            workspace,
            command_list,
            config,
            args.interactive,
            allow_network=args.allow_network,
        )

    if command == "doctor":
        return _cmd_doctor(getattr(args, "path", "."), getattr(args, "json", False))

    raise MugError(f"Unsupported command: {command}")


def _cmd_doctor(path: str, as_json: bool) -> int:
    root = canonical_root(path)
    config = load_config(root)
    engines = {name: bool(shutil.which(name)) for name in ("podman", "docker")}
    warnings: list[str] = []
    if config.sandbox_network:
        warnings.append("sandbox.network=true requires --allow-network on mug run (exfiltration risk)")
    if config.allow_weaken_defaults:
        warnings.append("allow_weaken_defaults=true can remove non-immutable export excludes")
    if config.sandbox_user in {"", "0:0", "root", "0"}:
        warnings.append("sandbox.user runs as root inside the container")
    payload = {
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "root": str(root),
        "config": str(root / ".mug.toml") if (root / ".mug.toml").exists() else "defaults",
        "sandbox_engines": engines,
        "safe_sandbox_available": any(engines.values()),
        "network_default": config.sandbox_network,
        "fail_on_unscanned": config.fail_on_unscanned,
        "immutable_exclude_count": len(IMMUTABLE_EXCLUDES),
        "warnings": warnings,
        "posture": "hardened" if not warnings and any(engines.values()) else "review",
    }
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        banner(__version__)
        for key, value in payload.items():
            if key == "warnings":
                print(f"{c('warnings', BOLD)}: {len(value)}")
                for warning in value:
                    warn(warning)
            elif key == "posture":
                color = GREEN if value == "hardened" else YELLOW
                print(f"{c('posture', BOLD)}: {c(str(value), color, BOLD)}")
            else:
                print(f"{c(str(key), DIM)}: {value}")
        print()
        info("Tip: run `mug` for the interactive menu, or `mug guide` for the workflow.")
    if not payload["safe_sandbox_available"]:
        return 1
    return 1 if warnings else 0


def run_menu() -> int:
    render_home(__version__)
    while True:
        render_menu()
        action = read_menu_choice()
        print()
        if action is None:
            warn("Unknown choice. Pick a number from the menu (or q to exit).")
            continue
        if action == "exit":
            ok("Bye. Stay fail-closed.")
            return 0
        try:
            code = _menu_action(action)
        except MugError as exc:
            err(str(exc))
            print()
            continue
        if code is None:
            continue
        if code not in {0, 1}:
            return code
        print()


def _menu_action(action: str) -> int | None:
    if action == "guide":
        print_guide()
        return None
    if action == "cheatsheet":
        print_cheatsheet()
        return None
    if action == "doctor":
        _cmd_doctor(".", False)
        return None
    if action == "init":
        return dispatch(SimpleNamespace(command="init", path=".", force=False))
    if action == "scan":
        path = prompt("Project path", ".")
        return dispatch(SimpleNamespace(command="scan", path=path, json=False))
    if action == "pack":
        path = prompt("Project path", ".")
        default_out = f"{Path(path).resolve().name}-sanitized.zip"
        output = prompt("ZIP output path", default_out)
        allow = confirm("Allow findings and pack anyway?", False)
        return dispatch(
            SimpleNamespace(
                command="pack",
                path=path,
                output=output,
                allow_findings=allow,
                json=False,
            )
        )
    if action == "workspace":
        path = prompt("Project path", ".")
        root = Path(path).expanduser().resolve()
        default_out = str(root.parent / f"{root.name}-ai-workspace")
        output = prompt("Workspace output (outside the repo)", default_out)
        allow = confirm("Allow findings and continue anyway?", False)
        return dispatch(
            SimpleNamespace(
                command="workspace",
                path=path,
                output=output,
                allow_findings=allow,
                json=False,
            )
        )
    if action == "diff":
        workspace = prompt("Workspace path")
        if not workspace:
            warn("Workspace path required.")
            return None
        return dispatch(SimpleNamespace(command="diff", workspace=workspace, json=False, no_patch=False))
    if action == "apply":
        workspace = prompt("Workspace path")
        if not workspace:
            warn("Workspace path required.")
            return None
        dry = confirm("Dry-run only (recommended first)?", True)
        yes = True if dry else confirm("Apply for real? This writes the original repo.", False)
        if not dry and not yes:
            info("Cancelled.")
            return None
        allow_delete = False if dry else confirm("Allow deletions?", False)
        return dispatch(
            SimpleNamespace(
                command="apply",
                workspace=workspace,
                yes=yes,
                allow_delete=allow_delete,
                force=False,
                dry_run=dry,
                json=False,
            )
        )
    warn(f"Unhandled action: {action}")
    return None

def _workspace_original(workspace: Path) -> Path:
    from .workspace import resolve_workspace

    original, _, _ = resolve_workspace(workspace)
    return original


def _print_findings(findings: list[object]) -> None:
    if not findings:
        ok("No findings.")
        return
    for item in findings:
        location = f"{item.path}:{item.line}" if item.line else item.path
        sev = item.severity.upper()
        color = RED if item.severity in {"high", "critical"} else YELLOW
        print(f"{c(f'{sev:8}', color, BOLD)} {location} [{item.rule}] {item.message}")
        if item.excerpt:
            print(f"         {item.excerpt}")
    by_rule: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for item in findings:
        by_rule[item.rule] = by_rule.get(item.rule, 0) + 1
        by_severity[item.severity] = by_severity.get(item.severity, 0) + 1
    print()
    print(c(f"Summary: {len(findings)} finding(s)", BOLD, CYAN))
    sev = ", ".join(f"{k}={v}" for k, v in sorted(by_severity.items(), key=lambda kv: kv[0]))
    print(f"  by severity: {sev}")
    rules = ", ".join(f"{k}={v}" for k, v in sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0])))
    print(f"  by rule: {rules}")
    if by_rule.get("unscanned-large"):
        print(
            "  tip: unscanned-large → raise scan.max_file_bytes for oversized source, "
            "or add the path to export.exclude_add if it should stay out of AI packs."
        )
    if by_rule.get("high-entropy"):
        print(
            "  tip: high-entropy → review redacted excerpts; lockfile/checksum noise is filtered by default."
        )


def _print_result(result: dict[str, object], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2))
        return
    for key, value in result.items():
        if key == "findings":
            print(f"findings: {len(value) if isinstance(value, list) else value}")
        elif key == "applied" and isinstance(value, list):
            print(f"applied: {len(value)}")
            for change in value:
                print(f"  {change['action'].upper():8} {change['path']}")
        else:
            print(f"{key}: {value}")
