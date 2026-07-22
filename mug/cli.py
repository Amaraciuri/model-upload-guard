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
from .baseline import BASELINE_NAME, load_baseline, write_baseline
from .config import DEFAULT_CONFIG_TEXT, IMMUTABLE_EXCLUDES, load_config
from .sandbox import inspect_command, run_sandbox
from .scanner import NON_BLOCKING_RULES, Finding, blocks_export, scan_tree
from .snapshot import (
    create_snapshot,
    latest_snapshot,
    list_snapshot_details,
    list_snapshots,
    restore_snapshot,
)
from .history import last_run, load_history, record_run
from .ui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    RED,
    YELLOW,
    MenuNav,
    banner,
    c,
    clear_screen,
    confirm,
    err,
    info,
    make_progress,
    ok,
    print_agents_help,
    print_change_preview,
    print_cheatsheet,
    print_guide,
    prompt,
    read_menu_choice,
    render_home,
    render_menu,
    wait_return,
    warn,
    wizard_header,
)
from .templates import AGENTS_MD
from .utils import MugError, canonical_root, default_mug_bin, install_root, mug_on_path, state_dir
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
    scan.add_argument(
        "--update-baseline",
        action="store_true",
        help=f"Accept the current findings into {BASELINE_NAME} after human review",
    )

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
    apply.add_argument(
        "--allow-delete",
        action="store_true",
        help="Permit deletions (still subject to max_delete_ratio unless --force)",
    )
    apply.add_argument(
        "--force",
        action="store_true",
        help="Override volume/git checks only; never bypasses protected paths",
    )
    apply.add_argument("--dry-run", action="store_true", help="Show the apply plan without writing")
    apply.add_argument("--json", action="store_true")

    snapshot = sub.add_parser("snapshot", help="Create a private local recovery snapshot")
    snapshot.add_argument("path", nargs="?", default=".")

    snapshots = sub.add_parser("snapshots", help="List private local recovery snapshots")
    snapshots.add_argument("path", nargs="?", default=".")
    snapshots.add_argument("--json", action="store_true")

    restore = sub.add_parser("restore", help="Restore a snapshot into a new empty directory")
    restore.add_argument("archive", nargs="?", help="Snapshot archive path (or use --latest)")
    restore.add_argument("target", nargs="?", help="Empty destination directory")
    restore.add_argument("--latest", action="store_true", help="Use the newest snapshot for path")
    restore.add_argument(
        "--from",
        dest="from_path",
        default=".",
        help="Project path used with --latest (default: .)",
    )
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
    doctor.add_argument(
        "--offline",
        action="store_true",
        help="Skip GitHub/PyPI checks (no network)",
    )

    status = sub.add_parser("status", help="Show install/state/last-run summary")
    status.add_argument("path", nargs="?", default=".")
    status.add_argument("--json", action="store_true")
    status.add_argument("--offline", action="store_true", help="Skip update check")

    update = sub.add_parser("update", help="Update mug in place from GitHub")
    update.add_argument("--ref", help="Tag or branch to install (default: latest release)")
    update.add_argument("--check", action="store_true", help="Only check whether a newer version exists")
    update.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Allow git-archive ZIP when release checksums are unavailable",
    )
    update.add_argument("--json", action="store_true")
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


def dispatch(args: argparse.Namespace | SimpleNamespace) -> int:
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
            raise MugError(
                f"Configuration already exists: {destination}. "
                "Re-run with --force to overwrite, or edit the file in place."
            )
        destination.write_text(DEFAULT_CONFIG_TEXT, encoding="utf-8")
        ok(f"Wrote {destination}")
        info("Next: mug scan   then   mug pack -o project-for-ai.zip")
        record_run("init", root=root, ok=True, summary={"config": str(destination)})
        return 0

    if command == "scan":
        root = canonical_root(args.path)
        config = load_config(root)
        quiet = bool(getattr(args, "json", False))
        bar, progress = make_progress("Scanning", quiet=quiet)
        findings = scan_tree(root, config, on_progress=progress, baseline=load_baseline(root))
        if bar is not None:
            bar.finish(c(f"✓ scanned {root.name}", GREEN) if not quiet else "")
        if getattr(args, "update_baseline", False):
            accepted = [item for item in findings if item.rule not in NON_BLOCKING_RULES]
            baseline_path, count = write_baseline(root, accepted)
            if not quiet:
                ok(f"Baseline written: {baseline_path} ({count} finding(s) accepted)")
                warn("Baselined findings no longer block export. Review them before committing the baseline.")
        blocked = blocks_export(findings, config.fail_on, config.fail_on_unscanned)
        if args.json:
            print(json.dumps([item.to_dict() for item in findings], indent=2))
        else:
            _print_findings(findings)
            if not findings or not blocked:
                info("Next: mug pack -o safe-for-ai.zip   or   mug workspace -o ../proj-ai")
        record_run(
            "scan",
            root=root,
            ok=not blocked,
            summary={
                "findings": len(findings),
                "blocked": blocked,
                "baselined": sum(1 for item in findings if item.baselined),
                "allowlisted": sum(1 for item in findings if item.allowlisted),
            },
        )
        return 1 if blocked else 0

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
        record_run(
            "pack",
            root=root,
            ok=True,
            summary={"output": str(result.get("output")), "files": result.get("files")},
        )
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
        if not quiet:
            info(f"Next: mug run {result['workspace']} -- your-agent")
        record_run(
            "workspace",
            root=root,
            ok=True,
            summary={"workspace": str(result.get("workspace")), "files": result.get("files")},
        )
        return 0

    if command == "diff":
        workspace = Path(args.workspace)
        config = load_config(_workspace_original(workspace))
        original, changes, manifest = compute_changes(
            workspace,
            config,
            include_patches=not args.no_patch,
        )
        source_files = manifest.get("source_files", {})
        deletes = sum(1 for change in changes if change.action == "delete")
        protected = sum(1 for change in changes if change.action == "blocked" and "Protected" in change.reason)
        denominator = max(1, len(source_files) if isinstance(source_files, dict) else 1)
        delete_ratio = deletes / denominator
        payload = {
            "original": str(original),
            "changes": [change.to_dict() for change in changes],
            "count": len(changes),
            "policy": {
                "max_changes": config.max_changes,
                "max_delete_ratio": config.max_delete_ratio,
                "deletes": deletes,
                "delete_ratio": round(delete_ratio, 4),
                "protected_blocked": protected,
                "configure": "edit [apply] in .mug.toml",
            },
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
            print()
            print(
                c("Apply policy", BOLD, CYAN)
                + f": changes≤{config.max_changes}  "
                + f"deletes {deletes} ({delete_ratio:.1%}) / max {config.max_delete_ratio:.1%}  "
                + f"protected_blocked={protected}"
            )
            info("Thresholds live in .mug.toml [apply]; --force never bypasses protected paths.")
        record_run(
            "diff",
            root=original,
            ok=not any(change.action == "blocked" for change in changes),
            summary={
                "count": len(changes),
                "deletes": deletes,
                "protected_blocked": protected,
                "workspace": str(workspace),
            },
        )
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
        record_run(
            "apply",
            root=original,
            ok=True,
            summary={
                "count": result.get("count"),
                "dry_run": result.get("dry_run"),
                "snapshot": result.get("snapshot"),
                "workspace": str(workspace),
            },
        )
        return 0

    if command == "snapshot":
        root = canonical_root(args.path)
        archive = create_snapshot(root)
        ok(f"Snapshot: {archive}")
        info(f"State dir: {state_dir()}")
        record_run("snapshot", root=root, ok=True, summary={"archive": str(archive)})
        return 0

    if command == "snapshots":
        root = canonical_root(args.path)
        details = list_snapshot_details(root)
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {"root": str(root), "state_dir": str(state_dir()), "snapshots": details},
                    indent=2,
                )
            )
            return 0
        if not details:
            info("No snapshots yet. Create one with: mug snapshot")
            info(f"State dir: {state_dir()}")
            return 0
        info(f"State dir: {state_dir()}")
        for item in details:
            created = item.get("created_at") or "?"
            reason = item.get("reason") or "unknown"
            size = int(item.get("size_bytes") or 0)
            print(f"{created}  {reason:12}  {size:>8} B  {item['archive']}")
        info("Restore latest into an empty dir: mug restore --latest ../restored --yes")
        return 0

    if command == "restore":
        if not args.yes:
            raise MugError("Restore is confirmation-gated. Re-run with --yes.")
        archive_arg = getattr(args, "archive", None)
        target_arg = getattr(args, "target", None)
        if getattr(args, "latest", False):
            root = canonical_root(getattr(args, "from_path", "."))
            archive_path = latest_snapshot(root)
            if archive_path is None:
                raise MugError(f"No snapshots found for {root}. Create one with: mug snapshot")
            # `mug restore --latest ../restored --yes` puts the dir in archive_arg.
            target_path = Path(target_arg or archive_arg or "")
            if not str(target_path):
                raise MugError(
                    "Restore with --latest needs a target directory. "
                    "Example: mug restore --latest ../restored --yes"
                )
        else:
            if not archive_arg or not target_arg:
                raise MugError(
                    "Usage: mug restore <archive> <target> --yes   "
                    "or   mug restore --latest ../restored --yes"
                )
            archive_path = Path(archive_arg)
            target_path = Path(target_arg)
        restore_snapshot(archive_path, target_path)
        ok(str(target_path.expanduser().resolve()))
        record_run(
            "restore",
            root=None,
            ok=True,
            summary={"archive": str(archive_path), "target": str(target_path)},
        )
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
        return _cmd_doctor(
            getattr(args, "path", "."),
            getattr(args, "json", False),
            offline=bool(getattr(args, "offline", False)),
        )

    if command == "status":
        return _cmd_status(
            getattr(args, "path", "."),
            getattr(args, "json", False),
            offline=bool(getattr(args, "offline", False)),
        )

    if command == "update":
        from .update import check_update, self_update

        if args.check:
            payload = check_update()
            if args.json:
                print(json.dumps(payload, indent=2))
            elif payload["update_available"]:
                info(f"Update available: {payload['current']} → {payload['latest']}")
                info("Run: mug update")
            else:
                ok(f"mug {payload['current']} is up to date (latest: {payload['latest']})")
            return 0 if not payload["update_available"] else 1
        result = self_update(
            getattr(args, "ref", None),
            allow_unverified=bool(getattr(args, "allow_unverified", False)),
        )
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            verified = "verified" if result.get("verified") else "unverified"
            ok(f"Updated {result['previous']} → {result['installed']} (ref {result['ref']}, {verified})")
            info("Restart any running mug session to use the new version.")
        return 0

    raise MugError(f"Unsupported command: {command}")


def _cmd_doctor(path: str, as_json: bool, *, offline: bool = False) -> int:
    from .update import check_update

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
    if not mug_on_path():
        warnings.append(
            f"`mug` not on PATH. Add ~/.local/bin or run: {default_mug_bin()} doctor"
        )

    pypi_available = False
    update_info: dict[str, object] = {
        "current": __version__,
        "latest": __version__,
        "update_available": False,
    }
    if not offline:
        try:
            import urllib.request

            with urllib.request.urlopen(
                urllib.request.Request(
                    "https://pypi.org/pypi/model-upload-guard/json",
                    headers={"User-Agent": f"mug/{__version__}"},
                ),
                timeout=5,
            ) as response:
                pypi_available = response.status == 200
        except Exception:
            pypi_available = False
        try:
            update_info = check_update()
            if update_info.get("update_available"):
                warnings.append(
                    f"Update available: {update_info['current']} → {update_info['latest']}. Run: mug update"
                )
        except MugError:
            pass

    payload = {
        "version": __version__,
        "latest_version": None if offline else update_info.get("latest"),
        "update_available": False if offline else update_info.get("update_available"),
        "offline": offline,
        "pypi_available": None if offline else pypi_available,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "root": str(root),
        "config": str(root / ".mug.toml") if (root / ".mug.toml").exists() else "defaults",
        "mug_on_path": mug_on_path(),
        "mug_bin": str(default_mug_bin()),
        "install_root": str(install_root()),
        "state_dir": str(state_dir()),
        "sandbox_profile": config.sandbox_profile,
        "sandbox_engines": engines,
        "safe_sandbox_available": any(engines.values()),
        "network_default": config.sandbox_network,
        "fail_on_unscanned": config.fail_on_unscanned,
        "immutable_exclude_count": len(IMMUTABLE_EXCLUDES),
        "apply_policy": {
            "max_changes": config.max_changes,
            "max_delete_ratio": config.max_delete_ratio,
            "protected_patterns": len(config.protected),
            "configure": "[apply] in .mug.toml — protected_add only adds; --force never bypasses protected",
        },
        "scan_custom_rules": len(config.rules_add),
        "scan_allowlist_paths": len(config.allowlist_paths),
        "warnings": warnings,
        "posture": "hardened" if not warnings and any(engines.values()) else "review",
        "install_hint": (
            "pip install model-upload-guard"
            if pypi_available
            else "curl -fsSL https://raw.githubusercontent.com/Amaraciuri/model-upload-guard/v0.3.4/install.sh | MUG_REF=v0.3.4 bash"
        ),
    }
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        banner(__version__)
        for key, value in payload.items():
            if key == "warnings" and isinstance(value, list):
                print(f"{c('warnings', BOLD)}: {len(value)}")
                for warning in value:
                    warn(str(warning))
            elif key == "posture":
                color = GREEN if value == "hardened" else YELLOW
                print(f"{c('posture', BOLD)}: {c(str(value), color, BOLD)}")
            elif key == "apply_policy" and isinstance(value, dict):
                print(
                    f"{c('apply_policy', BOLD)}: "
                    f"max_changes={value['max_changes']}  "
                    f"max_delete_ratio={value['max_delete_ratio']:.1%}  "
                    f"protected={value['protected_patterns']}"
                )
                info(str(value["configure"]))
            else:
                print(f"{c(str(key), DIM)}: {value}")
        print()
        if not payload["safe_sandbox_available"]:
            info("No container engine — pack/workspace/diff/apply still work; mug run needs Docker/Podman.")
        if not mug_on_path():
            info('Add to PATH: export PATH="$HOME/.local/bin:$PATH"  then: hash -r')
        if not offline:
            info(f"Install: {payload['install_hint']}")
            if not pypi_available:
                info("PyPI not live yet — use the GitHub verified installer above.")
        else:
            info("Offline mode: skipped GitHub/PyPI checks.")
        info("Tip: mug status · mug · mug guide")
    # Missing sandbox is advisory for pack-only users; still exit 1 so CI notices.
    if not payload["safe_sandbox_available"]:
        return 1
    return 1 if warnings else 0


def _cmd_status(path: str, as_json: bool, *, offline: bool = False) -> int:
    root = canonical_root(path)
    config = load_config(root)
    config_path = root / ".mug.toml"
    snapshots = list_snapshots(root)
    recent = load_history(limit=8)
    last = last_run(root=root) or (recent[0] if recent else None)
    workspaces_dir = state_dir() / "workspaces"
    workspace_count = len(list(workspaces_dir.glob("*.json"))) if workspaces_dir.exists() else 0
    update_available = None
    if not offline:
        try:
            from .update import check_update

            update_available = bool(check_update().get("update_available"))
        except MugError:
            update_available = None

    payload = {
        "version": __version__,
        "root": str(root),
        "config": str(config_path) if config_path.exists() else "defaults",
        "mug_on_path": mug_on_path(),
        "install_root": str(install_root()),
        "state_dir": str(state_dir()),
        "snapshots": len(snapshots),
        "latest_snapshot": str(snapshots[0]) if snapshots else None,
        "workspace_registries": workspace_count,
        "update_available": update_available,
        "last_run": last,
        "recent": recent,
        "apply_policy": {
            "max_changes": config.max_changes,
            "max_delete_ratio": config.max_delete_ratio,
        },
    }
    if as_json:
        print(json.dumps(payload, indent=2))
        return 0

    banner(__version__)
    print(f"{c('root', DIM)}: {payload['root']}")
    print(f"{c('config', DIM)}: {payload['config']}")
    print(f"{c('state_dir', DIM)}: {payload['state_dir']}")
    print(f"{c('install_root', DIM)}: {payload['install_root']}")
    on_path = c("yes", GREEN) if payload["mug_on_path"] else c("no", YELLOW)
    print(f"{c('mug_on_path', DIM)}: {on_path}")
    print(f"{c('snapshots', DIM)}: {payload['snapshots']}")
    print(f"{c('workspace_registries', DIM)}: {payload['workspace_registries']}")
    if update_available is True:
        warn("Update available — run: mug update")
    elif update_available is False:
        ok("Up to date")
    if last:
        print()
        print(c("Last run for this project", BOLD, CYAN))
        print(
            f"  {last.get('at', '?')}  {last.get('command')}  "
            f"{'ok' if last.get('ok') else 'blocked'}  {last.get('summary', {})}"
        )
    if recent:
        print()
        print(c("Recent history", BOLD))
        for entry in recent[:5]:
            mark = "✓" if entry.get("ok") else "!"
            print(
                f"  {mark} {entry.get('at', '?')}  {entry.get('command')}  "
                f"{Path(str(entry.get('root', ''))).name if entry.get('root') else '-'}"
            )
    print()
    info("Recovery: mug snapshots · mug restore --latest ../restored --yes")
    return 0


def run_menu() -> int:
    first = True
    while True:
        try:
            clear_screen()
            render_home(__version__, compact=not first)
            first = False
            render_menu()
            action = read_menu_choice()
            print()
            if action is None:
                warn("Unknown choice. Pick a number from the menu (or q to quit).")
                continue
            if action == "home":
                continue
            if action == "exit":
                ok("Bye. Stay fail-closed.")
                return 0
            try:
                code = _menu_action(action)
            except MenuNav as nav:
                if nav.kind == "quit":
                    ok("Bye. Stay fail-closed.")
                    return 0
                info("Back to menu.")
                continue
            except MugError as exc:
                err(str(exc))
                try:
                    wait_return()
                except MenuNav as nav:
                    if nav.kind == "quit":
                        ok("Bye. Stay fail-closed.")
                        return 0
                continue
            if code is None:
                try:
                    wait_return()
                except MenuNav as nav:
                    if nav.kind == "quit":
                        ok("Bye. Stay fail-closed.")
                        return 0
                continue
            if code not in {0, 1}:
                return code
            try:
                wait_return()
            except MenuNav as nav:
                if nav.kind == "quit":
                    ok("Bye. Stay fail-closed.")
                    return 0
        except KeyboardInterrupt:
            print()
            ok("Bye. Stay fail-closed.")
            return 0
        except MenuNav as nav:
            if nav.kind == "quit":
                ok("Bye. Stay fail-closed.")
                return 0
            info("Back to menu.")


def _menu_action(action: str) -> int | None:
    if action == "guide":
        wizard_header("Quick start")
        print_guide()
        return None
    if action == "cheatsheet":
        wizard_header("Cheat sheet")
        print_cheatsheet()
        return None
    if action == "agents":
        wizard_header("Agent rules")
        print_agents_help()
        if confirm("Write AGENTS.md in the current directory?", True):
            destination = Path.cwd() / "AGENTS.md"
            if destination.exists() and not confirm(f"{destination} exists — overwrite?", False):
                info("Cancelled.")
                raise MenuNav("back")
            destination.write_text(AGENTS_MD, encoding="utf-8")
            ok(f"Wrote {destination}")
        return None
    if action == "doctor":
        wizard_header("Doctor")
        _cmd_doctor(".", False, offline=False)
        return None
    if action == "status":
        wizard_header("Status")
        _cmd_status(".", False, offline=False)
        return None
    if action == "init":
        wizard_header("Init")
        info("Type b anytime to return to the menu.")
        path = prompt("Project path", ".")
        force = False
        if (Path(path).expanduser().resolve() / ".mug.toml").exists():
            force = confirm(".mug.toml already exists — overwrite?", False)
            if not force:
                info("Cancelled.")
                raise MenuNav("back")
        return dispatch(SimpleNamespace(command="init", path=path, force=force))
    if action == "scan":
        wizard_header("Scan", 1, 2)
        info("Type b anytime to return to the menu.")
        path = prompt("Project path", ".")
        wizard_header("Scan", 2, 2)
        return dispatch(SimpleNamespace(command="scan", path=path, json=False, update_baseline=False))
    if action == "update":
        wizard_header("Update")
        if not confirm("Update mug from GitHub now? (SHA256 verified)", True):
            info("Cancelled.")
            raise MenuNav("back")
        return dispatch(
            SimpleNamespace(
                command="update",
                ref=None,
                check=False,
                allow_unverified=False,
                json=False,
            )
        )
    if action == "recovery":
        wizard_header("Recovery", 1, 2)
        info("Type b anytime to return to the menu.")
        path = prompt("Project path", ".")
        wizard_header("Recovery", 2, 2)
        code = dispatch(SimpleNamespace(command="snapshots", path=path, json=False))
        if confirm("Restore the latest snapshot into a new empty directory?", False):
            target = prompt("Empty target directory", str(Path(path).resolve().parent / "restored"))
            if not confirm(f"Restore latest → {target}?", False):
                info("Cancelled.")
                raise MenuNav("back")
            return dispatch(
                SimpleNamespace(
                    command="restore",
                    archive=None,
                    target=target,
                    latest=True,
                    from_path=path,
                    yes=True,
                )
            )
        return code
    if action == "pack":
        wizard_header("Pack", 1, 3)
        info("Type b anytime to return to the menu.")
        path = prompt("Project path", ".")
        wizard_header("Pack", 2, 3)
        default_out = f"{Path(path).resolve().name}-sanitized.zip"
        output = prompt("ZIP output path", default_out)
        wizard_header("Pack", 3, 3)
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
        wizard_header("Workspace", 1, 3)
        info("Type b anytime to return to the menu.")
        path = prompt("Project path", ".")
        wizard_header("Workspace", 2, 3)
        root = Path(path).expanduser().resolve()
        default_out = str(root.parent / f"{root.name}-ai-workspace")
        output = prompt("Workspace output (outside the repo)", default_out)
        wizard_header("Workspace", 3, 3)
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
        wizard_header("Diff")
        info("Type b anytime to return to the menu.")
        workspace = prompt("Workspace path", required=True)
        return dispatch(SimpleNamespace(command="diff", workspace=workspace, json=False, no_patch=False))
    if action == "apply":
        wizard_header("Apply", 1, 4)
        info("Type b anytime to return to the menu.")
        workspace = prompt("Workspace path", required=True)
        try:
            original = _workspace_original(Path(workspace))
            config = load_config(original)
            _, changes, manifest = compute_changes(Path(workspace), config, include_patches=False)
        except MugError as exc:
            err(str(exc))
            raise MenuNav("back") from exc
        deletes = [change for change in changes if change.action == "delete"]
        actionable = [change for change in changes if change.action != "blocked"]
        source_files = manifest.get("source_files", {})
        denominator = max(1, len(source_files) if isinstance(source_files, dict) else 1)
        delete_ratio = len(deletes) / denominator
        wizard_header("Apply", 2, 4)
        info(
            f"Apply policy: max_changes={config.max_changes}, "
            f"max_delete_ratio={config.max_delete_ratio:.1%} "
            f"(edit [apply] in .mug.toml — menu does not change these)"
        )
        print_change_preview(changes)
        info(
            f"This run vs limit: {len(actionable)}/{config.max_changes} changes, "
            f"{len(deletes)} deletes ({delete_ratio:.1%} / {config.max_delete_ratio:.1%}). "
            "Protected paths cannot be forced."
        )
        wizard_header("Apply", 3, 4)
        dry = confirm("Dry-run only (recommended first)?", True)
        yes = True if dry else confirm("Apply for real? This writes the original repo.", False)
        if not dry and not yes:
            info("Cancelled.")
            raise MenuNav("back")
        allow_delete = False
        if deletes and not dry:
            wizard_header("Apply · deletions", 4, 4)
            print(c("These paths would be deleted from the original repo:", BOLD, YELLOW))
            for change in deletes[:40]:
                print(f"  {c('DELETE', YELLOW, BOLD)}  {change.path}")
            if len(deletes) > 40:
                print(c(f"  … and {len(deletes) - 40} more", DIM))
            print()
            allow_delete = confirm(
                f"Allow {len(deletes)} deletion(s)? "
                f"(limit {config.max_delete_ratio:.1%}; does not raise the limit)",
                False,
            )
            if not allow_delete:
                info("Cancelled — deletions not permitted.")
                raise MenuNav("back")
        need_force = len(actionable) > config.max_changes or delete_ratio > config.max_delete_ratio
        force = False
        if need_force and not dry:
            warn("This change set exceeds volume thresholds (max_changes / max_delete_ratio).")
            force = confirm("Pass --force for volume/git checks only? (never bypasses protected paths)", False)
            if not force:
                info("Cancelled. Raise limits in .mug.toml or shrink the change set.")
                raise MenuNav("back")
        if dry or not deletes:
            wizard_header("Apply", 4, 4)
        return dispatch(
            SimpleNamespace(
                command="apply",
                workspace=workspace,
                yes=yes,
                allow_delete=allow_delete,
                force=force,
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


def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        ok("No findings.")
        return
    baselined = [item for item in findings if item.baselined]
    allowlisted = [item for item in findings if item.allowlisted and not item.baselined]
    active = [item for item in findings if not item.baselined and not item.allowlisted]
    for item in active:
        location = f"{item.path}:{item.line}" if item.line else item.path
        sev = item.severity.upper()
        color = RED if item.severity in {"high", "critical"} else YELLOW
        print(f"{c(f'{sev:8}', color, BOLD)} {location} [{item.rule}] {item.message}")
        if item.excerpt:
            print(f"         {item.excerpt}")
    if allowlisted:
        print(
            c(
                f"{len(allowlisted)} allowlisted finding(s) via scan.allowlist_paths (not blocking)",
                DIM,
            )
        )
    if baselined:
        print(c(f"{len(baselined)} baselined finding(s) accepted via .mug-baseline.json (not blocking)", DIM))
    if not active:
        ok("No blocking findings.")
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
    if by_rule.get("gitignored-file"):
        print(
            "  tip: gitignored-file → gitignored files are often local-only config; "
            "add them to export.exclude_add or accept with --update-baseline."
        )
    print(
        "  tip: reviewed false positives? accept them individually: mug scan --update-baseline"
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
        elif key == "policy" and isinstance(value, dict):
            print(
                f"policy: changes={value.get('changes')}/{value.get('max_changes')}  "
                f"deletes={value.get('deletes')} ({value.get('delete_ratio')})  "
                f"protected_blocked={value.get('protected_blocked')}"
            )
            if value.get("configure"):
                info(str(value["configure"]))
        else:
            print(f"{key}: {value}")
