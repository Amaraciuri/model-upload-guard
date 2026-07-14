from __future__ import annotations

import difflib
import os
import shutil
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import Config, path_matches
from .gitaware import assert_apply_git_safe
from .snapshot import create_snapshot
from .utils import (
    MugError,
    atomic_write,
    is_binary,
    iter_regular_files,
    safe_join,
    sha256_file,
)
from .workspace import MANIFEST_NAME, WORKSPACE_ID_NAME, resolve_workspace


@dataclass(slots=True)
class Change:
    action: str
    path: str
    reason: str = ""
    patch: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        if payload.get("patch") is None:
            payload.pop("patch", None)
        return payload


def compute_changes(workspace: Path, config: Config, *, include_patches: bool = False) -> tuple[Path, list[Change], dict[str, object]]:
    original, workspace, manifest = resolve_workspace(workspace)
    source_files = manifest.get("source_files", {})
    if not isinstance(source_files, dict):
        raise MugError("Invalid workspace manifest")

    workspace_files: dict[str, Path] = {}
    for rel, path in iter_regular_files(workspace):
        if rel in {MANIFEST_NAME, WORKSPACE_ID_NAME}:
            continue
        workspace_files[rel] = path

    changes: list[Change] = []
    for rel, original_hash_obj in sorted(source_files.items()):
        exported_hash = str(original_hash_obj)
        work_path = workspace_files.get(rel)
        original_path = safe_join(original, rel)
        original_exists = original_path.is_file() and not original_path.is_symlink()
        current_original_hash = sha256_file(original_path) if original_exists else None

        if work_path is None:
            if not original_exists:
                continue
            if current_original_hash != exported_hash:
                changes.append(Change("blocked", rel, "Conflict: original file changed after workspace creation"))
            else:
                changes.append(Change("delete", rel, "File removed from workspace"))
            continue

        workspace_hash = sha256_file(work_path)
        if workspace_hash == exported_hash:
            continue
        if not original_exists:
            changes.append(Change("blocked", rel, "Conflict: original file was removed after workspace creation"))
        elif current_original_hash != exported_hash:
            changes.append(Change("blocked", rel, "Conflict: original file changed after workspace creation"))
        else:
            patch = _unified_patch(original_path, work_path, rel) if include_patches else None
            changes.append(Change("modify", rel, "Content differs from exported source", patch=patch))

    for rel in sorted(set(workspace_files) - set(source_files)):
        original_path = safe_join(original, rel)
        work_path = workspace_files[rel]
        if original_path.exists() or original_path.is_symlink():
            changes.append(Change("blocked", rel, "Conflict: path was created in the original repository"))
        else:
            patch = _unified_patch(None, work_path, rel) if include_patches else None
            changes.append(Change("add", rel, "New file in workspace", patch=patch))

    for change in changes:
        if path_matches(change.path, config.protected):
            change.action = "blocked"
            change.reason = "Protected path cannot be changed through a workspace"
            change.patch = None
    return original, changes, manifest


def apply_changes(
    workspace: Path,
    config: Config,
    *,
    yes: bool,
    allow_delete: bool,
    force: bool,
    dry_run: bool = False,
) -> dict[str, object]:
    original, changes, manifest = compute_changes(workspace, config, include_patches=False)
    blocked = [change for change in changes if change.action == "blocked"]
    actionable = [change for change in changes if change.action != "blocked"]
    protected_blocked = [
        change for change in blocked if "Protected path" in change.reason
    ]
    source_files = manifest.get("source_files", {})
    if not isinstance(source_files, dict):
        raise MugError("Invalid workspace manifest during apply validation")
    delete_changes = [change for change in actionable if change.action == "delete"]
    denominator = max(1, len(source_files))
    delete_ratio = len(delete_changes) / denominator
    policy = {
        "max_changes": config.max_changes,
        "max_delete_ratio": config.max_delete_ratio,
        "changes": len(actionable),
        "deletes": len(delete_changes),
        "delete_ratio": round(delete_ratio, 4),
        "protected_blocked": len(protected_blocked),
        "force_overrides": "volume and git checks only — never protected paths",
        "configure": "edit [apply] in .mug.toml (max_changes, max_delete_ratio, protected_add)",
    }

    if blocked:
        paths = ", ".join(change.path for change in blocked[:5])
        suffix = "..." if len(blocked) > 5 else ""
        raise MugError(f"Blocked or conflicting changes detected: {paths}{suffix}. Review `mug diff`.")
    if len(actionable) > config.max_changes and not force:
        raise MugError(
            f"Change set contains {len(actionable)} files; configured maximum is {config.max_changes} "
            f"(set apply.max_changes in .mug.toml, or pass --force for volume only)."
        )
    if delete_changes and not allow_delete:
        raise MugError(
            f"Workspace deletes {len(delete_changes)} file(s) "
            f"({delete_ratio:.1%} of exported set; limit apply.max_delete_ratio="
            f"{config.max_delete_ratio:.1%}). Re-run with --allow-delete after reviewing the diff."
        )
    if delete_ratio > config.max_delete_ratio and not force:
        raise MugError(
            f"Deletion ratio {delete_ratio:.1%} exceeds configured maximum {config.max_delete_ratio:.1%} "
            f"(apply.max_delete_ratio in .mug.toml). --force overrides this volume check only."
        )
    if not yes and not dry_run:
        raise MugError("Apply is confirmation-gated. Re-run with --yes after reviewing `mug diff`.")

    if not actionable:
        return {
            "snapshot": None,
            "applied": [],
            "count": 0,
            "dry_run": dry_run,
            "git_warnings": [],
            "policy": policy,
        }

    sealed_head = manifest.get("git_head")
    sealed_head_str = str(sealed_head) if isinstance(sealed_head, str) and sealed_head else None
    git_warnings = assert_apply_git_safe(original, sealed_head_str, force=force)

    if dry_run:
        return {
            "snapshot": None,
            "applied": [change.to_dict() for change in actionable],
            "count": len(actionable),
            "dry_run": True,
            "git_warnings": git_warnings,
            "policy": policy,
        }

    snapshot = create_snapshot(original, reason="pre-apply")
    _, resolved_workspace, _ = resolve_workspace(workspace)
    applied: list[dict[str, object]] = []
    # Journal of touched paths so a mid-apply failure rolls back automatically
    # instead of leaving the repository half-applied.
    journal: list[tuple[Path, Path | None, int | None]] = []
    backup_root = Path(tempfile.mkdtemp(prefix="mug-apply-journal-"))
    try:
        for change in actionable:
            destination = safe_join(original, change.path)
            if change.action in {"add", "modify"}:
                source = safe_join(resolved_workspace, change.path)
                if source.is_symlink() or not source.is_file():
                    raise MugError(f"Refusing non-regular workspace file: {change.path}")
                _journal_record(journal, backup_root, destination)
                destination.parent.mkdir(parents=True, exist_ok=True)
                atomic_write(destination, source.read_bytes(), source.stat().st_mode & 0o777)
            elif change.action == "delete":
                if destination.is_dir():
                    raise MugError(f"Refusing directory deletion: {change.path}")
                _journal_record(journal, backup_root, destination)
                destination.unlink(missing_ok=True)
                _remove_empty_parents(destination.parent, original)
            applied.append(change.to_dict())
    except BaseException as exc:
        rolled_back = _rollback(journal, original)
        if rolled_back:
            raise MugError(
                f"Apply failed and was rolled back ({exc}). "
                f"The repository is unchanged; pre-apply snapshot kept at {snapshot}."
            ) from exc
        raise MugError(
            f"Apply failed and automatic rollback was incomplete ({exc}). "
            f"Restore from the pre-apply snapshot: mug restore {snapshot} <new-empty-dir> --yes"
        ) from exc
    finally:
        shutil.rmtree(backup_root, ignore_errors=True)

    return {
        "snapshot": str(snapshot),
        "applied": applied,
        "count": len(applied),
        "dry_run": False,
        "git_warnings": git_warnings,
        "policy": policy,
    }


def _journal_record(
    journal: list[tuple[Path, Path | None, int | None]],
    backup_root: Path,
    destination: Path,
) -> None:
    if destination.is_file() and not destination.is_symlink():
        backup = backup_root / str(len(journal))
        shutil.copyfile(destination, backup)
        journal.append((destination, backup, destination.stat().st_mode & 0o777))
    else:
        journal.append((destination, None, None))


def _rollback(journal: list[tuple[Path, Path | None, int | None]], original: Path) -> bool:
    success = True
    for destination, backup, mode in reversed(journal):
        try:
            if backup is not None:
                destination.parent.mkdir(parents=True, exist_ok=True)
                # Plain writes on purpose: restore must not depend on the same
                # code path that may have just failed (e.g. tmpfile creation).
                destination.write_bytes(backup.read_bytes())
                if mode is not None:
                    os.chmod(destination, mode)
            else:
                destination.unlink(missing_ok=True)
                _remove_empty_parents(destination.parent, original)
        except OSError:
            success = False
    return success


def _unified_patch(original: Path | None, workspace_file: Path, rel: str) -> str | None:
    if workspace_file.is_symlink() or (original is not None and original.is_symlink()):
        return None
    if is_binary(workspace_file) or (original is not None and original.exists() and is_binary(original)):
        return f"Binary file differs: {rel}\n"
    try:
        new_text = workspace_file.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        old_text = (
            original.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            if original is not None and original.exists()
            else []
        )
    except OSError:
        return None
    diff = difflib.unified_diff(
        old_text,
        new_text,
        fromfile=f"a/{rel}",
        tofile=f"b/{rel}",
        lineterm="",
    )
    rendered = "\n".join(diff)
    if not rendered:
        return None
    return rendered + "\n"


def _remove_empty_parents(current: Path, root: Path) -> None:
    root = root.resolve()
    while current != root:
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent
