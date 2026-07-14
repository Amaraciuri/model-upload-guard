from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .config import Config, path_matches
from .snapshot import create_snapshot
from .utils import MugError, atomic_write, iter_regular_files, safe_join, sha256_file
from .workspace import MANIFEST_NAME, WORKSPACE_ID_NAME, resolve_workspace


@dataclass(slots=True)
class Change:
    action: str
    path: str
    reason: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def compute_changes(workspace: Path, config: Config) -> tuple[Path, list[Change], dict[str, object]]:
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
            changes.append(Change("modify", rel, "Content differs from exported source"))

    for rel in sorted(set(workspace_files) - set(source_files)):
        original_path = safe_join(original, rel)
        if original_path.exists() or original_path.is_symlink():
            changes.append(Change("blocked", rel, "Conflict: path was created in the original repository"))
        else:
            changes.append(Change("add", rel, "New file in workspace"))

    for change in changes:
        if path_matches(change.path, config.protected):
            change.action = "blocked"
            change.reason = "Protected path cannot be changed through a workspace"
    return original, changes, manifest


def apply_changes(
    workspace: Path,
    config: Config,
    *,
    yes: bool,
    allow_delete: bool,
    force: bool,
) -> dict[str, object]:
    original, changes, manifest = compute_changes(workspace, config)
    blocked = [change for change in changes if change.action == "blocked"]
    actionable = [change for change in changes if change.action != "blocked"]
    if blocked:
        paths = ", ".join(change.path for change in blocked[:5])
        suffix = "..." if len(blocked) > 5 else ""
        raise MugError(f"Blocked or conflicting changes detected: {paths}{suffix}. Review `mug diff`.")
    if len(actionable) > config.max_changes and not force:
        raise MugError(f"Change set contains {len(actionable)} files; configured maximum is {config.max_changes}.")

    source_files = manifest.get("source_files", {})
    delete_changes = [change for change in actionable if change.action == "delete"]
    denominator = max(1, len(source_files))
    delete_ratio = len(delete_changes) / denominator
    if delete_changes and not allow_delete:
        raise MugError("Workspace deletes files. Re-run with --allow-delete after reviewing the diff.")
    if delete_ratio > config.max_delete_ratio and not force:
        raise MugError(
            f"Deletion ratio {delete_ratio:.1%} exceeds configured maximum {config.max_delete_ratio:.1%}."
        )
    if not yes:
        raise MugError("Apply is confirmation-gated. Re-run with --yes after reviewing `mug diff`.")

    if not actionable:
        return {"snapshot": None, "applied": [], "count": 0}

    snapshot = create_snapshot(original, reason="pre-apply")
    _, resolved_workspace, _ = resolve_workspace(workspace)
    applied: list[dict[str, str]] = []
    for change in actionable:
        destination = safe_join(original, change.path)
        if change.action in {"add", "modify"}:
            source = safe_join(resolved_workspace, change.path)
            if source.is_symlink() or not source.is_file():
                raise MugError(f"Refusing non-regular workspace file: {change.path}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(destination, source.read_bytes(), source.stat().st_mode & 0o777)
        elif change.action == "delete":
            if destination.is_dir():
                raise MugError(f"Refusing directory deletion: {change.path}")
            destination.unlink(missing_ok=True)
            _remove_empty_parents(destination.parent, original)
        applied.append(change.to_dict())

    return {"snapshot": str(snapshot), "applied": applied, "count": len(applied)}


def _remove_empty_parents(current: Path, root: Path) -> None:
    root = root.resolve()
    while current != root:
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent
