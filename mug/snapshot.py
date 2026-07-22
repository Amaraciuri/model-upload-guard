from __future__ import annotations

import os
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from .utils import (
    MugError,
    iter_regular_files,
    project_key,
    read_json,
    safe_join,
    state_dir,
    write_json,
)

SNAPSHOT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    ".mug",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    "target",
}


def _snapshot_file_allowed(rel: str) -> bool:
    return not any(part in SNAPSHOT_EXCLUDES for part in rel.split("/"))


def create_snapshot(root: Path, reason: str = "manual") -> Path:
    root = root.resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = state_dir() / "snapshots" / project_key(root)
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / f"{stamp}.tar.gz"
    counter = 1
    while archive.exists():
        archive = directory / f"{stamp}-{counter}.tar.gz"
        counter += 1
    temp = archive.with_suffix(archive.suffix + ".tmp")
    try:
        with tarfile.open(temp, "w:gz") as tar:
            for rel, path in iter_regular_files(root):
                if _snapshot_file_allowed(rel):
                    tar.add(path, arcname=rel, recursive=False)
        os.chmod(temp, 0o600)
        os.replace(temp, archive)
        write_json(
            archive.with_suffix(archive.suffix + ".json"),
            {
                "format": 1,
                "source_root": str(root),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "reason": reason,
                "archive": str(archive),
            },
            private=True,
        )
    finally:
        temp.unlink(missing_ok=True)
    return archive


def list_snapshots(root: Path) -> list[Path]:
    directory = state_dir() / "snapshots" / project_key(root.resolve())
    if not directory.exists():
        return []
    return sorted(directory.glob("*.tar.gz"), reverse=True)


def snapshot_meta(archive: Path) -> dict[str, object]:
    archive = archive.expanduser().resolve()
    meta_path = Path(str(archive) + ".json")
    payload: dict[str, object] = {
        "archive": str(archive),
        "exists": archive.is_file(),
        "reason": "unknown",
        "created_at": None,
        "source_root": None,
    }
    if meta_path.is_file():
        try:
            data = read_json(meta_path)
            if isinstance(data, dict):
                payload["reason"] = data.get("reason") or "unknown"
                payload["created_at"] = data.get("created_at")
                payload["source_root"] = data.get("source_root")
        except MugError:
            pass
    try:
        payload["size_bytes"] = archive.stat().st_size if archive.is_file() else 0
    except OSError:
        payload["size_bytes"] = 0
    return payload


def list_snapshot_details(root: Path) -> list[dict[str, object]]:
    return [snapshot_meta(path) for path in list_snapshots(root)]


def latest_snapshot(root: Path) -> Path | None:
    archives = list_snapshots(root)
    return archives[0] if archives else None


def restore_snapshot(archive: Path, target: Path) -> None:
    archive = archive.expanduser().resolve()
    target = target.expanduser().resolve()
    if not archive.exists():
        raise MugError(
            f"Snapshot not found: {archive}. List available archives with: mug snapshots"
        )
    if target.exists() and any(target.iterdir()):
        raise MugError(
            f"Restore target must be empty: {target}. "
            "Pick a new empty directory (e.g. ../restored)."
        )
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            name = member.name.replace("\\", "/")
            if name.startswith("/") or (len(name) >= 2 and name[1] == ":"):
                raise MugError(f"Unsafe absolute entry in snapshot: {member.name}")
            if member.issym() or member.islnk() or member.isdev():
                raise MugError(f"Unsafe entry in snapshot: {member.name}")
            safe_join(target, member.name)
        tar.extractall(target, filter="data")
