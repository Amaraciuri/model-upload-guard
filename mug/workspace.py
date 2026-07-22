from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .baseline import load_baseline
from .config import Config, path_matches
from .gitaware import git_rev_parse
from .scanner import blocks_export, scan_tree
from .utils import (
    MugError,
    copy_mode,
    iter_regular_files,
    sha256_file,
    state_dir,
    write_json,
)

MANIFEST_NAME = ".mug-manifest.json"
WORKSPACE_ID_NAME = ".mug-id"
ProgressCb = Callable[[int, int, str], None]


def _canonical_source_files_digest(source_files: dict[str, str]) -> str:
    payload = json.dumps(source_files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_manifest(
    root: Path,
    config: Config,
    on_progress: ProgressCb | None = None,
) -> tuple[dict[str, str], list[str]]:
    hashes: dict[str, str] = {}
    excluded: list[str] = []
    files = list(iter_regular_files(root))
    total = len(files)
    for index, (rel, path) in enumerate(files, start=1):
        if on_progress is not None:
            on_progress(index, total, rel)
        if path_matches(rel, config.exclude):
            excluded.append(rel)
            continue
        hashes[rel] = sha256_file(path)
    return hashes, excluded


def create_workspace(
    source: Path,
    destination: Path,
    config: Config,
    allow_findings: bool = False,
    on_progress: ProgressCb | None = None,
) -> dict[str, object]:
    source = source.resolve()
    destination = destination.expanduser().resolve()
    if destination == source or source in destination.parents:
        raise MugError("Workspace must be outside the source repository")
    if destination.exists() and any(destination.iterdir()):
        raise MugError(
            f"Workspace destination is not empty: {destination}. "
            "Choose a new empty path (e.g. ../project-ai-workspace)."
        )

    hashes, excluded = build_manifest(source, config, on_progress=on_progress)
    findings = scan_tree(source, config, on_progress=on_progress, baseline=load_baseline(source))
    if blocks_export(findings, config.fail_on, config.fail_on_unscanned) and not allow_findings:
        raise MugError(
            "Secret-like or unscanned content was detected. Review `mug scan`, baseline reviewed "
            "findings with `mug scan --update-baseline`, or pass --allow-findings explicitly."
        )
    destination.mkdir(parents=True, exist_ok=True)
    copy_items = [(rel, source / rel) for rel in hashes]
    total = len(copy_items)
    for index, (rel, source_path) in enumerate(copy_items, start=1):
        if on_progress is not None:
            on_progress(index, total, rel)
        if sha256_file(source_path) != hashes[rel]:
            raise MugError(f"Source changed during workspace creation: {rel}. Re-run the command.")
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target, follow_symlinks=False)
        copy_mode(source_path, target)

    workspace_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()
    source_digest = _canonical_source_files_digest(hashes)
    git_head = git_rev_parse(source)
    public_manifest = {
        "format": 2,
        "workspace_id": workspace_id,
        "project_name": source.name,
        "created_at": created_at,
        "source_files": hashes,
        "source_files_sha256": source_digest,
        "excluded_count": len(excluded),
        "git_head": git_head,
    }
    write_json(destination / MANIFEST_NAME, public_manifest)
    (destination / WORKSPACE_ID_NAME).write_text(workspace_id + "\n", encoding="utf-8")

    registry = state_dir() / "workspaces" / f"{workspace_id}.json"
    write_json(
        registry,
        {
            "format": 2,
            "workspace_id": workspace_id,
            "source_root": str(source),
            "workspace_root": str(destination),
            "created_at": created_at,
            # Sealed outside the agent-writable workspace. Apply trusts only this copy.
            "source_files": hashes,
            "source_files_sha256": source_digest,
            "git_head": git_head,
        },
        private=True,
    )
    return {
        "workspace": str(destination),
        "workspace_id": workspace_id,
        "files": len(hashes),
        "excluded": len(excluded),
        "findings": [finding.to_dict() for finding in findings],
    }


def create_pack(
    source: Path,
    output: Path,
    config: Config,
    allow_findings: bool = False,
    on_progress: ProgressCb | None = None,
) -> dict[str, object]:
    source = source.resolve()
    output = output.expanduser().resolve()
    hashes, excluded = build_manifest(source, config, on_progress=on_progress)
    findings = scan_tree(source, config, on_progress=on_progress, baseline=load_baseline(source))
    if blocks_export(findings, config.fail_on, config.fail_on_unscanned) and not allow_findings:
        raise MugError(
            "Secret-like or unscanned content was detected. Export stopped. Review `mug scan` or "
            "baseline reviewed findings with `mug scan --update-baseline`."
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise MugError(
            f"Output already exists: {output}. "
            "Choose a new -o path or remove the existing ZIP first."
        )
    temp = output.with_suffix(output.suffix + ".tmp")
    try:
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            pack_items = [(rel, source_path) for rel, source_path in iter_regular_files(source) if rel in hashes]
            total = len(pack_items)
            for index, (rel, source_path) in enumerate(pack_items, start=1):
                if on_progress is not None:
                    on_progress(index, total, rel)
                if sha256_file(source_path) != hashes[rel]:
                    raise MugError(f"Source changed during ZIP creation: {rel}. Re-run the command.")
                archive.write(source_path, arcname=f"{source.name}/{rel}")
            export_manifest = {
                "format": 2,
                "project_name": source.name,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "files": hashes,
                "files_sha256": _canonical_source_files_digest(hashes),
                "excluded_count": len(excluded),
            }
            archive.writestr(f"{source.name}/MUG_EXPORT_MANIFEST.json", json.dumps(export_manifest, indent=2) + "\n")
        os.replace(temp, output)
    finally:
        temp.unlink(missing_ok=True)
    return {
        "output": str(output),
        "files": len(hashes),
        "excluded": len(excluded),
        "findings": [finding.to_dict() for finding in findings],
    }


def resolve_workspace(workspace: Path) -> tuple[Path, Path, dict[str, object]]:
    workspace = workspace.expanduser().resolve()
    manifest_path = workspace / MANIFEST_NAME
    id_path = workspace / WORKSPACE_ID_NAME
    if not manifest_path.exists() or not id_path.exists():
        raise MugError(
            f"Not a Model Upload Guard workspace: {workspace}. "
            "Create one with: mug workspace <project> -o <path-outside-repo>"
        )
    workspace_id = id_path.read_text(encoding="utf-8").strip()
    if not workspace_id or any(ch for ch in workspace_id if ch not in "0123456789abcdef"):
        raise MugError("Workspace id is invalid")
    registry_path = state_dir() / "workspaces" / f"{workspace_id}.json"
    if not registry_path.exists():
        raise MugError("Workspace registry is missing. Recreate the workspace from the original repository.")
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    original = Path(str(registry["source_root"])).expanduser().resolve()
    registered_workspace = Path(str(registry["workspace_root"])).expanduser().resolve()
    if registered_workspace != workspace:
        raise MugError("Workspace path does not match its local registry")

    sealed_files = registry.get("source_files")
    sealed_digest = registry.get("source_files_sha256")
    if not isinstance(sealed_files, dict) or not sealed_files:
        raise MugError("Workspace registry is missing sealed source file hashes. Recreate the workspace.")
    sealed_map = {str(key): str(value) for key, value in sealed_files.items()}
    expected = _canonical_source_files_digest(sealed_map)
    if sealed_digest != expected:
        raise MugError("Workspace registry seal is corrupted. Recreate the workspace.")

    # Prefer sealed registry data over the agent-writable workspace manifest.
    public_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    public_files = public_manifest.get("source_files")
    if isinstance(public_files, dict):
        public_map = {str(key): str(value) for key, value in public_files.items()}
        if public_map != sealed_map:
            raise MugError(
                "Workspace manifest was tampered with. Apply uses only the sealed local registry; "
                "recreate the workspace from the original repository."
            )

    sealed_manifest = {
        "format": int(registry.get("format", 2)),
        "workspace_id": workspace_id,
        "project_name": str(public_manifest.get("project_name", original.name)),
        "created_at": str(registry.get("created_at", "")),
        "source_files": sealed_map,
        "source_files_sha256": expected,
        "excluded_count": public_manifest.get("excluded_count", 0),
        "git_head": registry.get("git_head"),
    }
    return original, workspace, sealed_manifest
