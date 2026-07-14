from __future__ import annotations

import json
import os
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .config import Config, path_matches
from .scanner import Finding, blocks_export, scan_tree
from .utils import MugError, copy_mode, iter_regular_files, sha256_file, state_dir, write_json

MANIFEST_NAME = ".mug-manifest.json"
WORKSPACE_ID_NAME = ".mug-id"


def build_manifest(root: Path, config: Config) -> tuple[dict[str, str], list[str]]:
    hashes: dict[str, str] = {}
    excluded: list[str] = []
    for rel, path in iter_regular_files(root):
        if path_matches(rel, config.exclude):
            excluded.append(rel)
            continue
        hashes[rel] = sha256_file(path)
    return hashes, excluded


def create_workspace(source: Path, destination: Path, config: Config, allow_findings: bool = False) -> dict[str, object]:
    source = source.resolve()
    destination = destination.expanduser().resolve()
    if destination == source or source in destination.parents:
        raise MugError("Workspace must be outside the source repository")
    if destination.exists() and any(destination.iterdir()):
        raise MugError(f"Workspace destination is not empty: {destination}")

    hashes, excluded = build_manifest(source, config)
    findings = scan_tree(source, config)
    if blocks_export(findings, config.fail_on) and not allow_findings:
        raise MugError("Secret-like content was detected. Review `mug scan` or pass --allow-findings explicitly.")
    destination.mkdir(parents=True, exist_ok=True)
    for rel, source_path in iter_regular_files(source):
        if rel not in hashes:
            continue
        if sha256_file(source_path) != hashes[rel]:
            raise MugError(f"Source changed during workspace creation: {rel}. Re-run the command.")
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target, follow_symlinks=False)
        copy_mode(source_path, target)

    workspace_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()
    public_manifest = {
        "format": 1,
        "workspace_id": workspace_id,
        "project_name": source.name,
        "created_at": created_at,
        "source_files": hashes,
        "excluded_count": len(excluded),
    }
    write_json(destination / MANIFEST_NAME, public_manifest)
    (destination / WORKSPACE_ID_NAME).write_text(workspace_id + "\n", encoding="utf-8")

    registry = state_dir() / "workspaces" / f"{workspace_id}.json"
    write_json(
        registry,
        {
            "workspace_id": workspace_id,
            "source_root": str(source),
            "workspace_root": str(destination),
            "created_at": created_at,
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


def create_pack(source: Path, output: Path, config: Config, allow_findings: bool = False) -> dict[str, object]:
    source = source.resolve()
    output = output.expanduser().resolve()
    hashes, excluded = build_manifest(source, config)
    findings = scan_tree(source, config)
    if blocks_export(findings, config.fail_on) and not allow_findings:
        raise MugError("Secret-like content was detected. Export stopped. Review `mug scan`.")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise MugError(f"Output already exists: {output}")
    temp = output.with_suffix(output.suffix + ".tmp")
    try:
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for rel, source_path in iter_regular_files(source):
                if rel in hashes:
                    if sha256_file(source_path) != hashes[rel]:
                        raise MugError(f"Source changed during ZIP creation: {rel}. Re-run the command.")
                    archive.write(source_path, arcname=f"{source.name}/{rel}")
            export_manifest = {
                "format": 1,
                "project_name": source.name,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "files": hashes,
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
        raise MugError(f"Not a Model Upload Guard workspace: {workspace}")
    workspace_id = id_path.read_text(encoding="utf-8").strip()
    registry_path = state_dir() / "workspaces" / f"{workspace_id}.json"
    if not registry_path.exists():
        raise MugError("Workspace registry is missing. Recreate the workspace from the original repository.")
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    original = Path(str(registry["source_root"])).expanduser().resolve()
    registered_workspace = Path(str(registry["workspace_root"])).expanduser().resolve()
    if registered_workspace != workspace:
        raise MugError("Workspace path does not match its local registry")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return original, workspace, manifest
