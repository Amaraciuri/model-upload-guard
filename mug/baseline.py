"""Per-finding baseline (allowlist).

A baseline records reviewed findings by fingerprint so a single false positive
can be accepted without disabling export blocking globally (`--allow-findings`).
Fingerprints bind rule + path + matched content: if the content changes, the
fingerprint no longer matches and the finding blocks again (fail-closed).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Protocol

from .utils import MugError, read_json, write_json

BASELINE_NAME = ".mug-baseline.json"
BASELINE_FORMAT = 1


class _FindingLike(Protocol):
    fingerprint: str
    rule: str
    path: str
    severity: str


def make_fingerprint(rule: str, path: str, material: str) -> str:
    digest = hashlib.sha256(f"{rule}|{path}|{material}".encode("utf-8")).hexdigest()
    return digest[:32]


def load_baseline(root: Path) -> set[str]:
    baseline_path = root / BASELINE_NAME
    if not baseline_path.is_file():
        return set()
    data = read_json(baseline_path)
    if not isinstance(data, dict) or int(data.get("format", 0)) != BASELINE_FORMAT:
        raise MugError(
            f"Unsupported baseline format: {baseline_path}. "
            f"Delete it and re-run `mug scan --update-baseline` if you still want a baseline."
        )
    entries = data.get("findings", {})
    if not isinstance(entries, dict):
        raise MugError(
            f"Invalid baseline contents: {baseline_path}. "
            "Delete or fix the file, then re-scan."
        )
    return {str(key) for key in entries}


def write_baseline(root: Path, findings: Iterable[_FindingLike]) -> tuple[Path, int]:
    entries: dict[str, dict[str, str]] = {}
    for finding in findings:
        if not finding.fingerprint:
            continue
        entries[finding.fingerprint] = {
            "rule": finding.rule,
            "path": finding.path,
            "severity": finding.severity,
        }
    payload = {
        "format": BASELINE_FORMAT,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "comment": (
            "Findings reviewed and accepted by a human. "
            "Fingerprints bind rule+path+content; edits re-trigger blocking."
        ),
        "findings": dict(sorted(entries.items())),
    }
    baseline_path = root / BASELINE_NAME
    write_json(baseline_path, payload)
    return baseline_path, len(entries)
