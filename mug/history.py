"""Local last-run history (private, never uploaded)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .utils import project_key, read_json, state_dir, write_json

HISTORY_NAME = "history.json"
MAX_ENTRIES = 40


def history_path() -> Path:
    return state_dir() / HISTORY_NAME


def record_run(
    command: str,
    *,
    root: Path | str | None = None,
    ok: bool = True,
    summary: dict[str, Any] | None = None,
) -> Path:
    """Append a run record to the private local history file."""
    path = history_path()
    entries: list[dict[str, Any]] = []
    if path.exists():
        try:
            payload = read_json(path)
            if isinstance(payload, dict) and isinstance(payload.get("entries"), list):
                entries = [item for item in payload["entries"] if isinstance(item, dict)]
        except Exception:
            entries = []

    root_path = Path(root).expanduser().resolve() if root is not None else None
    entry: dict[str, Any] = {
        "at": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "ok": bool(ok),
        "summary": summary or {},
    }
    if root_path is not None:
        entry["root"] = str(root_path)
        entry["project_key"] = project_key(root_path)

    entries.insert(0, entry)
    entries = entries[:MAX_ENTRIES]
    write_json(path, {"format": 1, "entries": entries}, private=True)
    return path


def load_history(limit: int = 10) -> list[dict[str, Any]]:
    path = history_path()
    if not path.exists():
        return []
    try:
        payload = read_json(path)
    except Exception:
        return []
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        return []
    entries = [item for item in payload["entries"] if isinstance(item, dict)]
    return entries[: max(0, limit)]


def last_run(*, command: str | None = None, root: Path | str | None = None) -> dict[str, Any] | None:
    root_key = project_key(Path(root).expanduser().resolve()) if root is not None else None
    for entry in load_history(limit=MAX_ENTRIES):
        if command is not None and entry.get("command") != command:
            continue
        if root_key is not None and entry.get("project_key") != root_key:
            continue
        return entry
    return None
