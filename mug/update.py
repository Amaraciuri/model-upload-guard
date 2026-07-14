"""Self-update from GitHub (explicit user action; no automatic phoning home)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

from . import __version__
from .utils import MugError

DEFAULT_REPO = "Amaraciuri/model-upload-guard"


def _repo() -> str:
    return os.environ.get("MUG_REPO", DEFAULT_REPO)


def _get_json(url: str, timeout: float = 10.0) -> object:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"mug/{__version__}",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def latest_tag() -> str | None:
    """Latest release tag, falling back to the newest plain tag."""
    base = f"https://api.github.com/repos/{_repo()}"
    try:
        data = _get_json(f"{base}/releases/latest")
        if isinstance(data, dict) and data.get("tag_name"):
            return str(data["tag_name"])
    except (urllib.error.URLError, OSError, ValueError):
        pass
    try:
        data = _get_json(f"{base}/tags")
        if isinstance(data, list) and data and isinstance(data[0], dict) and data[0].get("name"):
            return str(data[0]["name"])
    except (urllib.error.URLError, OSError, ValueError):
        pass
    return None


def parse_version(value: str) -> tuple[int, ...] | None:
    raw = value.strip().lstrip("vV")
    parts = raw.split(".")
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        return None


def is_newer(candidate: str, current: str) -> bool:
    candidate_v = parse_version(candidate)
    current_v = parse_version(current)
    if candidate_v is None or current_v is None:
        return False
    return candidate_v > current_v


def check_update() -> dict[str, object]:
    tag = latest_tag()
    if tag is None:
        raise MugError(
            f"Could not reach GitHub to check releases for {_repo()}. "
            "Check your network connection."
        )
    return {
        "current": __version__,
        "latest": tag,
        "update_available": is_newer(tag, __version__),
    }


def self_update(ref: str | None = None) -> dict[str, object]:
    target = ref or latest_tag() or "main"
    url = f"https://github.com/{_repo()}/archive/{target}.zip"
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet", url],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise MugError(f"Update failed for {url}:\n{detail}")
    # Query the freshly installed code in a new interpreter; this process
    # keeps running the old version until restarted.
    version_probe = subprocess.run(
        [sys.executable, "-m", "mug", "--version"],
        capture_output=True,
        text=True,
    )
    new_version = (version_probe.stdout or "").strip().removeprefix("mug ").strip()
    return {
        "previous": __version__,
        "installed": new_version or "unknown",
        "ref": target,
    }
