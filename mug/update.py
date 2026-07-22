"""Self-update from GitHub (explicit user action; no automatic phoning home)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

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


def _download(url: str, destination: Path, timeout: float = 60.0) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": f"mug/{__version__}"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        destination.write_bytes(response.read())


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_source_sha(sums_text: str) -> str | None:
    for line in sums_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+)$", line)
        if not match:
            continue
        digest, name = match.group(1).lower(), match.group(2).strip()
        base = Path(name).name
        if base == "source.zip" or name.endswith("SOURCE_ARCHIVE") or "SOURCE_ARCHIVE" in name:
            return digest
    return None


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


def self_update(ref: str | None = None, *, allow_unverified: bool = False) -> dict[str, object]:
    target = ref or latest_tag() or "v0.3.4"
    source_url = f"https://github.com/{_repo()}/releases/download/{target}/source.zip"
    sums_url = f"https://github.com/{_repo()}/releases/download/{target}/SHA256SUMS.txt"
    archive_url = f"https://github.com/{_repo()}/archive/{target}.zip"
    verified = False
    install_path: Path | None = None

    with tempfile.TemporaryDirectory(prefix="mug-update-") as tmp:
        tmp_root = Path(tmp)
        archive = tmp_root / "source.zip"
        sums = tmp_root / "SHA256SUMS.txt"
        try:
            _download(sums_url, sums)
            _download(source_url, archive)
            expected = _expected_source_sha(sums.read_text(encoding="utf-8", errors="replace"))
            if not expected:
                raise MugError(f"SHA256SUMS.txt for {target} has no source.zip / SOURCE_ARCHIVE entry.")
            actual = _sha256_file(archive)
            if actual != expected:
                raise MugError(
                    f"SHA256 mismatch for {target}/source.zip "
                    f"(expected {expected}, got {actual})."
                )
            verified = True
            install_path = archive
            install_url = source_url
        except (urllib.error.URLError, OSError, MugError) as exc:
            if not allow_unverified:
                raise MugError(
                    f"Verified update failed for {target}: {exc}. "
                    "Re-run with --allow-unverified to use the git archive ZIP (not checksum-backed)."
                ) from exc
            archive_fallback = tmp_root / "archive.zip"
            _download(archive_url, archive_fallback)
            install_path = archive_fallback
            install_url = archive_url

        assert install_path is not None
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet", str(install_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise MugError(f"Update failed for {install_url}:\n{detail}")

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
        "source": install_url,
        "verified": verified,
    }
