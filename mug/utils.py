from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Iterable


class MugError(RuntimeError):
    """Expected user-facing error."""


def canonical_root(path: str | os.PathLike[str]) -> Path:
    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise MugError(
            f"Path does not exist: {root}. "
            "Pass an existing project directory (e.g. `.` or `./my-app`)."
        )
    if not root.is_dir():
        raise MugError(f"Expected a directory: {root}")
    return root


def normalize_rel(path: str | os.PathLike[str]) -> str:
    """Normalize a relative path without losing leading dots such as `.env`."""
    raw = str(path).replace("\\", "/")
    while raw.startswith("./"):
        raw = raw[2:]
    raw = raw.strip("/")
    if not raw or raw == ".":
        return ""
    parts = raw.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise MugError(f"Unsafe relative path: {path}")
    return "/".join(parts)


def safe_join(root: Path, rel: str) -> Path:
    rel_norm = normalize_rel(rel)
    candidate = (root / rel_norm).resolve(strict=False)
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise MugError(f"Path escapes root: {rel}") from exc
    return candidate


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def project_key(root: Path) -> str:
    return sha256_text(str(root.resolve()))[:16]


def state_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        result = base / "model-upload-guard"
    else:
        base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
        result = base / "model-upload-guard"
    result.mkdir(parents=True, exist_ok=True)
    try:
        result.chmod(0o700)
    except OSError:
        pass
    return result


def install_root() -> Path:
    return Path(
        os.environ.get("MUG_HOME", Path.home() / ".local" / "share" / "model-upload-guard")
    ).expanduser()


def mug_on_path() -> bool:
    return bool(shutil.which("mug"))


def default_mug_bin() -> Path:
    return Path.home() / ".local" / "bin" / "mug"


def atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def write_json(path: Path, payload: Any, private: bool = False) -> None:
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_write(path, data, 0o600 if private else None)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MugError(f"Missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise MugError(f"Invalid JSON in {path}: {exc}") from exc


def is_binary(path: Path, sample_size: int = 8192) -> bool:
    try:
        sample = path.read_bytes()[:sample_size]
    except OSError:
        return True
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    control = sum(1 for byte in sample if byte < 9 or (13 < byte < 32))
    return control / len(sample) > 0.15


def iter_regular_files(root: Path) -> Iterable[tuple[str, Path]]:
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        dirnames[:] = sorted(
            name for name in dirnames if not (current_path / name).is_symlink()
        )
        for filename in sorted(filenames):
            path = current_path / filename
            if path.is_symlink() or not path.is_file():
                continue
            rel = normalize_rel(path.relative_to(root))
            yield rel, path


def copy_mode(source: Path, destination: Path) -> None:
    try:
        source_mode = stat.S_IMODE(source.stat().st_mode)
        os.chmod(destination, source_mode & 0o777)
    except OSError:
        pass
