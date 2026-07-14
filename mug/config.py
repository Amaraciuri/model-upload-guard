from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .utils import MugError, normalize_rel


# Always enforced. Cannot be removed by project or user config.
IMMUTABLE_EXCLUDES = [
    ".git",
    ".hg",
    ".svn",
    ".mug",
    ".mug.toml",
    ".mug-id",
    ".mug-manifest.json",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "id_rsa*",
    "id_ed25519*",
    "credentials.json",
    "service-account*.json",
    "*serviceAccount*.json",
    "firebase-adminsdk*.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    "auth.json",
    "wp-config.php",
    "wp-config-*.php",
    "GoogleService-Info.plist",
    "google-services.json",
    "*.keystore",
    "*.mobileprovision",
    "*.tfstate",
    "*.tfstate.*",
    "secrets.json",
    "secrets.yml",
    "secrets.yaml",
    ".aws",
    ".ssh",
    ".gnupg",
]

# Removable only with allow_weaken_defaults = true.
DEFAULT_EXCLUDES = [
    *IMMUTABLE_EXCLUDES,
    "*.zip",
    "*.tar",
    "*.tar.gz",
    "*.tgz",
    "*.7z",
    "*.rar",
    "*.log",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.webp",
    "*.ico",
    "*.pdf",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.otf",
    "*.mp3",
    "*.mp4",
    "*.mov",
    "*.wasm",
    "*.so",
    "*.dylib",
    "*.dll",
    "*.exe",
    "*.bin",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    "target",
    "*.sqlite",
    "*.sqlite3",
    "*.db",
]

IMMUTABLE_PROTECTED = [
    ".git",
    ".git/**",
    ".mug.toml",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    ".ssh",
    ".ssh/**",
    ".aws",
    ".aws/**",
    ".gnupg",
    ".gnupg/**",
    "credentials.json",
    "service-account*.json",
    "*serviceAccount*.json",
    "firebase-adminsdk*.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    "auth.json",
    "wp-config.php",
    "wp-config-*.php",
    "*.keystore",
    "*.tfstate",
    "*.tfstate.*",
    "secrets.json",
    "secrets.yml",
    "secrets.yaml",
]

PROTECTED_PATTERNS = list(IMMUTABLE_PROTECTED)

DEFAULT_CONFIG_TEXT = """# Model Upload Guard configuration
# Security defaults are always enforced. Lists below only ADD patterns.
# Use exclude_remove / protected_remove only with allow_weaken_defaults = true.

[scan]
max_file_bytes = 1048576
fail_on = "high"
fail_on_unscanned = true
entropy_threshold = 4.5
entropy_min_length = 32

[export]
# Additive only. Immutable secret/credential patterns cannot be removed.
exclude_add = []
exclude_remove = []
allow_weaken_defaults = false

[apply]
max_changes = 200
max_delete_ratio = 0.05
protected_add = []
protected_remove = []

[sandbox]
engine = "auto"
image = "python:3.12-alpine"
network = false
memory = "2g"
cpus = "2"
pids_limit = 256
user = "65534:65534"
read_only_root = true
"""


@dataclass(slots=True)
class Config:
    max_file_bytes: int = 1024 * 1024
    fail_on: str = "high"
    fail_on_unscanned: bool = True
    entropy_threshold: float = 4.5
    entropy_min_length: int = 32
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    max_changes: int = 200
    max_delete_ratio: float = 0.05
    protected: list[str] = field(default_factory=lambda: list(PROTECTED_PATTERNS))
    allow_weaken_defaults: bool = False
    sandbox_engine: str = "auto"
    sandbox_image: str = "python:3.12-alpine"
    sandbox_network: bool = False
    sandbox_memory: str = "2g"
    sandbox_cpus: str = "2"
    sandbox_pids_limit: int = 256
    sandbox_user: str = "65534:65534"
    sandbox_read_only_root: bool = True


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise MugError(f"Configuration section [{name}] must be a table")
    return value


def _as_str_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise MugError(f"{label} must be a list of strings")
    return list(value)


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _resolve_pattern_list(
    *,
    base: list[str],
    immutable: list[str],
    legacy_replace: list[str] | None,
    additions: list[str],
    removals: list[str],
    allow_weaken: bool,
    label: str,
) -> list[str]:
    """Build a fail-closed pattern list.

    - Immutable patterns are always present.
    - `exclude` / `protected` legacy keys ADD to defaults (never replace).
    - Removals require allow_weaken_defaults and cannot touch immutable patterns.
    """
    if removals and not allow_weaken:
        raise MugError(
            f"{label}_remove requires export.allow_weaken_defaults = true "
            "(security defaults are fail-closed)"
        )
    immutable_set = set(immutable)
    blocked = [pattern for pattern in removals if pattern in immutable_set]
    if blocked:
        raise MugError(
            f"Refusing to remove immutable {label} patterns: {', '.join(blocked)}"
        )

    combined = list(base)
    if legacy_replace is not None:
        # Historical configs used full replacement lists. Treat them as additive
        # so a short list cannot accidentally re-export secrets.
        combined.extend(legacy_replace)
    combined.extend(additions)
    if allow_weaken and removals:
        removal_set = set(removals)
        combined = [pattern for pattern in combined if pattern not in removal_set]
    combined.extend(immutable)
    return _unique(combined)


def load_config(root: Path) -> Config:
    candidates = [Path.home() / ".config" / "mug" / "config.toml", root / ".mug.toml"]
    data: dict[str, Any] = {}
    for candidate in candidates:
        if candidate.exists():
            try:
                parsed = tomllib.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError) as exc:
                raise MugError(f"Cannot read configuration {candidate}: {exc}") from exc
            data = _deep_merge(data, parsed)

    scan = _section(data, "scan")
    export = _section(data, "export")
    apply = _section(data, "apply")
    sandbox = _section(data, "sandbox")

    allow_weaken = bool(export.get("allow_weaken_defaults", False))
    legacy_exclude = export.get("exclude")
    legacy_protected = apply.get("protected")

    exclude = _resolve_pattern_list(
        base=list(DEFAULT_EXCLUDES),
        immutable=list(IMMUTABLE_EXCLUDES),
        legacy_replace=_as_str_list(legacy_exclude, "export.exclude") if legacy_exclude is not None else None,
        additions=_as_str_list(export.get("exclude_add"), "export.exclude_add"),
        removals=_as_str_list(export.get("exclude_remove"), "export.exclude_remove"),
        allow_weaken=allow_weaken,
        label="exclude",
    )
    protected = _resolve_pattern_list(
        base=list(PROTECTED_PATTERNS),
        immutable=list(IMMUTABLE_PROTECTED),
        legacy_replace=_as_str_list(legacy_protected, "apply.protected") if legacy_protected is not None else None,
        additions=_as_str_list(apply.get("protected_add"), "apply.protected_add"),
        removals=_as_str_list(apply.get("protected_remove"), "apply.protected_remove"),
        allow_weaken=bool(apply.get("allow_weaken_defaults", allow_weaken)),
        label="protected",
    )

    config = Config(
        max_file_bytes=int(scan.get("max_file_bytes", 1024 * 1024)),
        fail_on=str(scan.get("fail_on", "high")).lower(),
        fail_on_unscanned=bool(scan.get("fail_on_unscanned", True)),
        entropy_threshold=float(scan.get("entropy_threshold", 4.5)),
        entropy_min_length=int(scan.get("entropy_min_length", 32)),
        exclude=exclude,
        max_changes=int(apply.get("max_changes", 200)),
        max_delete_ratio=float(apply.get("max_delete_ratio", 0.05)),
        protected=protected,
        allow_weaken_defaults=allow_weaken,
        sandbox_engine=str(sandbox.get("engine", "auto")),
        sandbox_image=str(sandbox.get("image", "python:3.12-alpine")),
        sandbox_network=bool(sandbox.get("network", False)),
        sandbox_memory=str(sandbox.get("memory", "2g")),
        sandbox_cpus=str(sandbox.get("cpus", "2")),
        sandbox_pids_limit=int(sandbox.get("pids_limit", 256)),
        sandbox_user=str(sandbox.get("user", "65534:65534")),
        sandbox_read_only_root=bool(sandbox.get("read_only_root", True)),
    )
    if config.fail_on not in {"low", "medium", "high", "critical"}:
        raise MugError("scan.fail_on must be low, medium, high, or critical")
    if config.max_changes < 1:
        raise MugError("apply.max_changes must be positive")
    if not 0 <= config.max_delete_ratio <= 1:
        raise MugError("apply.max_delete_ratio must be between 0 and 1")
    if config.entropy_min_length < 16:
        raise MugError("scan.entropy_min_length must be at least 16")
    if config.entropy_threshold < 3.0:
        raise MugError("scan.entropy_threshold must be at least 3.0")
    if config.sandbox_network:
        # Keep allowed, but fail closed unless the user opted in explicitly in config.
        pass
    return config


def _deep_merge(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    result = dict(left)
    for key, value in right.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def path_matches(rel: str, patterns: list[str]) -> bool:
    rel_norm = normalize_rel(rel)
    if not rel_norm:
        return False
    parts = rel_norm.split("/")
    basename = parts[-1]
    for raw_pattern in patterns:
        pattern = str(raw_pattern).replace("\\", "/").strip("/")
        if not pattern:
            continue
        if fnmatch.fnmatchcase(rel_norm, pattern) or fnmatch.fnmatchcase(basename, pattern):
            return True
        if "/" not in pattern and any(fnmatch.fnmatchcase(part, pattern) for part in parts):
            return True
        if pattern.endswith("/**"):
            prefix = pattern[:-3].rstrip("/")
            if rel_norm == prefix or rel_norm.startswith(prefix + "/"):
                return True
    return False
