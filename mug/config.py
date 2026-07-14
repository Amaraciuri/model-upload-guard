from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .utils import MugError, normalize_rel


DEFAULT_EXCLUDES = [
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
    "*.zip",
    "*.tar",
    "*.tar.gz",
    "*.tgz",
    "*.7z",
    "*.rar",
    "*.log",
    ".aws",
    ".ssh",
    ".gnupg",
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

PROTECTED_PATTERNS = [
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

DEFAULT_CONFIG_TEXT = """# Model Upload Guard configuration
# Deny-by-default: sensitive files are excluded and secret-like content blocks export.

[scan]
max_file_bytes = 1048576
fail_on = "high"

[export]
exclude = [
  ".git", ".hg", ".svn", ".mug", ".mug.toml", ".mug-id", ".mug-manifest.json",
  ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks",
  "id_rsa*", "id_ed25519*", "credentials.json", "service-account*.json",
  "*serviceAccount*.json", "firebase-adminsdk*.json", ".npmrc", ".pypirc", ".netrc",
  ".git-credentials", "auth.json", "wp-config.php", "wp-config-*.php",
  "GoogleService-Info.plist", "google-services.json", "*.keystore", "*.mobileprovision",
  "*.tfstate", "*.tfstate.*", "secrets.json", "secrets.yml", "secrets.yaml",
  "*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.7z", "*.rar", "*.log",
  ".aws", ".ssh", ".gnupg",
  "node_modules", "vendor", ".venv", "venv", "__pycache__", ".pytest_cache",
  ".mypy_cache", ".ruff_cache", "dist", "build", ".next", ".nuxt",
  "coverage", "target", "*.sqlite", "*.sqlite3", "*.db"
]

[apply]
max_changes = 200
max_delete_ratio = 0.05
protected = [
  ".git", ".git/**", ".mug.toml", ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx",
  "*.jks", ".ssh", ".ssh/**", ".aws", ".aws/**", ".gnupg", ".gnupg/**",
  "credentials.json", "service-account*.json", "*serviceAccount*.json",
  "firebase-adminsdk*.json", ".npmrc", ".pypirc", ".netrc", ".git-credentials",
  "auth.json", "wp-config.php", "wp-config-*.php", "*.keystore", "*.tfstate",
  "*.tfstate.*", "secrets.json", "secrets.yml", "secrets.yaml"
]

[sandbox]
engine = "auto"
image = "python:3.12-alpine"
network = false
memory = "2g"
cpus = "2"
pids_limit = 256
"""


@dataclass(slots=True)
class Config:
    max_file_bytes: int = 1024 * 1024
    fail_on: str = "high"
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    max_changes: int = 200
    max_delete_ratio: float = 0.05
    protected: list[str] = field(default_factory=lambda: list(PROTECTED_PATTERNS))
    sandbox_engine: str = "auto"
    sandbox_image: str = "python:3.12-alpine"
    sandbox_network: bool = False
    sandbox_memory: str = "2g"
    sandbox_cpus: str = "2"
    sandbox_pids_limit: int = 256


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise MugError(f"Configuration section [{name}] must be a table")
    return value


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

    config = Config(
        max_file_bytes=int(scan.get("max_file_bytes", 1024 * 1024)),
        fail_on=str(scan.get("fail_on", "high")).lower(),
        exclude=list(export.get("exclude", DEFAULT_EXCLUDES)),
        max_changes=int(apply.get("max_changes", 200)),
        max_delete_ratio=float(apply.get("max_delete_ratio", 0.05)),
        protected=list(apply.get("protected", PROTECTED_PATTERNS)),
        sandbox_engine=str(sandbox.get("engine", "auto")),
        sandbox_image=str(sandbox.get("image", "python:3.12-alpine")),
        sandbox_network=bool(sandbox.get("network", False)),
        sandbox_memory=str(sandbox.get("memory", "2g")),
        sandbox_cpus=str(sandbox.get("cpus", "2")),
        sandbox_pids_limit=int(sandbox.get("pids_limit", 256)),
    )
    if config.fail_on not in {"low", "medium", "high", "critical"}:
        raise MugError("scan.fail_on must be low, medium, high, or critical")
    if config.max_changes < 1:
        raise MugError("apply.max_changes must be positive")
    if not 0 <= config.max_delete_ratio <= 1:
        raise MugError("apply.max_delete_ratio must be between 0 and 1")
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
