from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .config import Config, path_matches
from .utils import is_binary, iter_regular_files


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(slots=True)
class Finding:
    severity: str
    rule: str
    path: str
    line: int | None
    message: str
    excerpt: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


CONTENT_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    ("critical", "private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Private key material"),
    ("critical", "aws-secret", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{32,}"), "AWS secret access key"),
    ("high", "aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "AWS access key ID"),
    ("high", "github-token", re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{30,255}\b"), "GitHub token"),
    ("high", "openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "OpenAI-style API key"),
    ("high", "anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "Anthropic API key"),
    ("high", "xai-key", re.compile(r"\bxai-[A-Za-z0-9_-]{20,}\b"), "xAI API key"),
    ("high", "groq-key", re.compile(r"\bgsk_[A-Za-z0-9_-]{20,}\b"), "Groq API key"),
    ("high", "huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"), "Hugging Face token"),
    ("high", "gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "GitLab token"),
    ("high", "npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"), "npm access token"),
    ("high", "google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "Google API key"),
    ("high", "slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    ("high", "stripe-secret", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), "Stripe secret key"),
    ("high", "jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "JSON Web Token"),
    ("high", "database-url", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s@/]+@"), "Database URL with embedded credentials"),
    ("medium", "password-assignment", re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token)\b\s*[:=]\s*['\"][^'\"\n]{8,}['\"]"), "Possible hard-coded credential"),
]

SENSITIVE_NAME_PATTERNS = [
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
]


def scan_tree(root: Path, config: Config, include_excluded_names: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    for rel, path in iter_regular_files(root):
        excluded = path_matches(rel, config.exclude)
        if include_excluded_names and path_matches(rel, SENSITIVE_NAME_PATTERNS):
            findings.append(Finding("high", "sensitive-filename", rel, None, "Sensitive file is present and will be excluded"))
        if excluded:
            continue
        findings.extend(scan_file(rel, path, config.max_file_bytes))
    return findings


def scan_file(rel: str, path: Path, max_file_bytes: int) -> list[Finding]:
    try:
        size = path.stat().st_size
    except OSError:
        return [Finding("medium", "unreadable-file", rel, None, "File could not be read")]
    if size > max_file_bytes or is_binary(path):
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [Finding("medium", "unreadable-file", rel, None, "File could not be read")]

    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for severity, rule, pattern, message in CONTENT_RULES:
            match = pattern.search(line)
            if match:
                excerpt = _redact(line.strip(), match.start(), match.end())
                findings.append(Finding(severity, rule, rel, line_no, message, excerpt))
    return findings


def _redact(line: str, start: int, end: int) -> str:
    if len(line) > 180:
        line = line[:177] + "..."
    safe_start = min(start, len(line))
    safe_end = min(end, len(line))
    return line[:safe_start] + "[REDACTED]" + line[safe_end:]


def blocks_export(findings: Iterable[Finding], fail_on: str) -> bool:
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[finding.severity] >= threshold and finding.rule != "sensitive-filename" for finding in findings)
