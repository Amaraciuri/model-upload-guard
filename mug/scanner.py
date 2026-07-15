from __future__ import annotations

import math
import re
import shutil
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable

from .baseline import make_fingerprint
from .config import Config, path_matches
from .utils import is_binary, iter_regular_files, sha256_file

ProgressCb = Callable[[int, int, str], None]


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Findings that never block export (file is excluded from pack/workspace anyway).
NON_BLOCKING_RULES = frozenset({"sensitive-filename"})


@dataclass(slots=True)
class Finding:
    severity: str
    rule: str
    path: str
    line: int | None
    message: str
    excerpt: str = ""
    fingerprint: str = ""
    baselined: bool = False
    allowlisted: bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


CONTENT_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    # Use -{5} so this source file does not contain literal PEM headers (self-scan noise).
    ("critical", "private-key", re.compile(r"-{5}BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-{5}"), "Private key material"),
    ("critical", "pgp-private-key", re.compile(r"-{5}BEGIN PGP PRIVATE KEY BLOCK-{5}"), "PGP private key material"),
    ("critical", "aws-secret", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{32,}"), "AWS secret access key"),
    ("high", "aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "AWS access key ID"),
    ("high", "github-token", re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{30,255}\b"), "GitHub token"),
    ("high", "github-pat-fine", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "GitHub fine-grained PAT"),
    ("high", "openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "OpenAI-style API key"),
    ("high", "anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "Anthropic API key"),
    ("high", "xai-key", re.compile(r"\bxai-[A-Za-z0-9_-]{20,}\b"), "xAI API key"),
    ("high", "groq-key", re.compile(r"\bgsk_[A-Za-z0-9_]{20,}\b"), "Groq API key"),
    ("high", "huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"), "Hugging Face token"),
    ("high", "gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "GitLab token"),
    ("high", "npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"), "npm access token"),
    ("high", "google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "Google API key"),
    ("high", "slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    ("high", "slack-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"), "Slack webhook URL"),
    ("high", "stripe-secret", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), "Stripe secret key"),
    ("high", "telegram-bot", re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b"), "Telegram bot token"),
    ("high", "discord-token", re.compile(r"\b[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b"), "Discord bot token"),
    ("high", "azure-storage-key", re.compile(r"(?i)AccountKey=[A-Za-z0-9+/=]{40,}"), "Azure storage account key"),
    ("high", "sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), "SendGrid API key"),
    ("high", "twilio-sid", re.compile(r"\bAC[a-f0-9]{32}\b"), "Twilio account SID"),
    ("high", "vercel-token", re.compile(r"\bvercel_[A-Za-z0-9_]{24,}\b"), "Vercel token"),
    ("high", "supabase-key", re.compile(r"\bsb[pa]_[A-Za-z0-9_-]{20,}\b"), "Supabase API key"),
    ("high", "railway-token", re.compile(r"\brailway_[A-Za-z0-9_]{20,}\b"), "Railway API token"),
    ("high", "cloudflare-token", re.compile(r"(?i)\b(?:cloudflare|cf)_?(?:api[_-]?)?(?:token|key)\b\s*[:=]\s*['\"]?[A-Za-z0-9_-]{30,}"), "Cloudflare API token"),
    ("high", "firebase-api-key", re.compile(r"(?i)firebase[_-]?(?:api)?[_-]?key\s*[:=]\s*['\"]?AIza[0-9A-Za-z_-]{30,}"), "Firebase API key assignment"),
    ("high", "digitalocean-token", re.compile(r"\bdop_v1_[a-f0-9]{64}\b"), "DigitalOcean personal access token"),
    ("high", "jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "JSON Web Token"),
    ("high", "bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{20,}\b"), "Bearer token"),
    ("high", "database-url", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|rediss)://[^\s:@/]+:[^\s@/]+@"), "Database URL with embedded credentials"),
    ("high", "generic-api-assignment", re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*['\"][^'\"\n]{12,}['\"]"), "Hard-coded API credential assignment"),
    ("medium", "password-assignment", re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token)\b\s*[:=]\s*['\"][^'\"\n]{8,}['\"]"), "Possible hard-coded credential"),
]

# High-entropy token candidates (base64/hex-ish blobs).
ENTROPY_CANDIDATE = re.compile(r"""(?:"|'|=|:|\s|^)([A-Za-z0-9+/=_-]{32,})(?:"|'|\s|$|,|;)""")

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

# Paths that often contain intentional high-entropy fixtures; still reported low unless other rules hit.
ALLOWLIST_PATH_HINTS = (
    "test",
    "tests",
    "spec",
    "fixtures",
    "testdata",
    "mock",
    "__mocks__",
)

# Dependency lockfiles / checksum manifests: high-entropy by design, not secrets.
LOCKFILE_BASENAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
        "bun.lock",
        "bun.lockb",
        "cargo.lock",
        "poetry.lock",
        "composer.lock",
        "gemfile.lock",
        "go.sum",
        "go.mod",
        "pipfile.lock",
        "uv.lock",
        "flake.lock",
        "gradle.lockfile",
        "package-lock.yaml",
    }
)

# Lines that are package integrity / checksum fields (npm, yarn, cargo, go.sum, etc.).
CHECKSUM_LINE = re.compile(
    r"""(?ix)
    ^\s*
    (?:
        ["']?integrity["']?\s*[:=]
      | ["']?checksum["']?\s*[:=]
      | ["']?sha(?:1|256|512)["']?\s*[:=]
      | hash\s*=
      | digest\s*=
    )
    |
    \bsha(?:1|256|512)-[A-Za-z0-9+/=_-]{20,}
    |
    \bh1:[A-Za-z0-9+/=_-]{20,}
    """
)



def scan_tree(
    root: Path,
    config: Config,
    include_excluded_names: bool = True,
    on_progress: ProgressCb | None = None,
    baseline: set[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    exportable: list[str] = []
    files = list(iter_regular_files(root))
    total = len(files)
    for index, (rel, path) in enumerate(files, start=1):
        if on_progress is not None:
            on_progress(index, total, rel)
        excluded = path_matches(rel, config.exclude)
        if include_excluded_names and path_matches(rel, SENSITIVE_NAME_PATTERNS):
            findings.append(
                Finding(
                    "high",
                    "sensitive-filename",
                    rel,
                    None,
                    "Sensitive file is present and will be excluded",
                    fingerprint=make_fingerprint("sensitive-filename", rel, ""),
                )
            )
        if excluded:
            continue
        exportable.append(rel)
        findings.extend(scan_file(rel, path, config))
    findings.extend(_gitignored_findings(root, exportable))
    if config.allowlist_paths:
        for finding in findings:
            if path_matches(finding.path, config.allowlist_paths):
                finding.allowlisted = True
    if baseline:
        for finding in findings:
            if finding.fingerprint and finding.fingerprint in baseline:
                finding.baselined = True
    return findings


def _gitignored_findings(root: Path, exportable: list[str]) -> list[Finding]:
    """Warn about gitignored files that would still be exported.

    Gitignored files are often local-only configuration and are a common place
    for secrets that never appear in Git history. Best effort: requires the
    `git` binary and a `.git` directory; silent otherwise.
    """
    if not exportable or not (root / ".git").exists() or not shutil.which("git"):
        return []
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "--stdin", "-z"],
            input=b"\x00".join(rel.encode("utf-8") for rel in exportable) + b"\x00",
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode not in {0, 1}:
        return []
    ignored = [item for item in proc.stdout.decode("utf-8", errors="replace").split("\x00") if item]
    return [
        Finding(
            "medium",
            "gitignored-file",
            rel,
            None,
            "Gitignored file would still be exported; add it to export.exclude_add if it is local-only",
            fingerprint=make_fingerprint("gitignored-file", rel, ""),
        )
        for rel in ignored
    ]


def scan_file(rel: str, path: Path, config: Config) -> list[Finding]:
    try:
        size = path.stat().st_size
    except OSError:
        return [
            Finding(
                "medium",
                "unreadable-file",
                rel,
                None,
                "File could not be read",
                fingerprint=make_fingerprint("unreadable-file", rel, ""),
            )
        ]

    if is_binary(path):
        # Fingerprint binds the exact file content: if the binary changes,
        # a baselined acceptance stops matching and blocks again.
        return [
            Finding(
                "high",
                "unscanned-binary",
                rel,
                None,
                "Binary file skipped by content scanner; refused for export by default",
                fingerprint=make_fingerprint("unscanned-binary", rel, _safe_file_hash(path)),
            )
        ]
    if size > config.max_file_bytes:
        tip = (
            "Raise scan.max_file_bytes or add the path to export.exclude_add if it is safe "
            "source that AI needs; otherwise keep it out of packs/workspaces."
        )
        return [
            Finding(
                "high",
                "unscanned-large",
                rel,
                None,
                f"File exceeds scan limit ({config.max_file_bytes} bytes); refused for export by default. {tip}",
                fingerprint=make_fingerprint("unscanned-large", rel, _safe_file_hash(path)),
            )
        ]

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [
            Finding(
                "medium",
                "unreadable-file",
                rel,
                None,
                "File could not be read",
                fingerprint=make_fingerprint("unreadable-file", rel, ""),
            )
        ]

    findings: list[Finding] = []
    custom_rules = [
        (rule.severity, rule.rule, re.compile(rule.pattern), rule.message)
        for rule in config.rules_add
    ]
    for line_no, line in enumerate(text.splitlines(), start=1):
        for severity, rule, pattern, message in CONTENT_RULES:
            match = pattern.search(line)
            if match:
                excerpt = _redact(line.strip(), match.start(), match.end())
                material = line[match.start() : match.end()]
                findings.append(
                    Finding(
                        severity,
                        rule,
                        rel,
                        line_no,
                        message,
                        excerpt,
                        fingerprint=make_fingerprint(rule, rel, material),
                    )
                )
        for severity, rule, pattern, message in custom_rules:
            match = pattern.search(line)
            if match:
                excerpt = _redact(line.strip(), match.start(), match.end())
                material = line[match.start() : match.end()]
                findings.append(
                    Finding(
                        severity,
                        rule,
                        rel,
                        line_no,
                        message,
                        excerpt,
                        fingerprint=make_fingerprint(rule, rel, material),
                    )
                )
        findings.extend(_entropy_findings(rel, line_no, line, config))
    return findings


def _safe_file_hash(path: Path) -> str:
    try:
        return sha256_file(path)
    except OSError:
        return ""


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_like_secret_blob(token: str) -> bool:
    if len(token) < 32:
        return False
    # Base64 padding is only trailing '=' / '=='; reject KEY=VALUE-style matches.
    if "=" in token.rstrip("="):
        return False
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    has_digit = any(c.isdigit() for c in token)
    # Reject obvious words / paths / uuids-ish low mix.
    if token.count("-") > max(3, len(token) // 8) and "/" not in token and "+" not in token:
        return False
    # Pure letter identifiers with underscores (config constants) are not secret blobs.
    core = token.rstrip("=")
    if core.replace("_", "").isalpha() and not has_digit and "+" not in token and "/" not in token:
        return False
    return (has_digit and (has_upper or has_lower)) or ("+" in token or "/" in token or "_" in token)


def _path_looks_like_fixture(rel: str) -> bool:
    lowered = rel.lower().replace("\\", "/")
    return any(f"/{hint}/" in f"/{lowered}/" or lowered.startswith(f"{hint}/") for hint in ALLOWLIST_PATH_HINTS)


def _basename(rel: str) -> str:
    return rel.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _is_lockfile(rel: str) -> bool:
    return _basename(rel) in LOCKFILE_BASENAMES


def _is_checksum_noise(rel: str, line: str) -> bool:
    if _is_lockfile(rel):
        return True
    if CHECKSUM_LINE.search(line):
        return True
    # Gradle wrapper distribution checksums / URL hashes
    if "gradle" in rel.lower().replace("\\", "/") and "sha256" in line.lower():
        return True
    return False


def _entropy_findings(rel: str, line_no: int, line: str, config: Config) -> list[Finding]:
    if _is_checksum_noise(rel, line):
        return []
    findings: list[Finding] = []
    for match in ENTROPY_CANDIDATE.finditer(line):
        token = match.group(1)
        if len(token) < config.entropy_min_length or not _looks_like_secret_blob(token):
            continue
        # npm-style integrity prefixes
        if token.startswith(("sha256-", "sha512-", "sha1-", "h1:")):
            continue
        entropy = _shannon_entropy(token)
        if entropy < config.entropy_threshold:
            continue
        severity = "medium" if _path_looks_like_fixture(rel) else "high"
        start = match.start(1)
        end = match.end(1)
        findings.append(
            Finding(
                severity,
                "high-entropy",
                rel,
                line_no,
                f"High-entropy string (entropy={entropy:.2f}); possible secret",
                _redact(line.strip(), start, end),
                fingerprint=make_fingerprint("high-entropy", rel, token),
            )
        )
    return findings


def _redact(line: str, start: int, end: int) -> str:
    if len(line) > 180:
        line = line[:177] + "..."
    safe_start = min(start, len(line))
    safe_end = min(end, len(line))
    return line[:safe_start] + "[REDACTED]" + line[safe_end:]


def blocks_export(findings: Iterable[Finding], fail_on: str, fail_on_unscanned: bool = True) -> bool:
    threshold = SEVERITY_ORDER[fail_on]
    for finding in findings:
        if finding.baselined or finding.allowlisted:
            continue
        if finding.rule in NON_BLOCKING_RULES:
            continue
        if finding.rule in {"unscanned-binary", "unscanned-large"} and not fail_on_unscanned:
            continue
        if SEVERITY_ORDER[finding.severity] >= threshold:
            return True
    return False
