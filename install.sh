#!/usr/bin/env bash
# Model Upload Guard installer — pinned release + SHA256 verification by default.
set -euo pipefail

REPO="${MUG_REPO:-Amaraciuri/model-upload-guard}"
REF="${MUG_REF:-v0.3.3}"
PYTHON="${PYTHON:-python3}"
INSTALL_ROOT="${MUG_HOME:-${HOME}/.local/share/model-upload-guard}"
VENV_DIR="${INSTALL_ROOT}/venv"
BIN_DIR="${HOME}/.local/bin"
CACHE_DIR="${INSTALL_ROOT}/cache"
ALLOW_UNVERIFIED="${MUG_ALLOW_UNVERIFIED:-0}"

log() { printf '%s\n' "$*"; }
die() { printf 'mug install: %s\n' "$*" >&2; exit 1; }

download() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
  else
    die "curl or wget is required."
  fi
}

sha256_file() {
  "$PYTHON" - "$1" <<'PY'
import hashlib, sys
from pathlib import Path
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
}

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  die "Python 3.11+ is required."
fi

"$PYTHON" - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit(1)
PY

if ! "$PYTHON" -m venv --help >/dev/null 2>&1; then
  die "Python's venv module is required."
fi

mkdir -p "$INSTALL_ROOT" "$BIN_DIR" "$CACHE_DIR"
"$PYTHON" -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/pyproject.toml" ]]; then
  log "Installing from local clone: $SCRIPT_DIR"
  "$VENV_DIR/bin/python" -m pip install --upgrade "$SCRIPT_DIR"
else
  SOURCE_URL="https://github.com/${REPO}/releases/download/${REF}/source.zip"
  SUMS_URL="https://github.com/${REPO}/releases/download/${REF}/SHA256SUMS.txt"
  ARCHIVE_FALLBACK="https://github.com/${REPO}/archive/${REF}.zip"
  ARCHIVE_PATH="${CACHE_DIR}/source-${REF}.zip"
  SUMS_PATH="${CACHE_DIR}/SHA256SUMS-${REF}.txt"

  log "Fetching release ${REF} from GitHub…"
  if download "$SUMS_URL" "$SUMS_PATH" && download "$SOURCE_URL" "$ARCHIVE_PATH"; then
    expected="$(awk '/[[:space:]]source\.zip$/ {print $1; exit} /SOURCE_ARCHIVE/ {print $1; exit}' "$SUMS_PATH")"
    [[ -n "$expected" ]] || die "SHA256SUMS.txt has no source.zip / SOURCE_ARCHIVE entry."
    actual="$(sha256_file "$ARCHIVE_PATH")"
    if [[ "$actual" != "$expected" ]]; then
      die "SHA256 mismatch for source.zip (expected ${expected}, got ${actual})."
    fi
    log "Verified SHA256 for ${REF}/source.zip"
  else
    rm -f "$ARCHIVE_PATH" "$SUMS_PATH"
    if [[ "$ALLOW_UNVERIFIED" != "1" ]]; then
      die "Release assets with checksums not found for ${REF}. Create a GitHub Release for this tag, or re-run with MUG_ALLOW_UNVERIFIED=1 (uses git archive ZIP, unverified)."
    fi
    log "WARNING: installing unverified archive ${ARCHIVE_FALLBACK}"
    download "$ARCHIVE_FALLBACK" "$ARCHIVE_PATH"
  fi
  "$VENV_DIR/bin/python" -m pip install --upgrade "$ARCHIVE_PATH"
fi

ln -sfn "$VENV_DIR/bin/mug" "$BIN_DIR/mug"
"$BIN_DIR/mug" --version

case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *)
    echo
    echo "Add this directory to PATH:"
    echo "  export PATH=\"${BIN_DIR}:\$PATH\""
    ;;
esac

echo
echo "Installed Model Upload Guard (${REF})."
echo "Run: mug doctor"
