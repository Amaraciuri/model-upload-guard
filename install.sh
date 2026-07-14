#!/usr/bin/env bash
set -euo pipefail

REPO="${MUG_REPO:-Amaraciuri/model-upload-guard}"
REF="${MUG_REF:-main}"
PYTHON="${PYTHON:-python3}"
INSTALL_ROOT="${MUG_HOME:-${HOME}/.local/share/model-upload-guard}"
VENV_DIR="${INSTALL_ROOT}/venv"
BIN_DIR="${HOME}/.local/bin"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Model Upload Guard requires Python 3.11+." >&2
  exit 1
fi

"$PYTHON" - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Model Upload Guard requires Python 3.11+.")
PY

if ! "$PYTHON" -m venv --help >/dev/null 2>&1; then
  echo "Python's venv module is required." >&2
  exit 1
fi

mkdir -p "$INSTALL_ROOT" "$BIN_DIR"
"$PYTHON" -m venv "$VENV_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/pyproject.toml" ]]; then
  "$VENV_DIR/bin/python" -m pip install --upgrade "$SCRIPT_DIR"
else
  "$VENV_DIR/bin/python" -m pip install --upgrade "https://github.com/${REPO}/archive/${REF}.zip"
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
echo "Installed Model Upload Guard."
echo "Run: mug doctor"
