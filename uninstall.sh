#!/usr/bin/env bash
set -euo pipefail
INSTALL_ROOT="${MUG_HOME:-${HOME}/.local/share/model-upload-guard}"
BIN_PATH="${HOME}/.local/bin/mug"
rm -f "$BIN_PATH"
rm -rf "$INSTALL_ROOT"
echo "Model Upload Guard removed. Recovery snapshots under the user state directory were not deleted."
