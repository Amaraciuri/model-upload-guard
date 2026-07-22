#!/usr/bin/env bash
set -euo pipefail
INSTALL_ROOT="${MUG_HOME:-${HOME}/.local/share/model-upload-guard}"
BIN_PATH="${HOME}/.local/bin/mug"
if [[ "$(uname -s)" == "Darwin" ]]; then
  STATE_DIR="${XDG_STATE_HOME:-${HOME}/.local/state}/model-upload-guard"
else
  STATE_DIR="${XDG_STATE_HOME:-${HOME}/.local/state}/model-upload-guard"
fi
rm -f "$BIN_PATH"
rm -rf "$INSTALL_ROOT"
echo "Model Upload Guard removed from:"
echo "  ${INSTALL_ROOT}"
echo "  ${BIN_PATH}"
echo
echo "Recovery snapshots were kept at:"
echo "  ${STATE_DIR}"
echo "Delete manually if you no longer need them:"
echo "  rm -rf \"${STATE_DIR}\""
