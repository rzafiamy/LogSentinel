#!/usr/bin/env bash
# Upload the GGUF files + generated model card to a Hugging Face model repo.
# Usage: scripts/publish_hf.sh runs/stage3 <hf-user>/<repo-name>     (run `.venv/bin/hf auth login` first)
set -euo pipefail
source "$(dirname "$0")/env.sh"
RUN=$1; REPO=$2; STAGE=$RUN/hf_upload; rm -rf "$STAGE"; mkdir -p "$STAGE"
$PY make_card.py "$RUN" "$REPO" > "$STAGE/README.md"
cp LICENSE "$STAGE/"
for q in Q4_K_M Q8_0 BF16; do ln -f "$RUN/gguf/$NAME-$q.gguf" "$STAGE/"; done
.venv/bin/hf repos create "$REPO" --repo-type model --exist-ok
.venv/bin/hf upload "$REPO" "$STAGE" . --repo-type model --commit-message "LogSentinel GGUF + model card"
echo "https://huggingface.co/$REPO"
