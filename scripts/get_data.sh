#!/usr/bin/env bash
# Download the exact datasets used for the published model from Hugging Face into data/ (~800 MB).
set -euo pipefail
source "$(dirname "$0")/env.sh"
.venv/bin/hf download "$HF_DATASET" --repo-type dataset --include "*.jsonl" --local-dir data
ls -la data/*.jsonl
