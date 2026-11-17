#!/usr/bin/env bash
# Optional: score the untrained Qwen3-0.6B (with the output schema in its system prompt) for comparison.
set -euo pipefail
source "$(dirname "$0")/env.sh"
mkdir -p runs/baseline
SNAP=$($PY -c "from huggingface_hub import snapshot_download; print(snapshot_download('Qwen/Qwen3-0.6B'))")
[ -f runs/baseline/base-Q8_0.gguf ] || { $PY "$LLAMA_CPP/convert_hf_to_gguf.py" "$SNAP" --outtype q8_0 --outfile runs/baseline/base-Q8_0.gguf; }
scripts/serve.sh start runs/baseline/base-Q8_0.gguf runs/baseline/server.log
$PY evaluate.py --server http://127.0.0.1:$PORT --test data/v3_test.jsonl --n 400 --kwargs --schema_prompt --out runs/baseline/eval_v3test.json | tee runs/baseline/eval_v3test.txt
scripts/serve.sh stop
