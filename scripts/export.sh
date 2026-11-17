#!/usr/bin/env bash
# Convert a trained checkpoint to GGUF: BF16, Q8_0, Q4_K_M. Usage: scripts/export.sh runs/stage3
set -euo pipefail
source "$(dirname "$0")/env.sh"
RUN=$1; SRC=$RUN/final; OUT=$RUN/gguf; mkdir -p "$OUT"
# The model was trained with thinking disabled: make the embedded chat template default to non-thinking.
sed -i 's/{%- if enable_thinking is defined and enable_thinking is false %}/{%- if not (enable_thinking is defined and enable_thinking is true) %}/' "$SRC/chat_template.jinja"
grep -q "enable_thinking is true" "$SRC/chat_template.jinja" || { echo "chat template patch failed"; exit 1; }
$PY "$LLAMA_CPP/convert_hf_to_gguf.py" "$SRC" --outtype bf16 --outfile "$OUT/$NAME-BF16.gguf"
for q in Q8_0 Q4_K_M; do
  "$LLAMA_BIN/llama-quantize" "$OUT/$NAME-BF16.gguf" "$OUT/$NAME-$q.gguf" $q > "$OUT/quantize-$q.log" 2>&1
done
ls -la "$OUT"
