#!/usr/bin/env bash
# Export to GGUF, then evaluate the Q8_0 and Q4_K_M files through llama.cpp. Usage: scripts/evaluate.sh runs/stage3
# Results: <run>/report/*.json (metrics + every model output) and *.txt (summary).
# Note: realtest.py also reads a few lines of YOUR /var/log files as a false-positive check;
#       real_*.json then contains excerpts of your logs. Do not publish those files.
set -uo pipefail
source "$(dirname "$0")/env.sh"
RUN=$1; OUT=$RUN/report; mkdir -p "$OUT"
[ -f "$RUN/gguf/$NAME-Q8_0.gguf" ] || scripts/export.sh "$RUN" > "$OUT/export.log" 2>&1 || { echo "export failed, see $OUT/export.log"; exit 1; }
URL=http://127.0.0.1:$PORT
for q in Q8_0 Q4_K_M; do
  t=$(echo $q | cut -c1-2 | tr A-Z a-z)   # q8 / q4
  scripts/serve.sh start "$RUN/gguf/$NAME-$q.gguf" "$OUT/server-$t.log" || exit 1
  $PY evaluate.py --server $URL --test data/v3_test.jsonl --out "$OUT/eval_${t}_v3test.json" > "$OUT/eval_${t}_v3test.txt" 2>&1
  $PY evaluate.py --server $URL --test data/v4_test.jsonl --out "$OUT/eval_${t}_v4test.json" > "$OUT/eval_${t}_v4test.txt" 2>&1
  [ $t = q8 ] && $PY evaluate.py --server $URL --test data/v2_test.jsonl --n 400 --out "$OUT/eval_${t}_v2test.json" > "$OUT/eval_${t}_v2test.txt" 2>&1
  $PY realtest.py --server $URL --out "$OUT/real_$t.json" > "$OUT/real_$t.txt" 2>&1
  scripts/serve.sh stop
done
for f in "$OUT"/eval_*.txt; do echo "== $f"; grep -E '"(finding_f1|json_valid|risk_acc|qa_f1)"' "$f"; done
for f in "$OUT"/real_*.txt; do echo "== $f"; tail -1 "$f"; done
