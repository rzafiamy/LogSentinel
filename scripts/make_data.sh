#!/usr/bin/env bash
# Alternative to get_data.sh: regenerate every dataset locally from the generators and fixed seeds.
# The generators are deterministic, so this produces byte-identical files (a few minutes on a CPU).
set -euo pipefail
source "$(dirname "$0")/env.sh"
mkdir -p data
G1=generators/gen_v1.py; G2=generators/gen_v2.py; G3=generators/gen_v3.py; G4=gen.py
$PY $G1 --n 40000 --seed 1  --out data/v1_train.jsonl &
$PY $G1 --n 500   --seed 2  --out data/v1_val.jsonl &
$PY $G2 --n 800   --seed 23 --out data/v2_test.jsonl &
$PY $G3 --n 60000 --seed 41 --out data/v3_train.jsonl &
$PY $G3 --n 500   --seed 42 --out data/v3_val.jsonl &
$PY $G3 --n 800   --seed 43 --out data/v3_test.jsonl &
$PY $G4 --n 16000 --seed 61 --out data/v4_new.jsonl &
$PY $G4 --n 400   --seed 62 --out data/v4_val.jsonl &
$PY $G4 --n 600   --seed 63 --out data/v4_test.jsonl &
wait
# stage-3 training set: 16k new v4 samples + 8k replayed v3 samples (avoids forgetting)
$PY - <<'PYEOF'
import random
r = random.Random(7)
a = open("data/v3_train.jsonl").readlines(); r.shuffle(a)
b = open("data/v4_new.jsonl").readlines() + a[:8000]; r.shuffle(b)
open("data/v4_train.jsonl", "w").writelines(b)
print("v4_train:", len(b))
PYEOF
ls -la data/*.jsonl
