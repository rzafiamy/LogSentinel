#!/usr/bin/env bash
# Train the model. Usage: scripts/train.sh 1|2|3|all
#   stage 1: format warm-up from Qwen/Qwen3-0.6B on v1 data (250 steps)      -> runs/stage1/final
#   stage 2: main training on v3 data (60k samples, 1 epoch)                -> runs/stage2/final
#   stage 3: targeted refinement on v4 data (16k new + 8k replay, 1 epoch)  -> runs/stage3/final
# Every stage is resumable: re-run the same command after an interruption and it continues
# from the last checkpoint (saved every 250 steps).
set -euo pipefail
source "$(dirname "$0")/env.sh"
COMMON="--tok_per_micro 1 --micro_per_step 16 --save_every 250 ${EXTRA:-}"
stage1() { $PY train.py --model Qwen/Qwen3-0.6B --train data/v1_train.jsonl --val data/v1_val.jsonl --out runs/stage1 \
             --epochs 1 --lr 3e-5 --warmup 0.03 --eval_every 250 --max_steps 250 $COMMON; }
stage2() { $PY train.py --model runs/stage1/final --train data/v3_train.jsonl --val data/v3_val.jsonl --out runs/stage2 \
             --epochs 1 --lr 2.5e-5 --warmup 0.02 --eval_every 500 $COMMON; }
stage3() { $PY train.py --model runs/stage2/final --train data/v4_train.jsonl --val data/v4_val.jsonl --out runs/stage3 \
             --epochs 1 --lr 1e-5 --warmup 0.03 --eval_every 500 $COMMON; }
case "${1:-}" in
  1) stage1 ;; 2) stage2 ;; 3) stage3 ;;
  all) stage1; stage2; stage3 ;;
  *) echo "usage: $0 1|2|3|all"; exit 1 ;;
esac
