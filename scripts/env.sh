# Shared settings, sourced by every script. Override any of them from the environment.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY=${PY:-$ROOT/.venv/bin/python}
LLAMA_CPP=${LLAMA_CPP:-$ROOT/llama.cpp}          # llama.cpp checkout (convert script + build/bin)
LLAMA_BIN=${LLAMA_BIN:-$LLAMA_CPP/build/bin}     # where llama-server and llama-quantize live
NAME=${NAME:-LogSentinel-Qwen3-0.6B}
HF_DATASET=${HF_DATASET:-rleo/LogSentinel-synthetic-logs}
PORT=${PORT:-8190}
cd "$ROOT"
