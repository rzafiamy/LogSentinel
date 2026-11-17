#!/usr/bin/env bash
# serve.sh start <model.gguf> <logfile> | serve.sh stop
# llama-server on 127.0.0.1:$PORT. CTX is the total context, shared by PAR parallel slots (each slot gets CTX/PAR).
# Test prompts go up to ~10k tokens, so keep CTX/PAR >= 12288. Lower both on small GPUs (e.g. CTX=49152 PAR=4).
source "$(dirname "$0")/env.sh"
PIDF=$ROOT/.server.pid
if [ "$1" = start ]; then
  setsid "$LLAMA_BIN/llama-server" -m "$2" --host 127.0.0.1 --port $PORT -ngl 99 -c ${CTX:-131072} --parallel ${PAR:-8} \
    --jinja --reasoning off > "$3" 2>&1 < /dev/null &
  echo $! > "$PIDF"
  for i in $(seq 1 120); do curl -sf 127.0.0.1:$PORT/health >/dev/null && exit 0; sleep 1; done
  echo "server failed, see $3"; exit 1
else
  [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null; rm -f "$PIDF"; sleep 2
fi
