#!/usr/bin/env bash
# One-time setup: Python venv with CUDA PyTorch, plus llama.cpp built with CUDA (GGUF export + evaluation).
# Needs: python3.10+, git, cmake, a C++ compiler, the CUDA toolkit (nvcc) and an NVIDIA driver.
set -euo pipefail
source "$(dirname "$0")/env.sh"
CUDA_WHL=${CUDA_WHL:-cu128}                  # PyTorch wheel flavour (cu126, cu128, ...), see pytorch.org
LLAMA_CPP_COMMIT=${LLAMA_CPP_COMMIT:-abeada335e2e78bd3fe63febafab7e900ce75810}
python3 -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install torch --index-url https://download.pytorch.org/whl/$CUDA_WHL
.venv/bin/pip install -r requirements.txt
.venv/bin/python -c "import torch; assert torch.cuda.is_available(), 'CUDA not visible to PyTorch'; print('GPU:', torch.cuda.get_device_name(0), '| bf16:', torch.cuda.is_bf16_supported())"
# find nvcc even when the CUDA toolkit is not on PATH (common with /usr/local/cuda installs)
if ! command -v nvcc >/dev/null; then
  for d in /usr/local/cuda/bin /usr/local/cuda-*/bin /opt/cuda/bin; do [ -x "$d/nvcc" ] && { export PATH="$d:$PATH"; break; }; done
fi
command -v nvcc >/dev/null || { echo "nvcc (CUDA toolkit) not found: install it, or add its bin/ directory to PATH"; exit 1; }
echo "nvcc: $(command -v nvcc)"
if [ ! -d "$LLAMA_CPP" ]; then git clone https://github.com/ggml-org/llama.cpp "$LLAMA_CPP"; fi
git -C "$LLAMA_CPP" fetch --quiet origin || true
git -C "$LLAMA_CPP" checkout --quiet "$LLAMA_CPP_COMMIT"
cmake -S "$LLAMA_CPP" -B "$LLAMA_CPP/build" -DGGML_CUDA=ON -DCMAKE_CUDA_COMPILER="$(command -v nvcc)" -DCMAKE_BUILD_TYPE=Release
cmake --build "$LLAMA_CPP/build" -j --target llama-server llama-quantize
echo "Setup OK"
