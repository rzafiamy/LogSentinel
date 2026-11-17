# LogSentinel

Train a **0.6B-parameter Linux log analyst** on a single NVIDIA GPU.

LogSentinel reads raw server logs (nginx, apache, `auth.log`/sshd, sudo, UFW, dmesg, syslog/journal, fail2ban) and returns structured
security findings as JSON. It also answers extraction questions ("which IPs failed SSH?") in English or French.

This repository contains everything used to build the published model:

| What | Where |
|---|---|
| Trained model (GGUF: Q4_K_M, Q8_0, BF16) | [rleo/LogSentinel-Qwen3-0.6B-GGUF](https://huggingface.co/rleo/LogSentinel-Qwen3-0.6B-GGUF) |
| Exact training / test datasets | [rleo/LogSentinel-synthetic-logs](https://huggingface.co/datasets/rleo/LogSentinel-synthetic-logs) |
| Data generators, training, evaluation, export code | this repository |

Base model: [Qwen/Qwen3-0.6B](https://huggingface.co/Qwen/Qwen3-0.6B), full fine-tune (all weights).

---

## Requirements

| | Minimum | Used for the published model |
|---|---|---|
| GPU | NVIDIA with **bf16** support (RTX 30xx / A-series or newer) and **16 GB VRAM** | RTX 4090 24 GB |
| Training memory | peak ~12.7 GB | |
| Disk | ~40 GB: Python env 7 GB, llama.cpp 1 GB, data 1 GB, per stage 9 GB (resume checkpoint 6.7 GB + final weights 2.3 GB), GGUF 2 GB | |
| Software | Linux, NVIDIA driver, CUDA toolkit (`nvcc`), Python 3.10+, git, cmake, g++ | Ubuntu 24.04, driver 570, CUDA 12.8, Python 3.12 |

Training time on an RTX 4090 (about 11–12k tokens/s): stage 1 ≈ 15 min, stage 2 ≈ 4 h 30, stage 3 ≈ 1 h 45.

---

## Procedure

All commands run from the repository root.

### 1. Install (once)

```bash
git clone https://github.com/rzafiamy/LogSentinel
cd LogSentinel
scripts/setup.sh
```

`setup.sh` creates `.venv/` with CUDA PyTorch and the Python dependencies. It then clones and builds
[llama.cpp](https://github.com/ggml-org/llama.cpp) at a pinned commit with CUDA, which is used for GGUF export and evaluation.
It stops with an error if PyTorch cannot see your GPU.

Options (environment variables):
- `CUDA_WHL=cu126` chooses another PyTorch CUDA build, to match your driver (default `cu128`).
- `LLAMA_CPP=/path/to/llama.cpp` reuses an existing checkout.

### 2. Get the data

Pick **one** of the two:

```bash
scripts/get_data.sh     # download the exact datasets from Hugging Face (~1 GB)
scripts/make_data.sh    # OR regenerate them locally (a few minutes, CPU only)
```

The generators are deterministic: `make_data.sh` produces byte-identical files to the downloaded ones.

### 3. Train

```bash
scripts/train.sh all    # or run the stages one by one: scripts/train.sh 1, then 2, then 3
```

| Stage | Starts from | Data | Steps | LR | Output |
|---|---|---|---|---|---|
| 1. Format warm-up | `Qwen/Qwen3-0.6B` | `v1_train` (40k) | 250 (of a 2491-step schedule) | 3e-5 | `runs/stage1/final` |
| 2. Main training | stage 1 | `v3_train` (60k) | 3711 (1 epoch) | 2.5e-5 | `runs/stage2/final` |
| 3. Refinement | stage 2 | `v4_train` (16k new + 8k replay of v3) | ~1485 (1 epoch) | 1e-5 | `runs/stage3/final` |

Common settings:
- one sequence per micro-batch, 16 micro-batches per optimizer step
- sequences up to 8192 tokens
- AdamW (betas 0.9/0.95, weight decay 0.01) over fp32 master weights, with bf16 autocast
- cosine schedule with a 10% floor; gradient clipping at 1.0
- gradient checkpointing; loss on the assistant answer only

Checkpoints are written every 250 steps. Only the latest is kept. Once a stage has finished, you can delete its `runs/stageN/ckpt-*` folder to free 6.7 GB. **If training is interrupted, run the same command again** and it resumes from the last checkpoint.
Progress is printed and logged to `runs/stageN/train.log`, for example:

```
step 340/1485 loss 0.0064 gn 0.55 lr 8.88e-06 mem 12.7G tok/s 11930 eta 76m
EVAL step 500 val_loss 0.0145
```

Less than 16 GB VRAM? Add `EXTRA="--max_len 4096"`, e.g. `EXTRA="--max_len 4096" scripts/train.sh all`. This drops the longest samples, so it is untested and the results will differ.

### 4. Export to GGUF and evaluate

```bash
scripts/evaluate.sh runs/stage3     # (or runs/stage2 to evaluate the 2-stage model)
```

This script does three things:
1. It patches the chat template so that thinking is off by default.
2. It writes `runs/stage3/gguf/LogSentinel-Qwen3-0.6B-{BF16,Q8_0,Q4_K_M}.gguf`.
3. It serves each quantization with llama-server and scores it.

The scoring covers:
- **held-out test sets:** `v3_test` and `v4_test`, plus `v2_test`, which was produced by an older generator version
- **hand-written cases** in formats the generator never produces, from `realtest.py`

Results go to `runs/stage3/report/`, with a short summary printed at the end.
The evaluation server uses about 16 GB of VRAM. On smaller GPUs use `CTX=49152 PAR=4 scripts/evaluate.sh runs/stage3`.

> `realtest.py` also feeds a few lines of **your own** `/var/log` files to the model, as a false-positive check on real benign traffic.
> The resulting `report/real_*.json` contains excerpts of your logs: do not publish them.

Optional: score the untrained base model for comparison with `scripts/baseline.sh`, which writes `runs/baseline/`.

### 5. Use it

```bash
llama.cpp/build/bin/llama-server -m runs/stage3/gguf/LogSentinel-Qwen3-0.6B-Q4_K_M.gguf --jinja --reasoning off -c 16384
```

```bash
LOGS=$(tail -n 40 /var/log/auth.log)
jq -n --arg l "$LOGS" '{temperature:0, messages:[{role:"user", content:("Analyze these logs and report any security issues.\n\n" + $l)}]}' \
  | curl -s localhost:8080/v1/chat/completions -H 'Content-Type: application/json' -d @- | jq -r '.choices[0].message.content'
```

- **Always run llama-server with `--reasoning off`.** The model was trained with thinking disabled. Without this flag, llama-server puts the answer in `reasoning_content` and leaves `content` empty.
- **Use temperature 0.**
- **Send about 40–80 log lines per request** (up to about 8k tokens). Split larger files into chunks.

### 6. Publish (optional)

```bash
.venv/bin/hf auth login
scripts/publish_hf.sh runs/stage3 <your-hf-user>/LogSentinel-Qwen3-0.6B-GGUF
```

This uploads the three GGUF files, the license and a model card generated from your evaluation results.

---

## How it works

### The data generator (`gen.py`)

LLM-written labels are noisy, so all training data is **synthetic with exact, programmatic ground truth**.
The generator first simulates a server: its users, internal IPs, services, cron jobs and timestamp formats. It writes realistic benign traffic,
then injects 0–3 incidents. Because it knows which lines belong to which incident, the expected answer is computed exactly:
category, severity, status, IPs, users, event count, first/last timestamp, a verbatim evidence line, a description and recommendations.

The generator covers:
- **Log formats:** nginx/apache `combined`, vhost, custom `rt=` and JSON access logs; nginx/apache error logs; `auth.log`; UFW;
  dmesg (uptime, `-T`, journal `kernel:` prefix); syslog/journal with several timestamp styles; fail2ban; and several sources mixed in one prompt.
- **41 categories:**
  - **Web:** SQL injection, XSS, path traversal, command injection, Log4Shell, Shellshock, scanners, sensitive-file and CMS probes, web brute force, web shells, HTTP floods, 5xx bursts
  - **SSH/sudo:** scans, brute force (single source, distributed, user enumeration), compromised accounts, root/unusual logins, privilege escalation, failed sudo, malicious sudo commands, account creation
  - **Firewall:** port scans, repeated blocks, firewall disabled
  - **Kernel/system:** OOM, segfaults, disk/SMART, hardware errors, kernel oops, SYN flood, conntrack, unsigned modules, AppArmor, USB storage, service failures, malicious cron jobs, fail2ban bans
- **Hard negatives** that must *not* be reported:
  - an admin typo followed by a successful login
  - ssh-agent "too many authentication failures"
  - late QUIC/TLS reply packets blocked by UFW, and multicast/broadcast noise
  - standard Debian cron jobs that look scary
  - search queries containing SQL words
  - scary-sounding boot messages such as CPU vulnerability mitigations and ACPI BIOS errors
- **Attack chains:** port scan → brute force → successful login → sudo → cron persistence.
- **Tasks:** 62% full JSON analysis and 38% extraction Q&A. Prompts are 75% English and 25% French.

Generator versions (in `generators/`) match the training stages: `gen_v1.py` (stage 1), `gen_v2.py` (extra test set),
`gen_v3.py` (stage 2) and `gen.py` = v4 (stage 3). Each version was built from failures of the previous model on real logs.

Each dataset line looks like this:
```json
{"messages": [{"role": "system", ...} (optional), {"role": "user", "content": "<question + logs>"}, {"role": "assistant", "content": "<expected answer>"}],
 "task": "analysis" | "qa", "lang": "en" | "fr", "mode": "<scenario type>", "n_lines": 42,
 "gold": {...parsed expected answer for analysis samples, null for qa...}}
```

### Training (`train.py`)

A plain PyTorch loop. It does not use the HF Trainer: this keeps memory and speed under control for long sequences with Qwen3's 152k vocabulary.
- **Unpadded micro-batches.** Each micro-batch is one sequence without padding, so PyTorch SDPA uses the flash-attention kernel.
- **Output projection on answer tokens only.** The LM head (152k-word vocabulary) runs only on the answer tokens. This avoids materializing about 8k × 152k logits.
- **Precision.** bf16 autocast over fp32 master weights; fused AdamW.

### Evaluation (`evaluate.py`, `realtest.py`)

Metrics:
- valid JSON
- risk level
- finding precision, recall and F1, with a per-category breakdown
- field accuracy on matched findings: severity, status, IPs, users, count, timestamps, evidence
- hallucination checks: every IP and every evidence line must exist in the input
- extraction Q&A: exact match and token F1

`realtest.py` adds hand-written out-of-distribution cases.

## Repository layout

```
gen.py                 data generator v4 (current)
generators/            generator versions v1-v3 (to rebuild the exact stage datasets)
train.py               fine-tuning loop
evaluate.py            scoring on a generated test set (HF model or llama-server)
realtest.py            hand-written OOD cases + local-log false-positive check
make_card.py           builds the Hugging Face model card from evaluation results
scripts/
  setup.sh             venv + CUDA PyTorch + llama.cpp build
  get_data.sh          download datasets from Hugging Face
  make_data.sh         regenerate datasets from seeds
  train.sh             stages 1-3
  export.sh            HF checkpoint -> GGUF (BF16, Q8_0, Q4_K_M)
  evaluate.sh          export + evaluate GGUF files
  serve.sh             start/stop llama-server for evaluation
  baseline.sh          score the untrained base model
  publish_hf.sh        upload GGUF + model card
  env.sh               shared paths/settings (override via environment)
```

## Limitations

- **Synthetic training data.** The model learned from generated logs. Unusual real-world formats, or attacks outside the 41 categories, may be missed or mislabelled.
  Use it as a first-pass triage assistant, not as a replacement for a SIEM, an IDS or a human analyst.
- **Fixed detection thresholds.** Thresholds follow common practice: brute force from about 5 failures per IP, port scan from about 6 distinct ports. Slower attacks may go unreported.

## License

Apache License 2.0 (see `LICENSE`), the same license as the base model Qwen3-0.6B (© Alibaba Cloud / Qwen team).
