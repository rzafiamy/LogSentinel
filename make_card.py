#!/usr/bin/env python3
"""Build the Hugging Face model card from evaluation outputs. Usage: python make_card.py runs/stage3 [hf_repo] > README.md"""
import json, sys, os

RUN = sys.argv[1]
REPO = sys.argv[2] if len(sys.argv) > 2 else "rleo/LogSentinel-Qwen3-0.6B-GGUF"
GITHUB = "https://github.com/rzafiamy/LogSentinel"
THREE = any(k in RUN for k in ("stage3", "r4"))
STAGES = ("three stages (format warm-up on v1 data, main training on v3 data, targeted refinement on v4 data)" if THREE
          else "two stages (format warm-up on v1 data, then main training on v3 data)")
R = os.path.join(RUN, "report")
NAME = "LogSentinel-Qwen3-0.6B"


def M(path):
    try:
        return json.load(open(path))["metrics"]
    except Exception:
        return {}


def first(*paths):
    for p in paths:
        if os.path.exists(p):
            return M(p)
    return {}


q8 = first(f"{R}/eval_q8_v3test.json", f"{R}/eval_q8_test3.json")
q8v2 = first(f"{R}/eval_q8_v2test.json", f"{R}/eval_q8_test2.json")
q4 = first(f"{R}/eval_q4_v3test.json", f"{R}/eval_q4_test3.json")
base = first("runs/baseline/eval_v3test.json", "runs/base_schema_test3.json")
real8 = json.load(open(f"{R}/real_q8.json")) if os.path.exists(f"{R}/real_q8.json") else {"results": []}
ood = [r for r in real8["results"] if r["name"].startswith("ood_") and "passed" in r]


def pct(m, k):
    v = m.get(k)
    return "–" if v is None else f"{100 * v:.1f}%"


rows = [("Finding F1 (category detection)", "finding_f1"), ("Finding precision", "finding_precision"), ("Finding recall", "finding_recall"),
        ("Valid JSON", "json_valid"), ("Overall risk level correct", "risk_acc"), ("\"No issue\" vs \"issue\" correct", "no_finding_correct"),
        ("Severity correct (matched findings)", "f_severity"), ("Status correct", "f_status"), ("IPs exactly correct", "f_ips"),
        ("Users exactly correct", "f_users"), ("Event count exact", "f_count"), ("first_seen exact", "f_first_seen"),
        ("Evidence line copied verbatim from input", "evidence_verbatim"), ("No hallucinated IP in output", "no_hallucinated_ip"),
        ("Extraction Q&A exact match", "qa_exact"), ("Extraction Q&A token F1", "qa_f1")]
table = "| Metric | Base Qwen3-0.6B + schema prompt | **LogSentinel Q8_0** | LogSentinel Q4_K_M |\n|---|---|---|---|\n"
table += "\n".join(f"| {n} | {pct(base, k)} | **{pct(q8, k)}** | {pct(q4, k)} |" for n, k in rows)
weak = q8.get("per_category", {})
cat_table = "| Category | F1 | | Category | F1 |\n|---|---|---|---|---|\n"
items = sorted(weak.items(), key=lambda x: x[0])
half = (len(items) + 1) // 2
for i in range(half):
    a = items[i]; b = items[i + half] if i + half < len(items) else None
    cat_table += f"| {a[0]} | {a[1]['f1']:.2f} | | {b[0] if b else ''} | {f'{b[1][chr(102) + chr(49)]:.2f}' if b else ''} |\n"
ood_lines = "\n".join(f"| {r['name'].replace('ood_', '')} | {', '.join(r.get('categories') or []) or '(none)'} | {'✅' if r['passed'] else '❌'} |" for r in ood)

print(f"""---
license: apache-2.0
base_model: Qwen/Qwen3-0.6B
language: [en, fr]
tags: [gguf, llama.cpp, security, log-analysis, siem, linux, nginx, apache, sshd, ufw, dmesg, qwen3]
pipeline_tag: text-generation
---

# {NAME} (GGUF)

A **0.6B-parameter** Linux log analyst. It reads raw server logs and returns structured security findings in JSON.
It also answers extraction questions in English or French ("which IPs failed SSH?", "export the 5xx errors as JSON", …).

Full fine-tune of [Qwen/Qwen3-0.6B](https://huggingface.co/Qwen/Qwen3-0.6B). It runs on a CPU or any small GPU (Q4_K_M is about 400 MB).

**Log types:** nginx / apache access logs (combined, vhost, custom `rt=` and JSON formats), nginx / apache error logs, `auth.log` (sshd, sudo, su, useradd, PAM),
UFW / kernel firewall, `dmesg` (uptime, `-T` and journal formats), syslog / journalctl (systemd, cron, smartd, app logs), fail2ban.

**Detects 41 categories:** SQL injection, XSS, path traversal / LFI / RFI, command injection, Log4Shell, Shellshock, vulnerability scanners (sqlmap, nikto, nuclei…),
sensitive-file and CMS probing, web brute force, web shells, HTTP floods, 5xx bursts, SSH scanning, brute force (single source, distributed, user enumeration),
**compromised accounts** (success after failures), root logins, unusual logins, privilege escalation, failed sudo, malicious sudo commands, account creation,
port scans, repeated blocked connections, firewall disabled, OOM kills, segfaults, disk / SMART errors, hardware (MCE / EDAC / thermal / AER) errors,
kernel oops, SYN flood, conntrack full, unsigned kernel modules, AppArmor denials, USB storage, service failures, malicious cron jobs, fail2ban bans.

## Files

| File | Size | Use |
|---|---|---|
| `{NAME}-Q4_K_M.gguf` | ~400 MB | Recommended for CPU / edge |
| `{NAME}-Q8_0.gguf` | ~640 MB | Best quality / size trade-off |
| `{NAME}-BF16.gguf` | ~1.2 GB | Full precision |

## Usage

**Important:** this model was trained with thinking **disabled**. The embedded chat template already defaults to non-thinking,
but llama-server's reasoning parser must also be off, otherwise the answer shows up in `reasoning_content`:

```bash
llama-server -m {NAME}-Q4_K_M.gguf --jinja --reasoning off -c 16384
```

```bash
curl -s localhost:8080/v1/chat/completions -H 'Content-Type: application/json' -d @- <<'EOF'
{{"messages":[{{"role":"user","content":"Analyze these logs and report any security issues.\\n\\n$(tail -n 40 /var/log/auth.log)"}}],
 "temperature":0}}
EOF
```

Use **temperature 0** and keep each request below about 8k tokens of logs (roughly 40–80 lines). For larger files, send them in chunks.
Optional system prompt (used in training): *"You are LogSentinel, a Linux log analysis assistant. You read server logs (nginx, apache, auth/sshd, sudo, ufw, dmesg, syslog, fail2ban) and report security findings and operational problems accurately. Never invent events that are not in the logs."*

### Output format (analysis requests)

```json
{{
  "log_sources": ["auth"],
  "time_range": {{"start": "Mar 05 02:01:11", "end": "Mar 05 02:02:30"}},
  "risk_level": "critical",
  "findings": [{{
      "category": "compromised_account", "severity": "critical", "status": "successful", "source": "auth",
      "ips": ["45.155.205.233"], "users": ["postgres"], "count": 6,
      "first_seen": "Mar 05 02:01:11", "last_seen": "Mar 05 02:01:40",
      "evidence": "Mar 05 02:01:40 db01 sshd[820]: Accepted password for postgres from 45.155.205.233 port 33190 ssh2",
      "description": "Successful SSH login for 'postgres' from 45.155.205.233 after 6 failed attempts: account likely compromised."}}],
  "summary": "...",
  "recommendations": ["Lock the account, kill its sessions, rotate credentials and investigate activity from 45.155.205.233 immediately."]
}}
```
`severity`: info / low / medium / high / critical. `status`: blocked / attempted / possibly_successful / successful / observed.
`count` is the number of events (attempts, requests, packets), not the number of lines. `evidence` is one line copied verbatim from the input.
If the prompt is in French, descriptions, summary and recommendations come back in French.

## Evaluation

Held-out test set: {q8.get('n_analysis', '?')} analysis and {q8.get('n_qa', '?')} Q&A samples from a separate generator seed. All numbers below are measured on the GGUF files through llama.cpp.
The baseline is the untrained Qwen3-0.6B with the full output schema and category list in its system prompt.

{table}

**Per-category F1 (Q8_0):**

{cat_table}

**Hand-written out-of-distribution cases** (log formats and phrasings the generator never produces):

| Case | Model output categories | Pass |
|---|---|---|
{ood_lines}

## Training

- **Data:** about 60k synthetic samples from a purpose-built log generator with **exact, programmatic ground truth** (no LLM-written labels). Each sample mixes realistic
  benign traffic with 0–3 injected incidents. It includes hard negatives: admin typos, ssh-agent "too many authentication failures", late QUIC/TLS reply packets blocked by UFW,
  multicast/broadcast noise, scary-looking but standard Debian cron jobs, benign search queries containing SQL keywords, and app logs with ANSI codes or JSON.
  Multi-stage attack chains are included (port scan → brute force → login → sudo → cron persistence).
  Tasks: 62% full JSON analysis, 38% extraction Q&A. 75% English and 25% French prompts.
- **Recipe:** full fine-tune in bf16 autocast over fp32 master weights, AdamW, lr 2.5e-5 cosine, ~16 sequences per step, sequences up to 8k tokens, loss on answer tokens only.
  Trained on one RTX 4090 in {STAGES}.
- **Reproduce:** all code, the exact datasets and a step-by-step procedure are public: [{GITHUB.split("github.com/")[1]}]({GITHUB}) on GitHub,
  dataset [rleo/LogSentinel-synthetic-logs](https://huggingface.co/datasets/rleo/LogSentinel-synthetic-logs).

## Limitations

- Trained on synthetic logs. Real logs with very unusual formats, or attacks not in the list above, may be missed or mislabelled. Use it as a first-pass triage assistant, not as a replacement for a SIEM, IDS or a human analyst.
- Thresholds follow common practice (brute force from about 5 failures per IP, port scan from about 6 distinct ports). Slower or stealthier activity may go unreported.
- Counting long runs of events is approximate, and the context window limits how much log fits in one request.

## License

Released under the **Apache License 2.0**, the same license as the base model [Qwen/Qwen3-0.6B](https://huggingface.co/Qwen/Qwen3-0.6B) (Copyright Alibaba Cloud / Qwen team).
You may use, modify and redistribute these weights, including commercially. Keep the license and attribution notices, and state any changes you make.
See the [Apache 2.0 text](https://www.apache.org/licenses/LICENSE-2.0).
The training data is fully synthetic (generated by a script), so no third-party log data is included.
""")
