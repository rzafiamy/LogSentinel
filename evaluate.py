#!/usr/bin/env python3
"""Evaluate a model on the held-out generator test set (HF transformers or an OpenAI-compatible server).

python evaluate.py --model runs/r1/final --test data/test.jsonl --out runs/r1/eval.json
python evaluate.py --server http://127.0.0.1:8190 --test data/test.jsonl --out gguf_eval.json
"""
import argparse, json, re, sys, time, collections
from concurrent.futures import ThreadPoolExecutor

ap = argparse.ArgumentParser()
ap.add_argument("--model")
ap.add_argument("--server")
ap.add_argument("--test", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--n", type=int, default=0)
ap.add_argument("--bs", type=int, default=24)
ap.add_argument("--kwargs", action="store_true", help="send enable_thinking=false (needed for the stock Qwen3 template)")
ap.add_argument("--schema_prompt", action="store_true", help="baseline: give the untrained model the schema in a system prompt")
a = ap.parse_args()

rows = [json.loads(l) for l in open(a.test)]
if a.n:
    rows = rows[:a.n]
SCHEMA = """You are a Linux log analysis assistant. When asked to analyze logs, answer ONLY with a JSON object:
{"log_sources": [...], "time_range": {"start": "<first timestamp as written>", "end": "<last timestamp>"}, "risk_level": "none|low|medium|high|critical",
 "findings": [{"category": "<one of the categories>", "severity": "info|low|medium|high|critical", "status": "blocked|attempted|possibly_successful|successful|observed",
   "source": "<log type>", "ips": [...], "users": [...], "count": <number of events>, "first_seen": "<timestamp>", "last_seen": "<timestamp>",
   "evidence": "<one log line copied verbatim>", "description": "<one sentence>"}],
 "summary": "<short summary>", "recommendations": ["..."]}
Categories: sql_injection, xss, path_traversal, command_injection, log4shell, shellshock, vulnerability_scanner, sensitive_file_probe, cms_admin_probe, web_brute_force,
webshell_access, http_flood, server_errors, ssh_scan, ssh_brute_force, ssh_user_enumeration, distributed_ssh_brute_force, compromised_account, root_login, unusual_login,
privilege_escalation_attempt, sudo_auth_failure, suspicious_sudo_command, account_created, port_scan, repeated_blocked_connections, firewall_disabled, oom_kill, segfault,
disk_error, hardware_error, kernel_oops, syn_flood, conntrack_full, unsigned_module, apparmor_denied, usb_device, service_failure, suspicious_cron, fail2ban_ban.
Report nothing for normal activity (findings: []). For other questions, answer concisely."""
if a.schema_prompt:
    for r in rows:
        r["messages"] = [{"role": "system", "content": SCHEMA}] + [m for m in r["messages"] if m["role"] != "system"]
IP_RE = re.compile(r"(?<![\d.:])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")


def gen_hf(rows):
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    tok = AutoTokenizer.from_pretrained(a.model, padding_side="left")
    m = AutoModelForCausalLM.from_pretrained(a.model, dtype=torch.bfloat16).cuda().eval()
    prompts = [tok.apply_chat_template(r["messages"][:-1], tokenize=False, add_generation_prompt=True, enable_thinking=False) for r in rows]
    order = sorted(range(len(rows)), key=lambda i: len(prompts[i]))
    outs = [None] * len(rows)
    for k in range(0, len(order), a.bs):
        ids = order[k:k + a.bs]
        enc = tok([prompts[i] for i in ids], return_tensors="pt", padding=True, add_special_tokens=False).to("cuda")
        with torch.no_grad():
            g = m.generate(**enc, max_new_tokens=1600, do_sample=False, pad_token_id=tok.pad_token_id)
        for i, seq in zip(ids, g):
            outs[i] = tok.decode(seq[enc["input_ids"].shape[1]:], skip_special_tokens=True).strip()
        print(f"\r{k + len(ids)}/{len(rows)}", end="", file=sys.stderr, flush=True)
    print(file=sys.stderr)
    return outs


def gen_server(rows):
    import urllib.request

    def one(r):
        req_ = {"messages": r["messages"][:-1], "temperature": 0, "max_tokens": 1600}
        if a.kwargs:
            req_["chat_template_kwargs"] = {"enable_thinking": False}
        body = json.dumps(req_).encode()
        req = urllib.request.Request(a.server + "/v1/chat/completions", body, {"Content-Type": "application/json"})
        try:
            out = json.load(urllib.request.urlopen(req, timeout=600))["choices"][0]["message"]["content"]
        except Exception as e:
            print("request error:", e, file=sys.stderr)
            return ""
        return re.sub(r"<think>.*?</think>", "", out, flags=re.S).strip()

    with ThreadPoolExecutor(8) as ex:
        return list(ex.map(one, rows))


def norm(s):
    return " ".join(s.split()).lower()


def tokf1(a_, b_):
    A, B = norm(a_).split(), norm(b_).split()
    if not A and not B:
        return 1.0
    c = sum((collections.Counter(A) & collections.Counter(B)).values())
    if c == 0:
        return 0.0
    p, r = c / len(A), c / len(B)
    return 2 * p * r / (p + r)


t0 = time.time()
outs = gen_hf(rows) if a.model else gen_server(rows)
gen_time = time.time() - t0

S = collections.defaultdict(list)
per_cat = collections.defaultdict(lambda: collections.Counter())
fails = []
for r, o in zip(rows, outs):
    user = r["messages"][-2]["content"]
    gold_txt = r["messages"][-1]["content"]
    if r["task"] == "qa":
        em = norm(o) == norm(gold_txt)
        S["qa_exact"].append(em); S["qa_f1"].append(tokf1(o, gold_txt))
        if not em:
            fails.append({"task": "qa", "q": user[-200:] if not user.startswith(("Which", "How", "What", "List", "Extract", "Give", "Is ", "Are", "Did", "Were", "Quel", "Combien", "Liste", "Extrais", "Donne", "Y a", "Une", "Qu")) else user[:200], "gold": gold_txt[:600], "pred": o[:600]})
        continue
    g = r["gold"]
    try:
        o2 = o.strip()
        if not o2.startswith("{") and "{" in o2:
            o2 = o2[o2.index("{"):o2.rindex("}") + 1]
        p = json.loads(o2)
        ok = isinstance(p, dict)
    except Exception:
        ok = False
    S["json_valid"].append(ok)
    if not ok:
        fails.append({"task": "analysis", "err": "invalid_json", "pred": o[-400:]})
        continue
    S["risk_acc"].append(p.get("risk_level") == g["risk_level"])
    S["time_range_exact"].append(p.get("time_range") == g["time_range"])
    gc = collections.Counter(f["category"] for f in g["findings"])
    pf = [f for f in p.get("findings", []) if isinstance(f, dict)]
    pc = collections.Counter(f.get("category") for f in pf)
    tp = sum((gc & pc).values())
    S["cat_tp"].append(tp); S["cat_fp"].append(sum(pc.values()) - tp); S["cat_fn"].append(sum(gc.values()) - tp)
    S["no_finding_correct"].append((len(pf) == 0) == (len(g["findings"]) == 0))
    for c in set(gc) | set(pc):
        per_cat[c]["tp"] += min(gc[c], pc[c]); per_cat[c]["fp"] += max(0, pc[c] - gc[c]); per_cat[c]["fn"] += max(0, gc[c] - pc[c])
    # hallucination checks
    for f in pf:
        ev = f.get("evidence", "")
        S["evidence_verbatim"].append(bool(ev) and ev in user)
        for ip in f.get("ips", []) or []:
            S["ip_in_input"].append(ip in user)
    out_ips = set(IP_RE.findall(o)); in_ips = set(IP_RE.findall(user))
    S["no_hallucinated_ip"].append(out_ips <= in_ips)
    # field accuracy on matched categories (first occurrence of each)
    used = set()
    for gf in g["findings"]:
        cand = [i for i, f in enumerate(pf) if f.get("category") == gf["category"] and i not in used]
        if not cand:
            if len(fails) < 4000:
                fails.append({"task": "analysis", "err": "missed", "cat": gf["category"], "sev": gf["severity"], "desc": gf["description"]})
            continue
        i = cand[0]; used.add(i); f = pf[i]
        for k in ("severity", "status", "count", "first_seen", "last_seen", "evidence"):
            S[f"f_{k}"].append(f.get(k) == gf.get(k))
        S["f_ips"].append(sorted(f.get("ips", []) or []) == sorted(gf.get("ips", [])))
        S["f_users"].append(sorted(f.get("users", []) or []) == sorted(gf.get("users", [])))
        if f.get("count") != gf.get("count"):
            fails.append({"task": "analysis", "err": "count", "cat": gf["category"], "gold": gf["count"], "pred": f.get("count")})
        if f.get("severity") != gf.get("severity"):
            fails.append({"task": "analysis", "err": "severity", "cat": gf["category"], "gold": gf["severity"], "pred": f.get("severity")})
    for i, f in enumerate(pf):
        if i not in used:
            fails.append({"task": "analysis", "err": "false_positive", "cat": f.get("category"), "desc": f.get("description", "")[:200]})

res = {}
for k, v in S.items():
    if k.startswith("cat_"):
        continue
    res[k] = round(sum(v) / len(v), 4) if v else None
tp, fp, fn = sum(S["cat_tp"]), sum(S["cat_fp"]), sum(S["cat_fn"])
res["finding_precision"] = round(tp / max(1, tp + fp), 4)
res["finding_recall"] = round(tp / max(1, tp + fn), 4)
res["finding_f1"] = round(2 * tp / max(1, 2 * tp + fp + fn), 4)
res["n_analysis"] = len(S["json_valid"]); res["n_qa"] = len(S["qa_exact"]); res["gen_seconds"] = round(gen_time)
weak = {c: dict(v, f1=round(2 * v["tp"] / max(1, 2 * v["tp"] + v["fp"] + v["fn"]), 3)) for c, v in per_cat.items()}
res["per_category"] = dict(sorted(weak.items(), key=lambda x: x[1]["f1"]))
json.dump({"metrics": res, "failures": fails, "outputs": outs}, open(a.out, "w"), ensure_ascii=False, indent=1)
print(json.dumps({k: v for k, v in res.items() if k != "per_category"}, indent=1))
print("weakest categories:", {c: v["f1"] for c, v in list(res["per_category"].items())[:10]})
