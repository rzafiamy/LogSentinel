#!/usr/bin/env python3
"""Full fine-tune of a small causal LM on chat jsonl (loss on assistant answer only).

Token-budget batching, LM head applied to answer positions only (saves VRAM with 152k vocab),
bf16 autocast over fp32 master weights, cosine LR, resumable checkpoints.
"""
import argparse, json, math, os, random, time, glob, shutil
import torch, torch.nn.functional as F
from transformers import AutoTokenizer, AutoModelForCausalLM

ap = argparse.ArgumentParser()
ap.add_argument("--model", default="Qwen/Qwen3-0.6B")
ap.add_argument("--train", nargs="+", required=True)
ap.add_argument("--val", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--epochs", type=float, default=2)
ap.add_argument("--lr", type=float, default=3e-5)
ap.add_argument("--max_len", type=int, default=8192)
ap.add_argument("--tok_per_micro", type=int, default=16384)
ap.add_argument("--micro_per_step", type=int, default=4)
ap.add_argument("--warmup", type=float, default=0.03)
ap.add_argument("--save_every", type=int, default=300)
ap.add_argument("--eval_every", type=int, default=300)
ap.add_argument("--seed", type=int, default=0)
ap.add_argument("--no_ckpt", action="store_true")
ap.add_argument("--max_steps", type=int, default=0)
a = ap.parse_args()
os.makedirs(a.out, exist_ok=True)
log = open(os.path.join(a.out, "train.log"), "a")


def P(*x):
    s = " ".join(str(i) for i in x)
    print(s, flush=True); log.write(s + "\n"); log.flush()


tok = AutoTokenizer.from_pretrained(a.model)


def encode(row):
    msgs = row["messages"]
    prompt = tok.apply_chat_template(msgs[:-1], tokenize=False, add_generation_prompt=True, enable_thinking=False)
    comp = msgs[-1]["content"] + "<|im_end|>\n"
    p = tok(prompt, add_special_tokens=False)["input_ids"]
    c = tok(comp, add_special_tokens=False)["input_ids"]
    return p, c


def load(paths):
    out = []
    for path in paths:
        for line in open(path):
            p, c = encode(json.loads(line))
            if len(p) + len(c) <= a.max_len:
                out.append((p, c))
    return out


t0 = time.time()
train = load(a.train)
val = load([a.val])[:400]
P(f"loaded train={len(train)} val={len(val)} in {time.time() - t0:.0f}s; train tokens={sum(len(p) + len(c) for p, c in train) / 1e6:.1f}M")


def make_micros(data, rng):
    idx = list(range(len(data)))
    rng.shuffle(idx)
    micros = []
    for k in range(0, len(idx), 256):  # length-bucket within chunks of 256
        chunk = sorted(idx[k:k + 256], key=lambda i: len(data[i][0]) + len(data[i][1]))
        cur, mx = [], 0
        for i in chunk:
            L = len(data[i][0]) + len(data[i][1])
            if cur and max(mx, L) * (len(cur) + 1) > a.tok_per_micro:
                micros.append(cur); cur, mx = [], 0
            cur.append(i); mx = max(mx, L)
        if cur:
            micros.append(cur)
    rng.shuffle(micros)
    return micros


def collate(data, ids):
    seqs = [data[i][0] + data[i][1] for i in ids]
    labs = [[-100] * len(data[i][0]) + data[i][1] for i in ids]
    L = max(len(s) for s in seqs)
    inp = torch.full((len(ids), L), tok.pad_token_id, dtype=torch.long)
    lab = torch.full((len(ids), L), -100, dtype=torch.long)
    att = torch.zeros((len(ids), L), dtype=torch.long)
    for j, (s, l) in enumerate(zip(seqs, labs)):
        inp[j, :len(s)] = torch.tensor(s); lab[j, :len(l)] = torch.tensor(l); att[j, :len(s)] = 1
    return inp.cuda(), lab.cuda(), att.cuda()


model = AutoModelForCausalLM.from_pretrained(a.model, dtype=torch.float32, attn_implementation="sdpa").cuda()
if not a.no_ckpt:
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
model.config.use_cache = False


def loss_sum(inp, lab, att):
    with torch.autocast("cuda", dtype=torch.bfloat16):
        h = model.model(input_ids=inp, attention_mask=None if inp.shape[0] == 1 else att).last_hidden_state
        h = h[:, :-1]; y = lab[:, 1:]
        m = y != -100
        logits = model.lm_head(h[m])
    return F.cross_entropy(logits.float(), y[m], reduction="sum"), m.sum()


rng = random.Random(a.seed)
epochs_full = math.ceil(a.epochs)
plan = []
for e in range(epochs_full):
    ms = make_micros(train, rng)
    if e == epochs_full - 1 and a.epochs < epochs_full:
        ms = ms[:int(len(ms) * (a.epochs - (epochs_full - 1)))]
    plan += ms
steps = [plan[i:i + a.micro_per_step] for i in range(0, len(plan), a.micro_per_step)]
total = len(steps)
warm = max(1, int(total * a.warmup))
opt = torch.optim.AdamW(model.parameters(), lr=a.lr, betas=(0.9, 0.95), weight_decay=0.01, fused=True)
sched = torch.optim.lr_scheduler.LambdaLR(opt, lambda s: min(1, (s + 1) / warm) * (0.1 + 0.9 * 0.5 * (1 + math.cos(math.pi * min(1, s / total)))))
start = 0
ck = sorted(glob.glob(os.path.join(a.out, "ckpt-*")), key=lambda p: int(p.split("-")[-1]))
if ck:
    st = torch.load(os.path.join(ck[-1], "state.pt"), map_location="cuda", weights_only=False)
    model.load_state_dict(st["model"]); opt.load_state_dict(st["opt"]); sched.load_state_dict(st["sched"]); start = st["step"]
    P(f"resumed from {ck[-1]} at step {start}")
P(f"total steps={total} micro/step={a.micro_per_step} tok/micro={a.tok_per_micro}")


@torch.no_grad()
def evaluate():
    model.eval()
    tl, tn = 0.0, 0
    for k in range(0, len(val), 4):
        inp, lab, att = collate(val, list(range(k, min(k + 4, len(val)))))
        l, n = loss_sum(inp, lab, att); tl += l.item(); tn += n.item()
    model.train()
    return tl / tn


def save(step, final=False):
    if final:
        d = os.path.join(a.out, "final")
        model.save_pretrained(d, safe_serialization=True); tok.save_pretrained(d)
        return
    d = os.path.join(a.out, f"ckpt-{step}")
    os.makedirs(d, exist_ok=True)
    torch.save({"model": model.state_dict(), "opt": opt.state_dict(), "sched": sched.state_dict(), "step": step}, os.path.join(d, "state.pt"))
    for old in sorted(glob.glob(os.path.join(a.out, "ckpt-*")), key=lambda p: int(p.split("-")[-1]))[:-1]:
        shutil.rmtree(old)


model.train()
t0 = time.time(); ntok = 0; best = float("inf")
for step in range(start, total):
    if a.max_steps and step >= a.max_steps:
        break
    micros = steps[step]
    batches = [collate(train, m) for m in micros]
    denom = sum((b[1] != -100).sum().item() for b in batches)
    tot = 0.0
    for inp, lab, att in batches:
        l, _ = loss_sum(inp, lab, att)
        (l / denom).backward(); tot += l.item(); ntok += att.sum().item()
    gn = torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
    opt.step(); sched.step(); opt.zero_grad(set_to_none=True)
    if step % 20 == 0:
        el = time.time() - t0
        P(f"step {step}/{total} loss {tot / denom:.4f} gn {gn:.2f} lr {sched.get_last_lr()[0]:.2e} mem {torch.cuda.max_memory_allocated() / 2**30:.1f}G tok/s {ntok / el:.0f} eta {(total - step) * el / max(1, step - start + 1) / 60:.0f}m")
    if (step + 1) % a.eval_every == 0 or step == total - 1:
        v = evaluate(); P(f"EVAL step {step + 1} val_loss {v:.4f}")
    if (step + 1) % a.save_every == 0:
        save(step + 1)
save(total, final=True)
P("done", time.time() - t0)
