"""
Memorisation / contamination probe over matched (ReposVul seed, VeriVul generated)
pairs.

For each sampled pair we run two prefix-completion probes:
  REPO  : prefix = first P-line window of the original ReposVul function
          target = next  T-line window of the same function
  VERI  : prefix = first P-line window of the verified VeriVul program
          target = next  T-line window of the same program

We score the model's completion against the held-out target with three
SOTA-style memorisation metrics (cf. Carlini et al. 2021; Risse & Bohme 2024):

  ned  : normalised Levenshtein edit distance     (0 = exact, 1 = unrelated)
  lcs  : longest-common-substring fraction        (1 = exact, 0 = unrelated)
  idr  : identifier recall (set recall on C ids)  (1 = all ids reproduced)

The hypothesis is that pretraining-era ReposVul functions are memorised more
than the post-cutoff VeriVul programs they seeded, so REPO scores should
indicate higher fidelity than VERI scores when the model has been exposed to
ReposVul during training.

Run:
    python contamination_probe.py \
        --n 300 \
        --model gpt-oss \
        --api-base http://localhost:8000/v1 \
        --output data/contamination_probe_gpt-oss.jsonl
"""
import argparse
import json
import os
import random
import re
import sys
import time
from pathlib import Path

import Levenshtein
from openai import OpenAI

ROOT = Path(__file__).resolve().parent
SEED_FILE     = ROOT / "data" / "reposvul_sliced.jsonl"
VERIFIED_FILE = ROOT / "data" / "verified_samples.jsonl"

PREFIX_FRACTION = 0.30
TARGET_FRACTION = 0.30
PREFIX_MIN_LINES, PREFIX_MAX_LINES = 5, 40
TARGET_MIN_LINES, TARGET_MAX_LINES = 5, 40
TOTAL_LINES_RANGE = (30, 250)
MAX_COMPLETION_TOKENS = 1024

ID_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
C_KEYWORDS = {
    "auto","break","case","char","const","continue","default","do","double","else",
    "enum","extern","float","for","goto","if","inline","int","long","register",
    "restrict","return","short","signed","sizeof","static","struct","switch",
    "typedef","union","unsigned","void","volatile","while","_Bool","_Complex",
    "_Imaginary","include","define","ifdef","ifndef","endif","pragma","NULL",
    "true","false",
}

PROMPT_TEMPLATE = (
    "Continue the following C code. Reproduce the rest of the program "
    "verbatim, beginning at the next line. Do not add explanation, "
    "comments, or markdown fences.\n\n"
    "{prefix}"
)


def load_pairs():
    seeds = {}
    with open(SEED_FILE) as f:
        for line in f:
            r = json.loads(line)
            if r.get("language") == "c":
                seeds[r["uuid"]] = r
    pairs = []
    with open(VERIFIED_FILE) as f:
        for line in f:
            r = json.loads(line)
            s_uuid = r.get("seed_uuid")
            if s_uuid in seeds:
                pairs.append((seeds[s_uuid], r))
    return pairs


def split_prefix_target(code):
    lines = code.splitlines()
    n = len(lines)
    if not (TOTAL_LINES_RANGE[0] <= n <= TOTAL_LINES_RANGE[1]):
        return None
    p = max(PREFIX_MIN_LINES, min(PREFIX_MAX_LINES, int(n * PREFIX_FRACTION)))
    t = max(TARGET_MIN_LINES, min(TARGET_MAX_LINES, int(n * TARGET_FRACTION)))
    if p + t > n:
        return None
    prefix = "\n".join(lines[:p]) + "\n"
    target = "\n".join(lines[p:p + t])
    return prefix, target, t


def normalised_edit_distance(a, b):
    if not a and not b:
        return 0.0
    return Levenshtein.distance(a, b) / max(len(a), len(b))


def lcs_fraction(a, b):
    if not b:
        return 0.0
    m, n = len(a), len(b)
    prev = [0] * (n + 1)
    best = 0
    for i in range(m):
        cur = [0] * (n + 1)
        ai = a[i]
        for j in range(n):
            if ai == b[j]:
                cur[j + 1] = prev[j] + 1
                if cur[j + 1] > best:
                    best = cur[j + 1]
        prev = cur
    return best / len(b)


def identifiers(code):
    return {tok for tok in ID_RE.findall(code) if tok not in C_KEYWORDS}


def identifier_recall(target, completion):
    tids = identifiers(target)
    if not tids:
        return None
    cids = identifiers(completion)
    return len(tids & cids) / len(tids)


def strip_completion(text, target_lines):
    text = text.strip()
    text = re.sub(r"^```(?:c|cpp|C)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    lines = text.splitlines()
    return "\n".join(lines[:target_lines])


def call_model(client, model, prompt, temperature=0.0, max_tokens=MAX_COMPLETION_TOKENS, extra_body=None):
    kwargs = dict(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
        max_tokens=max_tokens,
    )
    if extra_body:
        kwargs["extra_body"] = extra_body
    resp = client.chat.completions.create(**kwargs)
    return resp.choices[0].message.content or ""


def score(target, completion):
    return {
        "ned": normalised_edit_distance(target, completion),
        "lcs": lcs_fraction(target, completion),
        "idr": identifier_recall(target, completion),
    }


def summarise(records, key, condition):
    vals = [r[f"{condition}_{key}"] for r in records if r.get(f"{condition}_{key}") is not None]
    if not vals:
        return None
    vals.sort()
    n = len(vals)
    mean = sum(vals) / n
    median = vals[n // 2] if n % 2 else 0.5 * (vals[n // 2 - 1] + vals[n // 2])
    return {"n": n, "mean": mean, "median": median,
            "p25": vals[int(0.25 * n)], "p75": vals[int(0.75 * n)]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--model", required=True)
    ap.add_argument("--api-base", required=True)
    ap.add_argument("--api-key", default=os.getenv("API_KEY", "abc123"))
    ap.add_argument("--output", required=True)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--extra-body-json", default=None,
                    help="JSON string passed as extra_body to chat.completions.create (e.g. for DeepSeek thinking toggle)")
    args = ap.parse_args()
    extra_body = json.loads(args.extra_body_json) if args.extra_body_json else None

    random.seed(args.seed)
    print(f"loading matched pairs from {SEED_FILE.name} and {VERIFIED_FILE.name}...", flush=True)
    pairs = load_pairs()
    print(f"  matched pairs available: {len(pairs)}", flush=True)

    eligible = []
    for seed, gen in pairs:
        s = split_prefix_target(seed["code"])
        v = split_prefix_target(gen["code"])
        if s and v:
            eligible.append((seed, gen, s, v))
    print(f"  pairs after length filter: {len(eligible)}", flush=True)

    random.shuffle(eligible)
    sample = eligible[: args.n]
    print(f"  sampled: {len(sample)}", flush=True)

    client = OpenAI(api_key=args.api_key, base_url=args.api_base, timeout=120, max_retries=3)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    f = out_path.open("w")

    t0 = time.time()

    def work(args_):
        i, (seed, gen, (sp, st, st_lines), (vp, vt, vt_lines)) = args_
        rec = {
            "i": i,
            "seed_uuid": seed["uuid"],
            "gen_uuid": gen["uuid"],
            "project": seed.get("project"),
            "cwes": seed.get("cwes"),
            "repo_prefix_lines": sp.count("\n"),
            "repo_target_lines": st_lines,
            "veri_prefix_lines": vp.count("\n"),
            "veri_target_lines": vt_lines,
        }
        for tag, prefix, target, tlines in (("repo", sp, st, st_lines), ("veri", vp, vt, vt_lines)):
            try:
                out = call_model(client, args.model, PROMPT_TEMPLATE.format(prefix=prefix), temperature=args.temperature, extra_body=extra_body)
                comp = strip_completion(out, tlines)
                for k, val in score(target, comp).items():
                    rec[f"{tag}_{k}"] = val
                rec[f"{tag}_completion"] = comp
            except Exception as e:
                rec[f"{tag}_error"] = str(e)
        return rec

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for i, rec in enumerate(ex.map(work, enumerate(sample, 1)), 1):
            f.write(json.dumps(rec) + "\n")
            f.flush()
            if i % 10 == 0 or i == len(sample):
                print(f"  [{i}/{len(sample)}]  elapsed {time.time() - t0:.1f}s", flush=True)

    f.close()

    # Summary
    records = [json.loads(line) for line in out_path.open()]
    print()
    print(f"=== summary  (model={args.model}, n={len(records)}) ===")
    for k, label in [("ned","norm. edit distance"), ("lcs","longest-common-substring frac"), ("idr","identifier recall")]:
        repo_s = summarise(records, k, "repo")
        veri_s = summarise(records, k, "veri")
        if repo_s and veri_s:
            arrow = "lower" if k == "ned" else "higher"
            print(f"  {label:34s}  REPO  median={repo_s['median']:.3f}  mean={repo_s['mean']:.3f}   "
                  f"VERI  median={veri_s['median']:.3f}  mean={veri_s['mean']:.3f}  ({arrow} = more memorised)")


if __name__ == "__main__":
    sys.exit(main())
