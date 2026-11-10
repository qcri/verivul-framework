"""Builds the VeriVul evaluation sets from the released dataset.

    python build_eval_sets.py --release verivul.jsonl --out evaluation

seed_matched_400.jsonl: 50 vulnerable/safe pairs for each of eight CWEs (CWE-20, 119, 120, 125, 190, 401, 416, 476).
A pair is a vulnerable and a safe program that derive from the same seed; the CWE is the first target CWE of the
vulnerable program. Programs with a sanitizer counterexample on a safe label or an empty main are excluded.
verified_pairs_98.jsonl: every verified parent/child pair with opposite labels.
"""
import argparse
import collections
import itertools
import json
import random
from pathlib import Path

CWES = ["CWE-119", "CWE-120", "CWE-125", "CWE-190", "CWE-20", "CWE-401", "CWE-416", "CWE-476"]


def load(path):
    rows = [json.loads(line) for line in open(path)]
    return [r for r in rows if r["language"] in ("c", "cpp") and not r["flags"]["sanitizer_counterexample_on_safe"]
            and not r["flags"]["empty_main"]]


def target(r):
    return [c for c in r["cwes"] if c in CWES][:1]


def pair(a, b, cwe, real):
    return {"pair_id": a["id"] + "|" + b["id"], "cwe": cwe, "vulnerable_id": a["id"], "safe_id": b["id"],
            "language": "C" if a["language"] == "c" else "C++", "vulnerable_code": a["code"], "safe_code": b["code"],
            "trigger_line_number": a["trigger_line_number"], "trigger_line": a["trigger_line"], "verified_pair": real}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rows = load(args.release)
    by = collections.defaultdict(lambda: {"V": [], "S": []})
    for r in rows:
        by[r["seed_id"]]["V" if r["label"] == "VULNERABLE" else "S"].append(r)
    candidates = collections.defaultdict(list)
    for v in by.values():
        for a, b in zip(v["V"], v["S"]):
            if target(a):
                candidates[target(a)[0]].append((a, b))
    rng = random.Random(42)
    chosen = []
    for cwe in CWES:
        pool = candidates[cwe]
        rng.shuffle(pool)
        seen, first, rest = set(), [], []
        for a, b in pool:
            (rest if a["seed_id"] in seen else first).append((a, b))
            seen.add(a["seed_id"])
        chosen += [pair(a, b, cwe, False) for a, b in (first + rest)[:50]]
    have = {(p["vulnerable_id"], p["safe_id"]) for p in chosen}
    count = collections.Counter(p["cwe"] for p in chosen)
    rng = random.Random(7)
    for cwe in CWES:
        need = 50 - count[cwe]
        if need <= 0:
            continue
        pool = [(a, b) for v in by.values() for a, b in itertools.product(v["V"], v["S"])
                if (a["id"], b["id"]) not in have and target(a)[:1] == [cwe]]
        rng.shuffle(pool)
        used, picked = set(), []
        for a, b in pool:
            if a["id"] in used or b["id"] in used:
                continue
            picked.append((a, b))
            used |= {a["id"], b["id"]}
            if len(picked) == need:
                break
        chosen += [pair(a, b, cwe, False) for a, b in picked]
    by_id = {r["id"]: r for r in rows}
    verified = []
    for r in rows:
        p = by_id.get(r["parent_id"]) if r["parent_id"] else None
        if p and p["label"] != r["label"]:
            v, s = (p, r) if p["label"] == "VULNERABLE" else (r, p)
            verified.append(pair(v, s, v["cwes"][0] if v["cwes"] else "NONE", True))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, data in (("seed_matched_400.jsonl", chosen), ("verified_pairs_98.jsonl", verified)):
        with open(out / name, "w") as f:
            for p in data:
                f.write(json.dumps(p) + "\n")
    with open(out / "trigger_ground_truth.jsonl", "w") as f:
        for p in chosen:
            f.write(json.dumps({"uuid": p["pair_id"], "label": "VULNERABLE", "trigger_line_number": p["trigger_line_number"],
                                "trigger_line": p["trigger_line"]}) + "\n")
    print(len(chosen), len(verified))


if __name__ == "__main__":
    main()
