"""Builds data/reposvul_sliced.jsonl (seed functions) and data/verified_samples.jsonl
(one release program per seed) for contamination_probe.py.

    python prepare_pairs.py --release verivul.jsonl --seeds seeds.jsonl
"""
import argparse
import collections
import json
import random
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--release", required=True, help="released programs (data/verivul.jsonl)")
ap.add_argument("--seeds", required=True, help="seed functions (JSONL with uuid, code, language, project, cwes)")
ap.add_argument("--out", default="data")
args = ap.parse_args()

seeds = {}
for line in open(args.seeds):
    r = json.loads(line)
    if r.get("language") == "c":
        seeds[r["uuid"]] = r
progs = collections.defaultdict(list)
for line in open(args.release):
    r = json.loads(line)
    if r.get("language") == "c" and r["seed_id"] in seeds:
        progs[r["seed_id"]].append(r)

out = Path(args.out)
out.mkdir(exist_ok=True)
rng = random.Random(42)
with open(out / "reposvul_sliced.jsonl", "w") as f:
    for u in progs:
        f.write(json.dumps(seeds[u]) + "\n")
with open(out / "verified_samples.jsonl", "w") as f:
    for u in sorted(progs):
        r = rng.choice(progs[u])
        f.write(json.dumps({"uuid": r["id"], "seed_uuid": u, "code": r["code"], "label": r["label"]}) + "\n")
print(len(progs), "seeds with a released C program")
