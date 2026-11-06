"""Embedding wins of VeriVul over FormAI, per expansion model.

Counts, over 12 cells (per-dimension KS, centroid distance and MMD against ICVul, TitanVul, Mono and ARVO), how
often equal-size subsamples of VeriVul programs are closer than FormAI. Needs the code-encoder embeddings of all
vulnerable VeriVul programs (emb_all_verivul.npy, row order = ids_all_verivul.json) and of the comparison corpora
(emb_<tag>_<dataset>.npy from embed_datasets.py).

    python sensitivity.py --embeddings DIR --tag jinav2code --n 300 --seeds 5
"""
import argparse
import collections
import json
import os
from pathlib import Path

import numpy as np

from cluster_analysis import centroid_dist, l2_normalize, mmd_rbf, per_dim_ks

ROOT = Path(__file__).resolve().parent
RELEASE = Path(os.environ.get("VERIVUL_RELEASE", ROOT / ".." / ".." / ".." / "data" / "verivul.jsonl"))
REAL = ("icvul", "titanvul", "mono", "arvo")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--embeddings", required=True)
    ap.add_argument("--tag", default="jinav2code")
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--seeds", type=int, default=5)
    args = ap.parse_args()
    d = Path(args.embeddings)
    ids = json.load(open(d / "ids_all_verivul.json"))
    model = {}
    for line in open(RELEASE):
        r = json.loads(line)
        model[r["id"]] = r["generation_model"]
    emb = l2_normalize(np.load(d / "emb_all_verivul.npy"))
    partners = {k: l2_normalize(np.load(d / f"emb_{args.tag}_{k}.npy")) for k in REAL + ("formai",)}
    groups = collections.defaultdict(list)
    for i, u in enumerate(ids):
        groups[model[u]].append(i)
    scenarios = {k: emb[v] for k, v in groups.items() if len(v) >= args.n}
    scenarios["whole release"] = emb
    for name, X in scenarios.items():
        wins = []
        for s in range(args.seeds):
            rng = np.random.default_rng(s)
            sub = lambda A: A[rng.choice(len(A), min(args.n, len(A)), replace=False)]
            xs, fa, w = sub(X), sub(partners["formai"]), 0
            for p in REAL:
                y = sub(partners[p])
                dist = lambda z: (per_dim_ks(z, y, seed=s)["ks_mean"], centroid_dist(z, y), mmd_rbf(z, y, seed=s)["mmd"])
                w += sum(a < b for a, b in zip(dist(xs), dist(fa)))
            wins.append(w)
        print(f"{name:20s} n={len(X):6d} wins/12 mean={np.mean(wins):.1f} min={min(wins)} max={max(wins)}")


if __name__ == "__main__":
    main()
