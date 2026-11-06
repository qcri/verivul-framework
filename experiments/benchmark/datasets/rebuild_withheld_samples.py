"""Rebuilds the TitanVul and Mono samples from the original corpora and checks them against the shipped hashes.

    python rebuild_withheld_samples.py --external /path/to/corpora --manifest ../../../../data/comparison --out rebuilt

--external holds TitanVul/TitanVul.csv and monoVul/*.json. For each corpus the script writes eval_samples.jsonl (the
LLM evaluation pairs) and function_samples.jsonl (the realism sample) and reports how many records match the SHA-256
hashes in data/comparison/<corpus>/.
"""
import argparse
import glob
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent / "realism"))
from convert_datasets import norm_str


def sha(text):
    return hashlib.sha256((text or "").encode()).hexdigest()


def titanvul_pairs(external, ids):
    df = pd.read_csv(Path(external) / "TitanVul" / "TitanVul.csv")
    out = {}
    for pid in ids:
        row = df.iloc[int(pid.split("_")[1])]
        out[pid] = (norm_str(row["func_before"]), norm_str(row["func_after"]))
    return out


def mono_pairs(external, ids):
    wanted = set(ids)
    out = {}
    for path in sorted(glob.glob(str(Path(external) / "monoVul" / "*.json"))):
        try:
            d = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        cve = norm_str(d.get("cve_id"))
        for commit_hash, commit in d.get("commits", {}).items():
            for idx, patch in enumerate(commit.get("patches", [])):
                pid = f"Mono_{cve}_{commit_hash[:8]}_{idx}"
                if pid in wanted:
                    out[pid] = (norm_str(patch.get("func_before")), norm_str(patch.get("func_after")))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--external", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.mkdtemp()
    os.environ.update(EXTERNAL_DATASETS=args.external, REALISM_DIR=tmp)
    import sample_realism
    sample_realism.build_titanvul()
    sample_realism.build_mono()
    for corpus, folder, finder in (("TitanVul", "titanvul", titanvul_pairs), ("Mono", "mono", mono_pairs)):
        manifest = [json.loads(line) for line in open(Path(args.manifest) / folder / "eval_sample_ids.jsonl")]
        found = finder(args.external, [m["pair_id"] for m in manifest])
        ok = 0
        with open(out / f"{corpus}_eval_samples.jsonl", "w") as f:
            for m in manifest:
                before, after = found.get(m["pair_id"], (None, None))
                good = sha(before) == m["vulnerable_sha256"] and sha(after) == m["patched_sha256"]
                ok += good
                f.write(json.dumps({**{k: v for k, v in m.items() if not k.endswith("sha256")}, "vulnerable_code": before, "patched_code": after, "hash_match": good}) + "\n")
        print(f"{corpus} evaluation pairs: {ok}/{len(manifest)} match the shipped hashes")
        ids = [json.loads(line) for line in open(Path(args.manifest) / folder / "function_sample_ids.jsonl")]
        rebuilt = [json.loads(line) for line in open(Path(tmp) / f"func_{folder}.jsonl")]
        have = {(r["id"], sha(r["code"])) for r in rebuilt}
        match = sum((m["id"], m["code_sha256"]) in have for m in ids)
        with open(out / f"{corpus}_function_samples.jsonl", "w") as f:
            for r in rebuilt:
                f.write(json.dumps(r) + "\n")
        print(f"{corpus} function samples: {match}/{len(ids)} match the shipped hashes")


if __name__ == "__main__":
    main()
