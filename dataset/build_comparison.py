"""Writes data/comparison from the evaluation samples and the function samples of the comparison corpora.

    python dataset/build_comparison.py --samples <dir with <Corpus>_samples.json> --realism <dir with func_<corpus>.jsonl> --out ../data/comparison

ICVul, FormAI and ARVO are shipped with their code because their licenses allow redistribution. TitanVul and Mono
are withheld: only identifiers, CWEs and SHA-256 hashes of the code are written, and
experiments/benchmark/datasets/rebuild_withheld_samples.py rebuilds the samples from the original corpora.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

SHIPPED = {"ICVul": "icvul", "FormAI": "formai", "ARVO": "arvo"}
WITHHELD = {"TitanVul": "titanvul", "Mono": "mono"}


def sha(text):
    return hashlib.sha256((text or "").encode()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", required=True)
    ap.add_argument("--realism", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out)
    for name, folder in {**SHIPPED, **WITHHELD}.items():
        d = out / folder
        d.mkdir(parents=True, exist_ok=True)
        pairs = json.load(open(Path(args.samples) / f"{name}_samples.json"))
        funcs = [json.loads(line) for line in open(Path(args.realism) / f"func_{folder}.jsonl")]
        if name in SHIPPED:
            with open(d / "eval_samples.jsonl", "w") as f:
                for p in pairs:
                    f.write(json.dumps(p) + "\n")
            with gzip.open(d / "function_samples.jsonl.gz", "wt", compresslevel=9) as f:
                for r in funcs:
                    f.write(json.dumps(r) + "\n")
        else:
            keep = ("pair_id", "primary_cwe", "cwe_id", "language", "cve_id", "file_name")
            with open(d / "eval_sample_ids.jsonl", "w") as f:
                for p in pairs:
                    rec = {k: p.get(k) for k in keep}
                    rec.update(vulnerable_sha256=sha(p["vulnerable_code"]), patched_sha256=sha(p["patched_code"]))
                    f.write(json.dumps(rec) + "\n")
            with open(d / "function_sample_ids.jsonl", "w") as f:
                for r in funcs:
                    f.write(json.dumps({"id": r["id"], "language": r["language"], "code_sha256": sha(r["code"])}) + "\n")
        print(name, len(pairs), len(funcs))


if __name__ == "__main__":
    main()
