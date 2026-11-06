"""Writes data/verivul.parquet, a flat table of the scalar fields of data/verivul.jsonl (no traces, inputs or logs).

    python dataset/build_parquet.py --release ../data/verivul.jsonl --out ../data/verivul.parquet
"""
import argparse
import json

import pyarrow as pa
import pyarrow.parquet as pq


def flat(r):
    v, s, o, f, p = r["verification"], r["sanitizer"] or {}, r["origin"], r["flags"], r["provenance"]
    return {
        "id": r["id"], "seed_id": r["seed_id"], "parent_id": r["parent_id"], "pair_ids": r["pair_ids"], "label": r["label"],
        "language": r["language"], "code": r["code"], "code_sha256": r["code_sha256"], "loc": r["loc"],
        "generation_model": r["generation_model"], "generation_batch": r["generation_batch"], "source_corpus": o["corpus"],
        "cve": o["cve"], "project": o["project"], "repo_url": o["repo_url"], "commit_hash": o["commit_hash"], "cwes": r["cwes"],
        "cwe_source": r["cwe_source"], "seed_cwes": r["seed_cwes"], "esbmc_cwes": r["esbmc_cwes"],
        "esbmc_cwe_source": r["esbmc_cwe_source"], "category": r["category"], "property": r["property"],
        "property_function": r["property_function"], "property_line": r["property_line"],
        "trigger_line_number": r["trigger_line_number"], "trigger_line": r["trigger_line"],
        "trigger_in_program": r["trigger_in_program"], "esbmc_version": v["esbmc_version"], "esbmc_verdict": v["verdict"],
        "esbmc_proof": v["proof"], "esbmc_k": v["k"], "esbmc_timeout_s": v["timeout_s"], "esbmc_memlimit_mb": v["memlimit_mb"],
        "esbmc_duration_s": v["duration_s"], "sanitizer_level": s.get("level"), "sanitizer_kind": s.get("kind"),
        "sanitizer_runs": s.get("runs"), "sanitizer_stage": s.get("stage"), "flag_sanitizer_counterexample_on_safe": f["sanitizer_counterexample_on_safe"],
        "flag_empty_main": f["empty_main"], "flag_lexically_obvious": f["lexically_obvious"], "flag_env_dependent": f["env_dependent"],
        "created_at": p["created_at"],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rows = [flat(json.loads(line)) for line in open(args.release)]
    cols = {k: [r[k] for r in rows] for k in rows[0]}
    pq.write_table(pa.table(cols), args.out, compression="zstd")
    print(len(rows), "rows,", len(cols), "columns")


if __name__ == "__main__":
    main()
