"""
ICVul → universal slicer input adapter.

Reads:
  - ICVul-Dataset/function_info.csv  (before/after function code)
  - ICVul-Dataset/cve_fc_vcc_mapping.csv  (CVE → fixing commit)
  - ICVul-Dataset/commit_info.csv  (commit messages)
  - ICVul-Dataset/repository_info.csv  (project names, repo URLs)

Produces a JSONL in the universal slicer input format.

Usage:
    python -m slicer.adapters.icvul \\
        --dataset-dir /path/to/ICVul/ICVul-Dataset \\
        --output /path/to/output.jsonl
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import uuid
from collections import defaultdict
from pathlib import Path

csv.field_size_limit(10_000_000)


def _extract_fname(code: str) -> str:
    """Heuristic: extract function name from C/C++ function source."""
    m = re.search(r"\b(\w+)\s*\(", code)
    return m.group(1) if m else ""


def build(dataset_dir: Path, output: Path) -> None:
    print(f"Loading CSVs from {dataset_dir} …")

    # ── Load CSVs ─────────────────────────────────────────────────────────────
    def load_csv(name):
        with open(dataset_dir / name, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    mapping_rows = load_csv("cve_fc_vcc_mapping.csv")
    commit_rows = load_csv("commit_info.csv")
    func_rows = load_csv("function_info.csv")
    repo_rows = load_csv("repository_info.csv")

    # ── Lookups ───────────────────────────────────────────────────────────────
    commit_msg = {r["hash"]: r["msg"] for r in commit_rows}
    repo_project = {r["repo_url"]: r["repo_name"] for r in repo_rows}

    # fc_hash → [(cve, cwe, repo_url)]
    fc_to_cves: dict[str, list[dict]] = defaultdict(list)
    for r in mapping_rows:
        fc_to_cves[r["fc_hash"]].append(
            {"cve": r["cve_id"], "cwe": r["cwe_id"], "repo_url": r["repo_url"]}
        )

    # Group functions by commit hash
    before_by_hash: dict[str, list[dict]] = defaultdict(list)
    after_by_hash_name: dict[tuple, str] = {}
    for r in func_rows:
        h = r["hash"]
        name = r["name"]
        fn = r["filename"]
        code = r["code"].strip()
        if r["before_change"] == "True":
            before_by_hash[h].append({"name": name, "filename": fn, "code": code})
        else:
            after_by_hash_name[(h, name, fn)] = code

    # ── Build records ─────────────────────────────────────────────────────────
    records = []
    for fc_hash, cve_entries in fc_to_cves.items():
        funcs = before_by_hash.get(fc_hash)
        if not funcs:
            continue

        msg = commit_msg.get(fc_hash, "")

        for cve_entry in cve_entries:
            repo_url = cve_entry["repo_url"]
            project = repo_project.get(repo_url, "")
            cwe = cve_entry["cwe"]

            for func in funcs:
                code = func["code"]
                if not code:
                    continue

                # Find matching after-change version
                key = (fc_hash, func["name"], func["filename"])
                fixed_code = after_by_hash_name.get(key)

                # Neighbor functions = other before-change functions in this commit
                neighbors = [
                    {"name": f["name"], "code": f["code"]}
                    for f in funcs
                    if f["code"] != code
                ]

                records.append({
                    "uuid": str(uuid.uuid4()),
                    "code": code,
                    "language": "c",
                    "fixed_code": fixed_code,
                    "cwes": [cwe] if cwe else [],
                    "neighbor_functions": neighbors if neighbors else None,
                    "project": project,
                    "dataset": "ICVul",
                    "commit_hash": fc_hash,
                    "cve": cve_entry["cve"],
                    "repo_url": repo_url,
                    "commit_message": msg,
                })

    # ── Write ─────────────────────────────────────────────────────────────────
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    n_with_fixed = sum(1 for r in records if r.get("fixed_code"))
    n_with_neighbors = sum(1 for r in records if r.get("neighbor_functions"))
    print(f"  {len(records)} records written to {output}")
    print(f"  with fixed_code: {n_with_fixed} ({n_with_fixed/len(records):.0%})")
    print(f"  with neighbors:  {n_with_neighbors} ({n_with_neighbors/len(records):.0%})")


def main():
    parser = argparse.ArgumentParser(
        description="Convert ICVul dataset to universal slicer input."
    )
    parser.add_argument(
        "--dataset-dir", type=Path,
        default=Path(__file__).resolve().parents[2] / "ICVul" / "ICVul-Dataset",
        help="Path to ICVul-Dataset directory",
    )
    parser.add_argument(
        "--output", type=Path,
        default=Path(__file__).resolve().parents[2] / "Processed" / "icvul_slicer_input.jsonl",
    )
    args = parser.parse_args()
    build(args.dataset_dir, args.output)


if __name__ == "__main__":
    main()
