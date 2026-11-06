"""Writes id lists and the verified-pair list that accompany data/verivul.jsonl.

    python dataset/build_subsets.py --release ../data/verivul.jsonl --out ../data/subsets
"""
import argparse
import json
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rows = [json.loads(line) for line in open(args.release)]
    subsets = {
        "ids_c_cpp.txt": lambda r: r["language"] in ("c", "cpp"),
        "ids_python.txt": lambda r: r["language"] == "python",
        "ids_strict.txt": lambda r: not r["flags"]["sanitizer_counterexample_on_safe"] and not r["flags"]["empty_main"],
        "ids_env_independent.txt": lambda r: not r["flags"]["env_dependent"],
        "ids_flagged.txt": lambda r: r["flags"]["sanitizer_counterexample_on_safe"] or r["flags"]["empty_main"],
        "ids_vulnerable_exact.txt": lambda r: r["label"] == "VULNERABLE" and (r["sanitizer"] or {}).get("level") == "confirmed_exact",
    }
    for name, keep in subsets.items():
        ids = [r["id"] for r in rows if keep(r)]
        open(out / name, "w").write("\n".join(ids) + "\n")
        print(name, len(ids))
    with open(out / "pairs.jsonl", "w") as f:
        for r in rows:
            if r["label"] == "VULNERABLE":
                for other in r["pair_ids"]:
                    f.write(json.dumps({"vulnerable_id": r["id"], "safe_id": other, "seed_id": r["seed_id"], "cwes": r["cwes"],
                                        "language": r["language"]}) + "\n")
    with open(out / "flagged.jsonl", "w") as f:
        for r in rows:
            if any(r["flags"].values()):
                f.write(json.dumps({"id": r["id"], "label": r["label"], "flags": r["flags"]}) + "\n")


if __name__ == "__main__":
    main()
