"""Stage outcomes of the generation run from the pipeline's REST API.

    python dataset/yield_statistics.py --api http://localhost:54333 --out yield.json

Counts generated programs by language and status (generation failure, compilation failure, ESBMC verdict, timeout,
resource error). Appendix E of the paper reports the C and C++ rows.
"""
import argparse
import collections
import json
import urllib.request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://localhost:54333")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rows, skip = [], 0
    while True:
        with urllib.request.urlopen(f"{args.api}/api/snippets?skip={skip}&limit=1000", timeout=120) as r:
            page = json.load(r)
        rows += page
        skip += len(page)
        if len(page) < 1000:
            break
    generated = [r for r in rows if r["type"] == "GENERATED"]
    table = collections.defaultdict(collections.Counter)
    for r in generated:
        table[r["language"]][r["status"]] += 1
        table["all"][r["status"]] += 1
        table[f"model:{r['generation_model']}:{r['language']}"][r["status"]] += 1
    json.dump({k: dict(v) for k, v in table.items()}, open(args.out, "w"), indent=1)
    for k in ("c", "cpp"):
        print(k, dict(table[k]))


if __name__ == "__main__":
    main()
