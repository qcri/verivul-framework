"""Runs the bounded sanitizer search on SAFE C and C++ programs.

    python dataset/rerun_safe_sanitizer.py --input export.jsonl --out safe_rerun.jsonl --image esbmc:8.4

Each input record needs uuid, label, language and code. The output has one record per program with the
search result (no_crash_found or counterexample_found), the sanitizer kind, function and line of a finding, the
number of runs, and the finding's report and input.
"""
import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.utils.dynamic_confirm import confirm, summary


def one(job, budget, image):
    uuid, language, code = job
    res = confirm(code, language, "SAFE", budget=budget, image=image)
    s = summary(res)
    f = s.get("finding") or {}
    return {"uuid": uuid, "language": language, "result": res.get("result"), "runs": s.get("runs"),
            "env_dependent": s.get("env_dependent"), "channels": s.get("channels"), "kind": f.get("kind"),
            "line": f.get("line"), "function": f.get("function"), "report": (f.get("report") or "")[:6000],
            "input_b64": f.get("input_b64"), "elapsed_s": s.get("elapsed_s"), "error": s.get("error")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--image", default="esbmc:8.4")
    ap.add_argument("--budget", type=int, default=40)
    ap.add_argument("--workers", type=int, default=14)
    args = ap.parse_args()
    jobs = []
    for line in open(args.input):
        r = json.loads(line)
        if r["label"] == "SAFE" and r["language"] in ("c", "cpp"):
            jobs.append((r["uuid"], r["language"], r["code"]))
    print("SAFE C/C++ programs", len(jobs), flush=True)
    t = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex, open(args.out, "w") as out:
        for i, rec in enumerate(ex.map(lambda j: one(j, args.budget, args.image), jobs), 1):
            out.write(json.dumps(rec) + "\n")
            out.flush()
            if i % 200 == 0:
                print(i, round(time.time() - t), flush=True)


if __name__ == "__main__":
    main()
