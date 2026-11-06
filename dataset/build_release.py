"""Builds the released dataset files from two pipeline exports.

Each export is a slim JSONL (one record per program) with a companion log JSONL (esbmc_log, witnesses,
SARIF results). Usage:

    python dataset/build_release.py --batch A=slim_a.jsonl,logs_a.jsonl --batch B=slim_b.jsonl,logs_b.jsonl \
        --safe-rerun safe_rerun.jsonl --out ../data
"""
import argparse
import collections
import gzip
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.agents.esbmc_verification import cwes_from_esbmc_annotation, infer_cwes_from_esbmc_log

SHARD = 1000
EXCERPT = 4000
CWE = re.compile(r"CWE-\d+|NVD-CWE-\w+")
MODEL = {"gpt-oss": "gpt-oss-120b"}
EMPTY_MAIN = re.compile(r"\bmain\s*\([^)]*\)\s*\{(.*?)\n\}", re.S)
EMPTY_BODY = re.compile(r"\s*(return\s+\d*\s*;)?\s*")
COMMENTS = re.compile(r"//.*|/\*.*?\*/", re.S)
BUDGET = re.compile(r"--timeout (\d+)s --memlimit (\d+)m")


def empty_main(code, language):
    if language not in ("c", "cpp"):
        return False
    m = EMPTY_MAIN.search(code)
    return bool(m) and EMPTY_BODY.fullmatch(COMMENTS.sub("", m.group(1))) is not None


def excerpt(log):
    lines = (log or "").split("\n")
    head = []
    for i, line in enumerate(lines):
        if "Violated property" in line:
            head = lines[i:i + 25]
            break
    text = "\n".join(head + ["..."] + lines[-8:]) if head else "\n".join(lines[-12:])
    return text[:EXCERPT]


def cwe_list(value):
    return value if isinstance(value, list) else CWE.findall(str(value or ""))


def read_logs(path, shard_dir, batch, shards):
    info = {}
    out = None
    n = 0
    with open(path) as f:
        for line in f:
            if n % SHARD == 0:
                if out:
                    out.close()
                name = f"esbmc_logs_{batch}_{n // SHARD:03d}.jsonl.gz"
                shards.append(name)
                out = gzip.open(shard_dir / name, "wt", compresslevel=9)
            r = json.loads(line)
            log = r.get("esbmc_log") or ""
            annotated = cwes_from_esbmc_annotation(log)
            info[r["uuid"]] = {
                "excerpt": excerpt(log),
                "esbmc_cwes": annotated or infer_cwes_from_esbmc_log(log),
                "esbmc_cwe_source": "esbmc" if annotated else "rules",
                "shard": shards[-1],
            }
            out.write(json.dumps({"id": r["uuid"], "esbmc_log": log, "witness_graphml": r.get("witness_graphml"),
                                  "witness_yaml": r.get("witness_yaml"), "sarif_results": r.get("sarif_results"),
                                  "violated_properties": r.get("violated_properties")}) + "\n")
            n += 1
    if out:
        out.close()
    return info


def verification(v, log_info):
    m = BUDGET.search(v.get("command") or "")
    return {"esbmc_version": v.get("esbmc_version"), "command": v.get("command"), "image": v.get("image"),
            "image_digest": v.get("image_digest"), "timeout_s": int(m.group(1)) if m else None,
            "memlimit_mb": int(m.group(2)) if m else None, "duration_s": v.get("duration_s"), "verdict": v.get("verdict"),
            "proof": v.get("proof"), "k": v.get("k"), "log_excerpt": log_info["excerpt"], "log_shard": log_info["shard"]}


def sanitizer_vulnerable(r):
    s = r["sanitizer"] or {}
    stage = None
    if s.get("runs") is not None:
        stage = "afl" if s.get("afl") else "seeded" if s.get("seeded") else "search"
    return {"level": s.get("result"), "kind": r.get("sanitizer_kind"), "cwes": r.get("sanitizer_cwes") or [], "runs": s.get("runs"),
            "stage": stage, "channels": s.get("channels"), "env_apis": s.get("env_apis"), "trace": s.get("trace"),
            "input_b64": s.get("input_b64")}


def sanitizer_safe(rerun):
    crash = rerun["result"] == "counterexample_found"
    return {"level": "crash_found" if crash else "no_crash_found", "kind": rerun.get("kind"), "function": rerun.get("function"),
            "line": rerun.get("line"), "runs": rerun.get("runs"), "channels": rerun.get("channels"),
            "trace": rerun.get("report") if crash else None, "input_b64": rerun.get("input_b64") if crash else None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch", action="append", required=True, help="NAME=slim.jsonl,logs.jsonl")
    ap.add_argument("--safe-rerun", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out)
    shard_dir = out / "logs"
    shard_dir.mkdir(parents=True, exist_ok=True)
    rerun = {}
    for line in open(args.safe_rerun):
        r = json.loads(line)
        rerun[r["uuid"]] = r
    rows, logs, shards = [], {}, []
    for spec in args.batch:
        name, files = spec.split("=")
        slim, logf = files.split(",")
        logs.update(read_logs(logf, shard_dir, name, shards))
        for line in open(slim):
            r = json.loads(line)
            r["batch"] = name
            rows.append(r)
    by_id = {r["uuid"]: r for r in rows}
    pair_ids = collections.defaultdict(list)
    for r in rows:
        p = by_id.get(r["parent_uuid"]) if r["parent_uuid"] else None
        if p and p["label"] != r["label"]:
            pair_ids[r["uuid"]].append(p["uuid"])
            pair_ids[p["uuid"]].append(r["uuid"])
    records = []
    mismatch = 0
    for r in rows:
        code = r["code"]
        sha = hashlib.sha256(code.encode()).hexdigest()
        mismatch += sha != r["verified_code_hash"]
        vul = r["label"] == "VULNERABLE"
        cwes = cwe_list(r["cwes"])
        if not vul:
            cwes = sorted({c for o in pair_ids[r["uuid"]] for c in cwe_list(by_id[o]["cwes"])})
        info = logs[r["uuid"]]
        metrics = r["metrics"] or {}
        san = sanitizer_vulnerable(r) if vul else (sanitizer_safe(rerun[r["uuid"]]) if r["uuid"] in rerun else None)
        crash = (not vul) and san is not None and san["level"] == "crash_found"
        env = r["env_dependent"] if vul else (rerun[r["uuid"]].get("env_dependent") if r["uuid"] in rerun else None)
        rec = {
            "id": r["uuid"], "seed_id": r["seed_uuid"], "parent_id": r["parent_uuid"], "pair_ids": pair_ids.get(r["uuid"], []),
            "label": r["label"], "language": r["language"], "code": code, "code_sha256": sha, "loc": len(code.split("\n")),
            "generation_model": MODEL.get(r["generation_model"], r["generation_model"]), "generation_batch": r["batch"],
            "origin": {"corpus": r["dataset"], "cve": r["cve"], "project": r["project"], "repo_url": r["repo_url"],
                       "commit_hash": r["commit_hash"]},
            "cwes": cwes, "cwe_source": metrics.get("target_cwe_source") if vul else None, "seed_cwes": metrics.get("seed_cwes") or [],
            "esbmc_cwes": info["esbmc_cwes"] if vul else [], "esbmc_cwe_source": info["esbmc_cwe_source"] if vul and info["esbmc_cwes"] else None,
            "category": r["category"], "property": r["property"], "property_function": r["property_function"],
            "property_line": r["property_line"], "trigger_line_number": r["trigger_line_number"], "trigger_line": r["trigger_line"],
            "trigger_in_program": r["in_program"],
            "verification": verification(r["verifier"], info), "sanitizer": san,
            "flags": {"sanitizer_counterexample_on_safe": crash, "empty_main": empty_main(code, r["language"]),
                      "lexically_obvious": bool(r["lexically_obvious"]), "env_dependent": bool(env)},
            "provenance": {"created_at": (r["created_at"] or "")[:10]},
        }
        records.append(rec)
    with open(out / "verivul.jsonl", "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    with open(out / "logs" / "index.json", "w") as f:
        json.dump({r["id"]: logs[r["id"]]["shard"] for r in records}, f)
    flags = collections.Counter(k for rec in records for k, v in rec["flags"].items() if v)
    print(len(records), dict(collections.Counter(r["label"] for r in records)), dict(flags), "hash mismatches", mismatch)


if __name__ == "__main__":
    main()
