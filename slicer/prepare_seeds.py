"""Turn sliced records into the seed file the pipeline consumes.

Adds `target_cwe` / `target_cwe_source`: the seed's own CWE when ESBMC can
verify it, otherwise a deterministic (uuid-seeded) choice among the verifiable
classes.  Nothing is dropped except byte-identical duplicate functions.

    python -m slicer.prepare_seeds --input a.sliced.jsonl [b.sliced.jsonl ...] --output seeds.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
from collections import Counter
from pathlib import Path

VERIFIABLE = {
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126", "CWE-127",
    "CWE-129", "CWE-131", "CWE-190", "CWE-191", "CWE-193", "CWE-369", "CWE-401", "CWE-415",
    "CWE-416", "CWE-476", "CWE-590", "CWE-787", "CWE-788", "CWE-823", "CWE-825",
}
ASSIGNABLE = ["CWE-119", "CWE-120", "CWE-125", "CWE-787", "CWE-190", "CWE-476",
              "CWE-416", "CWE-415", "CWE-590", "CWE-401"]
PY_ASSIGNABLE = ["CWE-190", "CWE-476", "CWE-119"]
SOL_ASSIGNABLE = ["CWE-190", "CWE-841", "CWE-284"]
CWE_RE = re.compile(r"CWE-\d+|NVD-CWE-[A-Za-z]+")


def normalise_cwes(value) -> list[str]:
    items = value if isinstance(value, list) else CWE_RE.findall(str(value or ""))
    return sorted({str(c).strip() for c in items if str(c).strip()})


def choose_target(rec: dict) -> tuple[str, str]:
    cwes = normalise_cwes(rec.get("cwes"))
    own = [c for c in cwes if c in VERIFIABLE]
    lang = (rec.get("language") or "c").lower()
    pool = PY_ASSIGNABLE if lang == "python" else SOL_ASSIGNABLE if lang == "solidity" else ASSIGNABLE
    if own:
        if lang not in ("python", "solidity") or own[0] in pool:
            return own[0], "seed"
    rng = random.Random(int(hashlib.sha256(rec["uuid"].encode()).hexdigest(), 16))
    return rng.choice(pool), "assigned"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", nargs="+", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    seen: set[str] = set()
    stats = Counter()
    out = []
    for path in args.input:
        for line in open(path, encoding="utf-8"):
            rec = json.loads(line)
            h = hashlib.sha256(rec["code"].encode("utf-8", "replace")).hexdigest()
            if h in seen:
                stats["duplicate_code"] += 1
                continue
            seen.add(h)
            rec["cwes"] = normalise_cwes(rec.get("cwes"))
            if not rec.get("slice_code"):
                rec["slice_code"] = rec["code"]
                rec["criterion_source"] = rec.get("criterion_source") or "none"
                stats["slice_fallback_whole_function"] += 1
            rec["target_cwe"], rec["target_cwe_source"] = choose_target(rec)
            stats["target_" + rec["target_cwe_source"]] += 1
            stats["lang_" + (rec.get("language") or "?")] += 1
            stats["criterion_" + str(rec.get("criterion_source"))] += 1
            out.append(rec)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        for rec in out:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"{len(out)} seeds -> {args.output}")
    for k, v in sorted(stats.items()):
        print(f"  {v:7d}  {k}")
    print("  target CWE distribution:", Counter(r["target_cwe"] for r in out).most_common(12))


if __name__ == "__main__":
    main()
