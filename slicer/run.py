"""
Generic slicer CLI.

Reads a JSONL file in the universal slicer input format:

  Required:  uuid, code, language
  Slicing:   fixed_code, cwes, neighbor_functions
  Passthru:  everything else (project, dataset, cve, commit_hash, …)

Produces a JSONL with the original fields plus:
  slice_code, slice_lines, criterion_lines,
  slice_stmts_before, slice_stmts_after, inter_proc_calls

Usage:
    python -m slicer.run --input in.jsonl --output out.jsonl [--workers N] [--limit N]
"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path


# ── Worker ────────────────────────────────────────────────────────────────────


def _process_record(record: dict) -> dict:
    from slicer import slice_function  # import inside worker for multiprocessing

    code = record.get("code", "")
    language = record.get("language", "c").lower()
    if language in ("c++",):
        language = "cpp"

    fixed_code = record.get("fixed_code")
    cwes = record.get("cwes", [])
    cwe = cwes[0] if cwes else ""
    neighbors = record.get("neighbor_functions")

    if language not in ("c", "cpp"):
        # no grammar for these languages: keep the function, record the diff lines
        enriched = dict(record)
        enriched["slice_code"] = code
        enriched["criterion_lines"] = _changed_lines(code, fixed_code) if fixed_code else []
        enriched["slice_lines"] = list(range(1, len(code.splitlines()) + 1))
        enriched["slice_stmts_before"] = enriched["slice_stmts_after"] = len(code.splitlines())
        enriched["inter_proc_calls"] = []
        enriched["criterion_source"] = "line-diff" if enriched["criterion_lines"] else "none"
        return enriched

    try:
        result = slice_function(
            code,
            fixed_src=fixed_code,
            cwe=cwe,
            language=language,
            neighbor_functions=neighbors,
        )
        enriched = dict(record)
        enriched.pop("neighbor_functions", None)
        enriched["slice_code"] = result.sliced_code
        enriched["slice_lines"] = result.sliced_lines
        enriched["criterion_lines"] = result.criterion_lines
        enriched["slice_stmts_before"] = result.num_stmts_before
        enriched["slice_stmts_after"] = result.num_stmts_after
        enriched["inter_proc_calls"] = result.inter_proc_calls
        enriched["criterion_source"] = result.criterion_source
    except Exception as exc:
        enriched = dict(record)
        enriched.pop("neighbor_functions", None)
        enriched["slice_error"] = str(exc)

    return enriched


def _changed_lines(before: str, after: str) -> list:
    import difflib
    b, a = before.splitlines(), after.splitlines()
    out = []
    for tag, i1, i2, _j1, _j2 in difflib.SequenceMatcher(None, b, a).get_opcodes():
        if tag in ("replace", "delete"):
            out.extend(range(i1 + 1, i2 + 1))
        elif tag == "insert":
            out.extend(ln for ln in (i1, i1 + 1) if 1 <= ln <= len(b))
    return sorted(set(out))


def _worker_init():
    """Import slicer in the worker process."""
    import slicer  # noqa: F401


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the backward slicer on a universal-format JSONL."
    )
    parser.add_argument("--input", type=Path, required=True,
                        help="Input JSONL (universal slicer format)")
    parser.add_argument("--output", type=Path, required=True,
                        help="Output JSONL with slice fields added")
    parser.add_argument("--workers", type=int, default=1,
                        help="Parallel worker processes (default 1)")
    parser.add_argument("--limit", type=int, default=0,
                        help="Process only the first N records (0 = all)")
    args = parser.parse_args()

    print(f"Loading records from {args.input} …")
    with open(args.input, encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]

    if args.limit:
        records = records[: args.limit]
    print(f"  {len(records)} records to process")

    args.output.parent.mkdir(parents=True, exist_ok=True)

    done = 0
    errors = 0

    with open(args.output, "w", encoding="utf-8") as out_f:
        if args.workers <= 1:
            for rec in records:
                enriched = _process_record(rec)
                out_f.write(json.dumps(enriched, ensure_ascii=False) + "\n")
                done += 1
                if "slice_error" in enriched:
                    errors += 1
                if done % 500 == 0:
                    print(f"  {done}/{len(records)} done, {errors} errors",
                          flush=True)
        else:
            with ProcessPoolExecutor(
                max_workers=args.workers,
                initializer=_worker_init,
            ) as pool:
                futures = {pool.submit(_process_record, rec): rec
                           for rec in records}
                for fut in as_completed(futures):
                    enriched = fut.result()
                    out_f.write(
                        json.dumps(enriched, ensure_ascii=False) + "\n"
                    )
                    done += 1
                    if "slice_error" in enriched:
                        errors += 1
                    if done % 500 == 0:
                        print(f"  {done}/{len(records)} done, {errors} errors",
                              flush=True)

    print(f"\nDone. {done} records → {args.output}")
    print(f"Errors: {errors}")


if __name__ == "__main__":
    main()
