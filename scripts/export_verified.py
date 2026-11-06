"""
Export all VERIFICATION_SUCCESS snippets (with CWEs) to a JSONL file.

Each line is one CodeSnippet record with all columns serialised, plus a
`cwes` list of CWE IDs attached to that snippet.

Run:
  python scripts/export_verified.py
  python scripts/export_verified.py --output my_verified.jsonl
  python scripts/export_verified.py --label VULNERABLE --language c
  python scripts/export_verified.py --type GENERATED
  python scripts/export_verified.py --uuids valid.txt   # only these rows (one uuid per line)
"""
import argparse, hashlib, json, os, sys
from datetime import datetime, date

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor

from src.agents.esbmc_agent import ESBMC_LANG_EXT
from src.agents.esbmc_verification import build_verification_command
from src.utils.provenance import category, lexically_obvious, trigger_line

load_dotenv()

BATCH_SIZE = 500


def _connect():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
        dbname=os.getenv("POSTGRES_DB"),
        connect_timeout=30,
    )


def _serialise_value(v):
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    return v


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output",   default="verified_samples.jsonl",
                        help="Output JSONL file (default: verified_samples.jsonl)")
    parser.add_argument("--label",    default=None,
                        help="Filter by label (SAFE, VULNERABLE, UNKNOWN)")
    parser.add_argument("--language", default=None,
                        help="Filter by language (e.g. c, python)")
    parser.add_argument("--type",     default=None,
                        help="Filter by type (SEED, GENERATED, FIXED)")
    parser.add_argument("--allow-inconsistent", action="store_true",
                        help="Write rows that fail the consistency checks instead of skipping them")
    parser.add_argument("--include-unreproduced", action="store_true",
                        help="Also export VULNERABLE rows no sanitizer crash backs and SAFE rows a sanitizer "
                             "crashed (default: neither)")
    parser.add_argument("--uuids", default=None,
                        help="File with one uuid per line: export only these rows")
    args = parser.parse_args()
    only = set(open(args.uuids).read().split()) if args.uuids else None
    # the label command of each language, as EsbmcAgent builds it
    expected_command = {lang: build_verification_command("kt" if lang == "kotlin" else lang, f"/work/source.{ext}")
                        for lang, ext in ESBMC_LANG_EXT.items()}

    conn = _connect()

    # Build main query
    conditions = ["status = 'VERIFICATION_SUCCESS'", "label IN ('SAFE', 'VULNERABLE')"]
    if args.label:
        conditions.append(f"label = '{args.label.upper()}'")
    if args.language:
        conditions.append(f"language = '{args.language.lower()}'")
    if args.type:
        conditions.append(f"type = '{args.type.upper()}'")
    if not args.include_unreproduced:
        conditions.append("(label <> 'VULNERABLE' OR reproduced = 'REPRODUCED')")
        conditions.append("(label <> 'SAFE' OR coalesce(verification_meta->'confirmation'->>'result', '') "
                          "<> 'counterexample_found')")

    where_sql = " AND ".join(conditions)

    columns = [
        "uuid", "seed_uuid", "parent_uuid", "generation_model", "language",
        "type", "label", "status", "dataset", "project", "repo_url", "cve",
        "commit_hash", "commit_message", "code_hash", "code", "slice_code",
        "install_command", "compilation_log", "esbmc_log", "witness", "info",
        "metrics", "attempt_count", "created_at", "updated_at",
        "verification_meta", "verified_code_hash", "pair_attempts",
        "reproduced", "sanitizer_log", "poc_input", "sanitizer_cwes", "reproduce_attempts",
    ]
    col_sql = ", ".join(columns)

    try:
        with conn.cursor() as count_cur:
            count_cur.execute(f"SELECT count(*) FROM code_snippets WHERE {where_sql}")
            total = count_cur.fetchone()[0]
    except Exception:
        total = "?"
        conn = _connect()

    if only is not None:
        total = f"{len(only)} listed of {total}"
    print(f"Exporting {total} verified snippets → {args.output}")

    seeds = {}
    with conn.cursor(cursor_factory=RealDictCursor) as scur:
        scur.execute("SELECT uuid, cve, repo_url, commit_hash, dataset, project, commit_message "
                     "FROM code_snippets WHERE type = 'SEED'")
        for r in scur.fetchall():
            seeds[r["uuid"]] = dict(r)
        scur.execute("SELECT code_snippet_uuid, cwe_id FROM code_snippet_cwe WHERE code_snippet_uuid IN "
                     "(SELECT uuid FROM code_snippets WHERE type = 'SEED')")
        for su, cwe in scur.fetchall():
            seeds.setdefault(su, {}).setdefault("cwes", []).append(cwe)

    written = 0
    offset = 0
    seen_code, duplicates = set(), 0
    skipped = {}
    with open(args.output, "w") as out_f:
        while True:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    f"SELECT {col_sql} FROM code_snippets "
                    f"WHERE {where_sql} ORDER BY created_at "
                    f"LIMIT {BATCH_SIZE} OFFSET {offset}"
                )
                rows = cur.fetchall()

            if not rows:
                break

            batch_uuids = [row["uuid"] for row in rows]

            # Fetch CWEs for this batch only
            cwes_by_uuid: dict[str, list[str]] = {}
            with conn.cursor() as cwe_cur:
                cwe_cur.execute(
                    "SELECT code_snippet_uuid, cwe_id "
                    "FROM code_snippet_cwe "
                    "WHERE code_snippet_uuid = ANY(%s)",
                    (batch_uuids,),
                )
                for snippet_uuid, cwe_id in cwe_cur.fetchall():
                    cwes_by_uuid.setdefault(snippet_uuid, []).append(cwe_id)

            for row in rows:
                if only is not None and row["uuid"] not in only:
                    continue
                program = hashlib.sha256((row["code"] or "").encode("utf-8", errors="replace")).hexdigest()
                if program in seen_code:  # the same program exported earlier: keep the oldest row
                    duplicates += 1
                    continue
                record = {k: _serialise_value(v) for k, v in row.items()}
                record["cwes"] = sorted(cwes_by_uuid.get(record["uuid"], []))
                problems = _consistency_problems(record, expected_command)
                if problems and not args.allow_inconsistent:
                    for p in problems:
                        skipped[p] = skipped.get(p, 0) + 1
                    continue
                record["consistency_problems"] = problems
                seed = seeds.get(record["seed_uuid"], {})
                for k in ("cve", "repo_url", "commit_hash", "dataset", "project", "commit_message"):
                    if not record.get(k) and seed.get(k):
                        record[k] = seed[k]
                record["seed_cwes"] = sorted(seed.get("cwes", []))
                log = record.get("esbmc_log") or ""
                tl = trigger_line(log) if record["label"] == "VULNERABLE" else None
                code_lines = (record.get("code") or "").split("\n")
                record["trigger_line_number"] = tl
                record["trigger_line"] = code_lines[tl - 1] if tl and 0 < tl <= len(code_lines) else None
                record.update(category(record["label"], log, record.get("verification_meta")))
                record["lexically_obvious"] = lexically_obvious(record.get("code") or "", tl)
                conf = (record.get("verification_meta") or {}).get("confirmation") or {}
                record["dynamic_check"] = conf.get("result")
                record["env_dependent"] = conf.get("env_dependent")
                finding = conf.get("finding") or {}
                record["sanitizer_kind"] = finding.get("kind")
                record["sanitizer_trace"] = finding.get("report")
                record["sanitizer_input_b64"] = finding.get("input_b64")
                record["dynamic_confirmed"] = (conf.get("result") in ("confirmed_exact", "confirmed_function", "confirmed_class")
                                               if record["label"] == "VULNERABLE" else
                                               conf.get("result") == "no_crash_found" if record["label"] == "SAFE" else None)
                out_f.write(json.dumps(record) + "\n")
                seen_code.add(program)
                written += 1

            offset += len(rows)
            if offset % 5000 == 0:
                print(f"  {written}/{total} records written...")

            if len(rows) < BATCH_SIZE:
                break

    conn.close()
    print(f"Done. {written} records written to {args.output} ({duplicates} duplicate programs left out)")
    if skipped:
        print("Skipped for consistency problems:")
        for k, v in sorted(skipped.items(), key=lambda x: -x[1]):
            print(f"  {v:7d}  {k}")
        if not args.allow_inconsistent:
            sys.exit(2)


def _consistency_problems(record, expected_command):
    """Reasons a row must not be released as a labelled program."""
    problems = []
    code = record.get("code") or ""
    h = hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest()
    if record.get("code_hash") and record["code_hash"] != h:
        problems.append("code_hash != sha256(code)")
    if record.get("label") in ("SAFE", "VULNERABLE"):
        if record.get("verified_code_hash") != h:
            problems.append("verified_code_hash missing or != sha256(code)")
        log = record.get("esbmc_log") or ""
        verdict = "VULNERABLE" if "VERIFICATION FAILED" in log else "SAFE" if "VERIFICATION SUCCESSFUL" in log else None
        if verdict != record["label"]:
            problems.append("label != log verdict")
        meta = record.get("verification_meta") or {}
        if not meta.get("command"):
            problems.append("verification_meta.command missing")
        elif _strip_budget(meta["command"]) != _strip_budget(expected_command.get(record.get("language"))):
            problems.append("command differs from the current label command")
        if meta.get("esbmc_version") and not str(meta["esbmc_version"]).startswith("8.4"):
            problems.append(f"esbmc_version {meta['esbmc_version']}")
    return problems


def _strip_budget(cmd):
    import re
    return re.sub(r"--(timeout|memlimit) \S+", "", cmd or "")


if __name__ == "__main__":
    main()
