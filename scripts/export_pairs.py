"""
Export all confirmed code pairs to data/pairs.jsonl (default).

Each record contains:
  pair_type, language, model, seed_uuid,
  safe_uuid, safe_code, safe_status,
  vulnerable_uuid, vulnerable_code, vulnerable_status,
  cwes, cve, commit_message, seed_code, seed_cwes

Only cross-label pairs are exported (VULNERABLE→SAFE fix pairs and
SAFE→VULNERABLE injection pairs).  Snippets whose parent_uuid was
cleared after inconclusive verification are excluded automatically.

Run:
  python scripts/export_pairs.py
  python scripts/export_pairs.py --output data/my_pairs.jsonl
  python scripts/export_pairs.py --language c
  python scripts/export_pairs.py --pair-type fix
  python scripts/export_pairs.py --verified-only
"""
import argparse, json, os, sys, time
from datetime import datetime, date

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor

load_dotenv()

DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "pairs.jsonl"
)
BATCH_SIZE = 500
MAX_RETRIES = 3


def _connect():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
        dbname=os.getenv("POSTGRES_DB"),
        connect_timeout=30,
    )


def _retry_connect():
    for attempt in range(MAX_RETRIES):
        try:
            return _connect()
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                raise
            time.sleep(2 ** attempt)


def _fetch_by_uuids(conn, uuids: list[str]) -> dict[str, dict]:
    """Fetch code_snippets rows for a list of UUIDs, returned as uuid→dict."""
    if not uuids:
        return {}
    columns = (
        "uuid, seed_uuid, parent_uuid, generation_model, language, "
        "type, label, status, cve, commit_message, code, code_hash, metrics, "
        "verification_meta, created_at"
    )
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"SELECT {columns} FROM code_snippets WHERE uuid = ANY(%s)",
            (uuids,),
        )
        return {row["uuid"]: dict(row) for row in cur.fetchall()}


def _fetch_cwes(conn, uuids: list[str]) -> dict[str, list[str]]:
    """Fetch CWE IDs per snippet UUID."""
    if not uuids:
        return {}
    result: dict[str, list[str]] = {}
    with conn.cursor() as cur:
        cur.execute(
            "SELECT code_snippet_uuid, cwe_id FROM code_snippet_cwe "
            "WHERE code_snippet_uuid = ANY(%s)",
            (uuids,),
        )
        for snippet_uuid, cwe_id in cur.fetchall():
            result.setdefault(snippet_uuid, []).append(cwe_id)
    return result


def _reject(child, parent, verified_only):
    if parent is None:
        return "parent missing"
    if parent["label"] not in ("SAFE", "VULNERABLE"):
        return "parent not conclusive"
    if parent["label"] == child["label"]:
        return "same label"
    if verified_only and parent["status"] != "VERIFICATION_SUCCESS":
        return "parent not VERIFICATION_SUCCESS"
    if child["code"] == parent["code"]:
        return "identical code"
    cm = (child.get("verification_meta") or {}).get("command")
    pm = (parent.get("verification_meta") or {}).get("command")
    if not cm or not pm:
        return "missing verification_meta"
    if cm != pm:
        return "different commands"
    return None


def main():
    parser = argparse.ArgumentParser(description="Export confirmed pairs to JSONL.")
    parser.add_argument("--output",        default=DEFAULT_OUTPUT,
                        help="Destination file (default: data/pairs.jsonl)")
    parser.add_argument("--language",      default=None,
                        help="Filter by language (e.g. c, python)")
    parser.add_argument("--pair-type",     default=None, choices=["fix", "injection"],
                        help="Export only fix or injection pairs")
    parser.add_argument("--verified-only", action="store_true",
                        help="Only include pairs where both snippets are VERIFICATION_SUCCESS")
    parser.add_argument("--distinct", action="store_true",
                        help="Keep one counterpart per parent program (the earliest created)")
    args = parser.parse_args()

    conn = _retry_connect()

    # ── 1. Fetch children (generated snippets with a parent) ──────────────
    conditions = [
        "type = 'GENERATED'",
        "parent_uuid IS NOT NULL",
        "label IN ('SAFE', 'VULNERABLE')",
    ]
    if args.language:
        conditions.append(f"language = '{args.language.lower()}'")
    if args.pair_type == "fix":
        conditions.append("label = 'SAFE'")
    elif args.pair_type == "injection":
        conditions.append("label = 'VULNERABLE'")
    if args.verified_only:
        conditions.append("status = 'VERIFICATION_SUCCESS'")

    where_sql = " AND ".join(conditions)

    children: list[dict] = []
    offset = 0
    columns = (
        "uuid, seed_uuid, parent_uuid, generation_model, language, "
        "type, label, status, cve, commit_message, code, code_hash, metrics, "
        "verification_meta, created_at"
    )
    print("Fetching children...")
    while True:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"SELECT {columns} FROM code_snippets "
                f"WHERE {where_sql} ORDER BY created_at "
                f"LIMIT {BATCH_SIZE} OFFSET {offset}"
            )
            rows = cur.fetchall()
        if not rows:
            break
        children.extend(dict(r) for r in rows)
        offset += len(rows)
        if len(rows) < BATCH_SIZE:
            break

    print(f"  {len(children)} candidate children loaded")

    # ── 2. Batch-fetch parents ────────────────────────────────────────────
    parent_uuids = list({c["parent_uuid"] for c in children})
    parents: dict[str, dict] = {}
    print(f"Fetching {len(parent_uuids)} parents...")
    for i in range(0, len(parent_uuids), BATCH_SIZE):
        batch = parent_uuids[i : i + BATCH_SIZE]
        try:
            parents.update(_fetch_by_uuids(conn, batch))
        except Exception:
            conn = _retry_connect()
            parents.update(_fetch_by_uuids(conn, batch))

    # ── 3. Filter to genuine cross-label pairs ────────────────────────────
    valid_children = []
    rejected = {}
    for child in children:
        parent = parents.get(child["parent_uuid"])
        reason = _reject(child, parent, args.verified_only)
        if reason:
            rejected[reason] = rejected.get(reason, 0) + 1
            continue
        valid_children.append((child, parent))
    if args.distinct:
        valid_children.sort(key=lambda cp: str(cp[0]["created_at"]))
        seen = set()
        valid_children = [cp for cp in valid_children
                          if not (cp[1]["uuid"] in seen or seen.add(cp[1]["uuid"]))]

    print(f"  {len(valid_children)} valid cross-label pairs over "
          f"{len({p['uuid'] for _, p in valid_children})} distinct parents")
    for k, v in sorted(rejected.items(), key=lambda x: -x[1]):
        print(f"  rejected {v:6d}  {k}")

    # ── 4. Batch-fetch seeds ──────────────────────────────────────────────
    seed_uuids = list({c["seed_uuid"] for c, _ in valid_children if c["seed_uuid"]})
    seeds: dict[str, dict] = {}
    print(f"Fetching {len(seed_uuids)} seeds...")
    for i in range(0, len(seed_uuids), BATCH_SIZE):
        batch = seed_uuids[i : i + BATCH_SIZE]
        try:
            seeds.update(_fetch_by_uuids(conn, batch))
        except Exception:
            conn = _retry_connect()
            seeds.update(_fetch_by_uuids(conn, batch))

    # ── 5. Batch-fetch CWEs for all relevant snippets ─────────────────────
    all_uuids = (
        [c["uuid"] for c, _ in valid_children]
        + [p["uuid"] for _, p in valid_children]
        + list(seeds.keys())
    )
    all_uuids = list(set(all_uuids))
    cwes_map: dict[str, list[str]] = {}
    print(f"Fetching CWEs for {len(all_uuids)} snippets...")
    for i in range(0, len(all_uuids), BATCH_SIZE):
        batch = all_uuids[i : i + BATCH_SIZE]
        try:
            cwes_map.update(_fetch_cwes(conn, batch))
        except Exception:
            conn = _retry_connect()
            cwes_map.update(_fetch_cwes(conn, batch))

    conn.close()

    # ── 6. Build and write records ────────────────────────────────────────
    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    written = 0
    with open(args.output, "w") as f:
        for child, parent in valid_children:
            if parent["label"] == "VULNERABLE" and child["label"] == "SAFE":
                pair_type    = "fix"
                safe_snip    = child
                vuln_snip    = parent
            else:
                pair_type    = "injection"
                safe_snip    = parent
                vuln_snip    = child

            seed = seeds.get(child["seed_uuid"]) if child["seed_uuid"] else None

            record = {
                "pair_type":          pair_type,
                "language":           child["language"] or parent["language"],
                "model":              child["generation_model"],
                "seed_uuid":          child["seed_uuid"],
                "pair_command":       (child.get("verification_meta") or {}).get("command"),
                "safe_uuid":          safe_snip["uuid"],
                "safe_code":          safe_snip["code"],
                "safe_status":        safe_snip["status"],
                "vulnerable_uuid":    vuln_snip["uuid"],
                "vulnerable_code":    vuln_snip["code"],
                "vulnerable_status":  vuln_snip["status"],
                "cwes":               sorted(cwes_map.get(vuln_snip["uuid"], [])),
                "cve":                (seed["cve"] if seed else None)
                                      or parent["cve"] or child["cve"],
                "commit_message":     parent["commit_message"] or child["commit_message"],
                "seed_code":          seed["code"] if seed else None,
                "seed_cwes":          sorted(cwes_map.get(seed["uuid"], [])) if seed else [],
            }
            f.write(json.dumps(record) + "\n")
            written += 1

    print(f"Wrote {written} pairs → {args.output}")


if __name__ == "__main__":
    main()
