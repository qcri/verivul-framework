"""
Prune dead-weight rows from the code_snippets table.

Rows eligible for deletion:
  - type != SEED
  - no children (not a parent in any live chain)
  - status in GENERATION_FAILED | COMPILATION_FAILED | VERIFICATION_ERROR | PENDING_COMPILATION

After deletion the stats row is rebuilt from the surviving rows.

Run (dry-run — shows counts only):
  python scripts/prune_db.py

Actually delete:
  python scripts/prune_db.py --confirm

Restrict to a specific status:
  python scripts/prune_db.py --status VERIFICATION_ERROR --confirm
"""
import argparse, os, sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sqlalchemy import func, text
from sqlalchemy.orm import selectinload
from src.db.database import DatabaseManager
from src.db.models import CodeSnippet, Stats, Status, Label, Type

PRUNABLE_STATUSES = {
    Status.GENERATION_FAILED.value,
    Status.COMPILATION_FAILED.value,
    Status.VERIFICATION_ERROR.value,
    Status.PENDING_COMPILATION.value,
}


def _rebuild_stats(session) -> Stats:
    stats = session.query(Stats).first()
    if stats is None:
        stats = Stats()
        session.add(stats)

    rows = (
        session.query(CodeSnippet)
        .options(selectinload(CodeSnippet.cwes))
        .filter(CodeSnippet.status != Status.GROUND_TRUTH.value)
        .all()
    )

    status_counts: dict = {}
    label_counts: dict = {}
    model_counts: dict = {}
    cwe_distribution: dict = {}
    vulnerable_count = 0
    safe_count = 0

    for s in rows:
        status_counts[s.status] = status_counts.get(s.status, 0) + 1
        model_counts[s.generation_model] = model_counts.get(s.generation_model, 0) + 1

        if s.status and s.status.startswith("VERIFICATION_"):
            if s.label:
                label_counts[s.label] = label_counts.get(s.label, 0) + 1
            if s.label == Label.VULNERABLE.value:
                vulnerable_count += 1
            elif s.label == Label.SAFE.value:
                safe_count += 1
            for cwe in s.cwes:
                cwe_distribution[cwe.id] = cwe_distribution.get(cwe.id, 0) + 1

    stats.total_snippets   = len(rows)
    stats.status_counts    = status_counts
    stats.label_counts     = label_counts
    stats.model_counts     = model_counts
    stats.cwe_distribution = cwe_distribution
    stats.vulnerable_count = vulnerable_count
    stats.safe_count       = safe_count
    return stats


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--confirm", action="store_true",
        help="Actually delete rows. Without this flag the script only reports what would be removed.",
    )
    parser.add_argument(
        "--status", default=None,
        help="Restrict pruning to a single status (e.g. VERIFICATION_ERROR). "
             "Default: all prunable statuses.",
    )
    args = parser.parse_args()

    target_statuses = PRUNABLE_STATUSES
    if args.status:
        s = args.status.upper()
        if s not in PRUNABLE_STATUSES:
            print(f"Error: '{s}' is not a prunable status. Choose from: {sorted(PRUNABLE_STATUSES)}")
            sys.exit(1)
        target_statuses = {s}

    db = DatabaseManager(caller="prune_db")

    with db.session_scope() as session:
        # Find UUIDs that have at least one child — must not be deleted
        parent_uuids = {
            row[0]
            for row in session.query(CodeSnippet.parent_uuid)
            .filter(CodeSnippet.parent_uuid.isnot(None))
            .distinct()
        }

        candidates = (
            session.query(CodeSnippet)
            .filter(
                CodeSnippet.type != Type.SEED.value,
                CodeSnippet.status.in_(target_statuses),
                CodeSnippet.uuid.notin_(parent_uuids) if parent_uuids else text("1=1"),
            )
            .all()
        )

        if not candidates:
            print("Nothing to prune.")
            return

        by_status = Counter(c.status for c in candidates)
        by_lang   = Counter(c.language or "unknown" for c in candidates)

        print(f"\n{'DRY RUN — ' if not args.confirm else ''}Rows eligible for deletion: {len(candidates)}\n")
        print("  By status:")
        for k, v in sorted(by_status.items()):
            print(f"    {k:<35} {v:>6}")
        print("\n  By language:")
        for k, v in sorted(by_lang.items()):
            print(f"    {k:<35} {v:>6}")

        if not args.confirm:
            print("\nRe-run with --confirm to delete.")
            return

        print("\nDeleting…")
        deleted = 0
        for snippet in candidates:
            session.delete(snippet)
            deleted += 1
            if deleted % 500 == 0:
                print(f"  {deleted} deleted so far…")
                session.flush()

        session.flush()
        print(f"\nDeleted {deleted} rows. Rebuilding stats…")
        _rebuild_stats(session)
        print("Stats rebuilt. Done.")


if __name__ == "__main__":
    main()
