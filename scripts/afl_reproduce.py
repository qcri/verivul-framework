"""AFL++ for VULNERABLE C/C++ programs the sanitizer search left NOT_REPRODUCED (see src/utils/afl.py).

AFL++ inputs are replayed with the pipeline's runner; a crash sets reproduced = REPRODUCED with
the sanitizer report and input, exactly as the seeded search does.  Every attempt is recorded in
verification_meta['afl'] and not repeated.  Violations no input can trigger (known ESBMC model
gaps: C++ destructor/STL leaks, C++ shifts, NaN, FILE not closed, STL model asserts) are skipped
unless --all.

Run:
  python scripts/afl_reproduce.py --dry-run
  python scripts/afl_reproduce.py --workers 20
"""
import argparse
import base64
import os
import random
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from config.settings import settings  # noqa: E402
from src.agents.esbmc_verification import code_hash  # noqa: E402
from src.db.database import DatabaseManager  # noqa: E402
from src.db.models import CodeSnippet  # noqa: E402
from src.utils.afl import afl_inputs, likely_false_positive  # noqa: E402
from src.utils.dynamic_confirm import (confirm, counterexample_hints, reproduction_fields, summary,  # noqa: E402
                                      target_property)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--workers', type=int, default=10)
    ap.add_argument('--seconds', type=int, default=300, help='AFL++ time per program')
    ap.add_argument('--limit', type=int)
    ap.add_argument('--all', action='store_true', help='also fuzz violations no input is expected to trigger')
    ap.add_argument('--dry-run', action='store_true', help='only count the candidates')
    args = ap.parse_args()
    image = settings.esbmc.get('image', 'esbmc:8.4')
    db = DatabaseManager(caller="AflReproduce", db_url=settings.database['url'])
    with db.session_scope() as s:
        rows = s.query(CodeSnippet.uuid, CodeSnippet.code, CodeSnippet.language, CodeSnippet.verification_meta).filter(
            CodeSnippet.label == 'VULNERABLE', CodeSnippet.reproduced == 'NOT_REPRODUCED',
            CodeSnippet.language.in_(['c', 'cpp'])).all()
    todo, skipped = [], Counter()
    for r in rows:
        meta = r.verification_meta or {}
        if meta.get('afl'):
            skipped['already fuzzed'] += 1
            continue
        why = likely_false_positive(r.code, r.language, (meta.get('violated_properties') or [{}])[0])
        if why and not args.all:
            skipped[why] += 1
            continue
        todo.append(r.uuid)
    random.Random(7).shuffle(todo)
    if args.limit:
        todo = todo[:args.limit]
    print(f"{len(rows)} NOT_REPRODUCED; fuzzing {len(todo)}; skipped {dict(skipped)}", flush=True)
    if args.dry_run:
        return

    def one(uuid):
        row = db.get_snippet(uuid=uuid)
        meta = dict(row.verification_meta or {})
        hints = counterexample_hints(row.esbmc_log or '', meta)
        found, stats = afl_inputs(row.code, row.language, hints, args.seconds)
        result = 'not_reproduced'
        fields = {}
        if found:
            cat, fn, line = target_property('VULNERABLE', row.esbmc_log or '', meta)
            conf = confirm(row.code, row.language, 'VULNERABLE', cat, fn, line, image=image, budget=90,
                           hints={'seeds': [base64.b64encode(x).decode() for x in found]})
            result = conf.get('result')
            if conf.get('finding'):
                meta['confirmation'] = summary(conf)
                fields = reproduction_fields(conf, 'VULNERABLE')
        # the running pipeline may have regenerated the program meanwhile: its new code is not what was fuzzed
        now = db.get_snippet(uuid=uuid)
        if now is None or code_hash(now.code) != code_hash(row.code) or now.reproduced != 'NOT_REPRODUCED':
            return 'changed meanwhile'
        meta['afl'] = {**stats, 'seconds': args.seconds, 'result': result}
        db.update_snippet(uuid=uuid, metadata={'verification_meta': meta, **fields})
        return 'reproduced' if fields else result

    done = Counter()
    with ThreadPoolExecutor(args.workers) as ex:
        futs = {ex.submit(one, u): u for u in todo}
        for i, f in enumerate(as_completed(futs), 1):
            try:
                done[f.result()] += 1
            except Exception as e:
                done['error'] += 1
                print(f"{futs[f][:8]} ERROR {e}", flush=True)
            if i % 25 == 0 or i == len(todo):
                print(f"[{i}/{len(todo)}] {dict(done)}", flush=True)


if __name__ == '__main__':
    main()
