"""Dynamic confirmation of verified labels (see src/utils/dynamic_confirm.py).

Stores the outcome in verification_meta['confirmation'] and never changes the label.

Run:
  python scripts/confirm_labels.py --workers 8
  python scripts/confirm_labels.py --label VULNERABLE --limit 200
  python scripts/confirm_labels.py --redo
"""
import argparse
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from config.settings import settings  # noqa: E402
from src.db.database import DatabaseManager  # noqa: E402
from src.db.models import CodeSnippet  # noqa: E402
from src.utils.dynamic_confirm import (confirm, counterexample_hints, reproduction_fields, summary,  # noqa: E402
                                      target_property)
from src.queue.producer import QueueProducer  # noqa: E402
from src.utils.queue import make_queue_name  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--workers', type=int, default=8)
    ap.add_argument('--limit', type=int)
    ap.add_argument('--label', choices=['SAFE', 'VULNERABLE'])
    ap.add_argument('--budget', type=float, default=40, help='seconds of search per program')
    ap.add_argument('--redo', action='store_true')
    ap.add_argument('--poc', action='store_true',
                    help='queue the LLM proof-of-concept task for VULNERABLE programs the search did not crash '
                         '(the running pipeline then replays it, and regenerates or re-pairs on failure)')
    args = ap.parse_args()
    producer = QueueProducer(caller="ConfirmLabels", host=settings.rabbitmq['host'],
                             port=settings.rabbitmq['port']) if args.poc else None
    image = settings.esbmc.get('image', 'esbmc:8.4')
    db = DatabaseManager(caller="ConfirmLabels", db_url=settings.database['url'])
    with db.session_scope() as s:
        q = s.query(CodeSnippet.uuid, CodeSnippet.code, CodeSnippet.language, CodeSnippet.label,
                    CodeSnippet.esbmc_log, CodeSnippet.verification_meta, CodeSnippet.generation_model).filter(
            CodeSnippet.status == 'VERIFICATION_SUCCESS', CodeSnippet.label.in_(['SAFE', 'VULNERABLE']),
            CodeSnippet.language.in_(['c', 'cpp']))
        if args.label:
            q = q.filter(CodeSnippet.label == args.label)
        rows = [r for r in q.all() if args.redo or not (r.verification_meta or {}).get('confirmation')]
    if args.limit:
        rows = rows[:args.limit]
    print(f"confirming {len(rows)} programs", flush=True)
    done = Counter()

    def one(r):
        meta = dict(r.verification_meta or {})
        cat, fn, line = target_property(r.label, r.esbmc_log or '', meta)
        res = confirm(r.code, r.language, r.label, cat, fn, line, image=image, budget=args.budget,
                      hints=counterexample_hints(r.esbmc_log or '', meta))
        meta['confirmation'] = summary(res)
        fields = {} if res['result'] == 'runner_error' else reproduction_fields(res, r.label)
        if producer and fields.get('reproduced') == 'NOT_REPRODUCED' and res['result'] != 'compile_error':
            fields['reproduced'] = 'PENDING'
        db.update_snippet(uuid=r.uuid, metadata={'verification_meta': meta, **fields})
        if fields.get('reproduced') == 'PENDING':
            producer.publish_message(make_queue_name('llm', r.generation_model),
                                     {'uuid': r.uuid, 'task_type': 'reproduce_poc', 'round': 1, 'tried': []})
        return (r.label, res['result'])

    def tracked(r):
        out = one(r)
        done[out[1]] += 1
        n = sum(done.values())
        if n % 50 == 0 or n == len(rows):
            print(f"{n}/{len(rows)} {dict(done)}", flush=True)
        return out

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(tracked, rows))
    for label in ('VULNERABLE', 'SAFE'):
        print(label, dict(Counter(res for lb, res in results if lb == label)))


if __name__ == '__main__':
    main()
