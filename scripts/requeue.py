#!/usr/bin/env python3
"""Re-queue work that ended without a usable result. Only the database and the queues are touched,
so it is safe while the pipeline runs. The agents must be running to consume the tasks.

  compile     snippets that exhausted their compile-fix budget get a new `compilation_fix` task
  frontend    programs ESBMC could not read (PARSING ERROR, missing module) go back to the LLM for repair
  resource    programs that ended in a timeout, out of memory or a kill are verified again
              (raise esbmc.timeout / esbmc_mem_limit in config.yaml and restart the agents first)
  generation  `generate` tasks for seeds a model has not generated yet (for example after a model server restart)

    python scripts/requeue.py compile --dry-run
    python scripts/requeue.py frontend --languages cpp --model gemma-4-31b-it --limit 200
    python scripts/requeue.py resource --cause memory
    python scripts/requeue.py generation seeds.jsonl --model qwen3.8-27b
"""
import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from sqlalchemy import text

from config.settings import settings
from src.agents.esbmc_verification import frontend_failure_message
from src.core.workflow_manager import WorkflowManager
from src.db.database import DatabaseManager
from src.queue.producer import QueueProducer
from src.utils.data_loader import DatasetLoader
from src.utils.logger import logger
from src.utils.queue import make_queue_name

log = logger.get_logger("requeue")

FRONTEND_PATTERN = r'PARSING ERROR|module-file-not-found|Cannot open file|Object "[^"]+" not found'
RESOURCE_PATTERNS = {
    "timeout": r"ERROR: Timed out|\[TIMEOUT\]",
    "memory": r"ERROR: Out of memory",
    "killed": r"(^|\n)Killed",
}
CLEARED = {'esbmc_log': None, 'witness': None, 'verification_meta': None, 'verified_code_hash': None, 'esbmc_cwes': None}

SELECT_COMPILE = text("""
    SELECT uuid, generation_model, language
    FROM code_snippets
    WHERE type = 'GENERATED' AND parent_uuid IS NULL
      AND status = 'COMPILATION_FAILED'
      AND attempt_count >= :min_attempts
      AND language = ANY(:languages)
      AND compilation_log IS NOT NULL
    ORDER BY updated_at
""")
SELECT_FRONTEND = text("""
    SELECT uuid, generation_model, language, esbmc_log
    FROM code_snippets
    WHERE type = 'GENERATED' AND parent_uuid IS NULL
      AND status = 'VERIFICATION_ERROR'
      AND language = ANY(:languages)
      AND right(esbmc_log, 3000) ~ :pattern
    ORDER BY updated_at
""")
SELECT_RESOURCE = text("""
    SELECT uuid, generation_model, language
    FROM code_snippets
    WHERE type = 'GENERATED' AND parent_uuid IS NULL
      AND status IN ('VERIFICATION_ERROR', 'VERIFICATION_TIMEOUT')
      AND language = ANY(:languages)
      AND (status = 'VERIFICATION_TIMEOUT' OR right(esbmc_log, 3000) ~ :pattern)
    ORDER BY updated_at
""")


def enabled_models(ap, wanted):
    enabled = {k for k, v in settings.models.items() if v.get('enabled', True)}
    models = set(wanted) if wanted else enabled
    unknown = models - enabled
    if unknown:
        ap.error(f"not enabled in config.yaml: {', '.join(sorted(unknown))}")
    return models


def run_requeue(name, rows, models, args, update, queue_kind, message, stays, label=lambda model, language: language,
                resume_hint=""):
    producer = None if args.dry_run else QueueProducer(
        caller=name, host=settings.rabbitmq['host'], port=settings.rabbitmq['port'])
    done, skipped, failed = Counter(), Counter(), 0
    for row in rows:
        uuid, model, language = row[0], row[1], row[2]
        if model not in models:
            skipped[f"model {model}"] += 1
            continue
        update_fields = update(row)
        if update_fields is False:
            skipped["no error line"] += 1
            continue
        if args.limit and sum(done.values()) >= args.limit:
            break
        if args.dry_run:
            done[label(model, language)] += 1
            continue
        if update_fields is not None and not args.db.update_snippet(uuid=uuid, metadata=update_fields):
            skipped["snippet vanished"] += 1
            continue
        queue = make_queue_name(queue_kind, model)
        if producer.publish_message(queue, message(uuid)):
            done[label(model, language)] += 1
        else:
            failed += 1
            log.error(f"PUBLISH FAILED for {uuid} -> {queue}; it stays {stays} ({resume_hint})")
    verb = "would requeue" if args.dry_run else "requeued"
    log.info(f"{verb} {sum(done.values())} snippet(s) {dict(done)}; skipped {dict(skipped)}; {failed} publish failure(s).")


def cmd_compile(ap, args):
    languages = [l for l in args.languages.split(",") if l not in settings.skip_languages]
    models = enabled_models(ap, args.model)
    args.db = DatabaseManager(caller="RequeueCompile", db_url=settings.database['url'])
    with args.db.session_scope() as session:
        rows = session.execute(SELECT_COMPILE, {"languages": languages, "min_attempts": args.min_attempts}).all()
    log.info(f"{len(rows)} snippet(s) in COMPILATION_FAILED.")
    run_requeue("RequeueCompile", rows, models, args, lambda r: {'attempt_count': 0}, "llm",
                lambda u: {'uuid': u, 'task_type': 'compilation_fix', 'attempt_count': 0}, "COMPILATION_FAILED",
                lambda m, l: f"{m}/{l}", "run `resume_stuck_snippets.py --stages compile_fix` to re-queue it")


def cmd_frontend(ap, args):
    models = enabled_models(ap, args.model)
    args.db = DatabaseManager(caller="RequeueFrontend", db_url=settings.database['url'])
    with args.db.session_scope() as session:
        rows = session.execute(SELECT_FRONTEND, {"languages": args.languages.split(","), "pattern": FRONTEND_PATTERN}).all()
    log.info(f"{len(rows)} snippet(s) in VERIFICATION_ERROR with a front-end error.")

    def update(row):
        message = frontend_failure_message(row[3] or "")
        if message is None:
            return False
        return {'status': 'COMPILATION_FAILED', 'compilation_log': message, 'attempt_count': 0, **CLEARED}

    run_requeue("RequeueFrontend", rows, models, args, update, "llm",
                lambda u: {'uuid': u, 'task_type': 'compilation_fix', 'attempt_count': 0}, "COMPILATION_FAILED",
                resume_hint="run `resume_stuck_snippets.py --stages compile_fix` to re-queue it")


def cmd_resource(ap, args):
    models = enabled_models(ap, args.model)
    pattern = "|".join(RESOURCE_PATTERNS[c] for c in (args.cause or RESOURCE_PATTERNS))
    log.info(f"Verification limits in config: timeout={settings.esbmc.get('timeout')}s "
             f"(derived {settings.esbmc.get('derived_timeout')}s), memory={settings.resource_management.get('esbmc_mem_limit')}; "
             f"the agents must have been restarted to use them.")
    args.db = DatabaseManager(caller="RequeueResource", db_url=settings.database['url'])
    with args.db.session_scope() as session:
        rows = session.execute(SELECT_RESOURCE, {"languages": args.languages.split(","), "pattern": pattern}).all()
    log.info(f"{len(rows)} snippet(s) ended without a verdict for lack of time or memory.")
    run_requeue("RequeueResource", rows, models, args, lambda r: {'status': 'COMPILATION_SUCCESS', **CLEARED}, "esbmc",
                lambda u: {'uuid': u}, "COMPILATION_SUCCESS",
                resume_hint="run `resume_stuck_snippets.py --stages verify` to pick it up")


def queue_depth(model_key):
    import pika
    host, port = settings.rabbitmq['host'], int(os.getenv("RABBITMQ_PORT", settings.rabbitmq['port']))
    user, pw = os.getenv("RABBITMQ_USER"), os.getenv("RABBITMQ_PASS")
    creds = pika.PlainCredentials(user, pw) if user and pw else pika.PlainCredentials("guest", "guest")
    conn = pika.BlockingConnection(pika.ConnectionParameters(host=os.getenv("RABBITMQ_HOST", host), port=port, credentials=creds))
    try:
        return conn.channel().queue_declare(queue=make_queue_name("llm", model_key), passive=True).method.message_count
    except Exception:
        return 0
    finally:
        if conn.is_open:
            conn.close()


def cmd_generation(ap, args):
    for m in args.model:
        if m not in settings.models or not settings.models[m].get('enabled', True):
            ap.error(f"model '{m}' is not an enabled model in config.yaml")
        depth = queue_depth(m)
        if depth and not args.force:
            ap.error(f"queue for '{m}' still has {depth} message(s); queueing again would duplicate them (use --force)")
    datapoints = DatasetLoader(args.dataset).load()
    WorkflowManager().resume_workflow(datapoints=datapoints, stages={"generate"}, models=set(args.model))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    def common(p, languages=True):
        if languages:
            p.add_argument("--languages", default="c,cpp,python", help="comma-separated (default: c,cpp,python)")
        p.add_argument("--model", action="append", help="only this model key (repeatable)")
        p.add_argument("--limit", type=int, help="stop after this many snippets")
        p.add_argument("--dry-run", action="store_true", help="report what would change, change nothing")

    p = sub.add_parser("compile", help="give snippets that exhausted their compile-fix budget another go")
    common(p)
    p.add_argument("--min-attempts", type=int, default=1, help="only snippets that already used this many attempts")
    p.set_defaults(fn=cmd_compile)
    p = sub.add_parser("frontend", help="send programs ESBMC could not read back to the LLM")
    common(p)
    p.set_defaults(fn=cmd_frontend)
    p = sub.add_parser("resource", help="verify again programs that ran out of time or memory")
    common(p)
    p.add_argument("--cause", action="append", choices=sorted(RESOURCE_PATTERNS), help="repeatable, default: all")
    p.set_defaults(fn=cmd_resource)
    p = sub.add_parser("generation", help="re-queue generate tasks for chosen models")
    p.add_argument("dataset")
    p.add_argument("--model", action="append", required=True, help="model key from config.yaml (repeatable)")
    p.add_argument("--force", action="store_true", help="queue even if the model's llm queue is not empty")
    p.set_defaults(fn=cmd_generation)

    args = ap.parse_args()
    args.fn(ap, args)


if __name__ == "__main__":
    main()
