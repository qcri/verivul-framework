import argparse
import multiprocessing
import time

from src.agents.llm_agent import start_llm_agent
from src.agents.compiler_agent import start_compiler_agent
from src.agents.esbmc_agent import start_esbmc_agent
from src.core.workflow_manager import WorkflowManager, RESUME_STAGES
from src.db.database import DatabaseManager
from src.db.models import CodeSnippet
from src.utils.data_loader import DatasetLoader
from src.utils.docker_cleanup import remove_stale_containers
from src.utils.logger import logger
from src.utils.resource_manager import ResourceManager
from config.settings import settings
from src.utils.queue import clear_rabbitmq_queues, get_queue_depths

# Grace period given to agents to finish their in-flight Docker work and settle
# their unacked messages before they are killed outright.
SHUTDOWN_GRACE_SECONDS = 30


_models_in_db_cache = None


def models_in_database() -> list:
    """Return every generation_model that appears in the snippets table.

    Includes models no longer listed in config.yaml, which is exactly the set a
    "clean slate" purge has to cover — queues belonging to disabled models are
    otherwise unreachable forever.  Memoised: building a DatabaseManager also
    runs the schema migrations, so it is not free.
    """
    global _models_in_db_cache
    if _models_in_db_cache is not None:
        return _models_in_db_cache
    try:
        db = DatabaseManager(caller="startup_check")
        with db.session_scope() as session:
            _models_in_db_cache = [
                row[0] for row in
                session.query(CodeSnippet.generation_model).distinct()
                if row[0] and row[0] != "seed"
            ]
            return _models_in_db_cache
    except Exception as e:
        logger.get_logger("main").warning(f"Could not list models from the database: {e}")
        return []


def warn_about_unconsumable_queues(log):
    """Warn about queued work for models that no agent will be started for.

    start_agents() iterates settings.models, so a queue belonging to a model that
    has been commented out in config.yaml keeps its messages forever: nothing
    consumes them, and clear_rabbitmq_queues() does not even look at them.
    """
    enabled = {k for k, cfg in settings.models.items() if cfg.get('enabled', True)}
    orphaned_models = [m for m in models_in_database() if m not in enabled]
    if not orphaned_models:
        return

    depths = get_queue_depths(orphaned_models)
    pending = {name: count for name, count in depths.items() if count}
    if pending:
        total = sum(pending.values())
        log.warning(
            f"{total} message(s) are queued for models that are not enabled in "
            f"config.yaml and will never be consumed: "
            + ", ".join(f"{name}={count}" for name, count in sorted(pending.items()))
        )
        log.warning(
            "Re-enable those models in config/config.yaml to drain them, or purge "
            "them explicitly with --purge-queues."
        )


def start_agents(resource_manager: ResourceManager):
    log = logger.get_logger("agent_manager")
    processes = []

    log.info("Starting LLM agents...")
    for model_key in settings.models:
        process = multiprocessing.Process(target=start_llm_agent, args=(model_key,), name=f"llm_{model_key}_agent")
        process.start()
        processes.append(process)

    log.info("Starting compiler agents...")
    for model_key in settings.models:
        process = multiprocessing.Process(target=start_compiler_agent, args=(model_key, resource_manager), name=f"compiler_{model_key}_agent")
        process.start()
        processes.append(process)

    log.info("Starting ESBMC agents...")
    for model_key in settings.models:
        process = multiprocessing.Process(target=start_esbmc_agent, args=(model_key, resource_manager), name=f"esbmc_{model_key}_agent")
        process.start()
        processes.append(process)

    log.info("All agent processes started.")
    return processes


def main():
    log = logger.get_logger("main")
    parser = argparse.ArgumentParser(description='Code Verification System')
    parser.add_argument(
        'dataset', type=str, nargs='?',
        help='Path to dataset file (.json/.jsonl). Required unless --resume is used without the "generate" stage.',
    )
    parser.add_argument(
        '--resume', action='store_true',
        help='Resume the workflow from the database state.',
    )
    parser.add_argument(
        '--stages', type=str, default=None,
        metavar='STAGE[,STAGE...]',
        help=(
            f'Comma-separated list of resume stages to run (only valid with --resume). '
            f'Available stages: {", ".join(RESUME_STAGES)}. '
            f'Defaults to all stages when --resume is used without --stages.'
        ),
    )
    parser.add_argument(
        '--purge-queues', action='store_true',
        help=(
            'Delete every pending task from RabbitMQ before starting, including the '
            'queues of models no longer enabled in config.yaml. DESTRUCTIVE: the '
            'matching database rows keep their status, so anything purged mid-flight '
            'has to be recovered with scripts/resume_stuck_snippets.py.'
        ),
    )
    args = parser.parse_args()

    # Validate: --stages only makes sense with --resume
    if args.stages and not args.resume:
        parser.error('--stages requires --resume')

    # Parse requested stages
    requested_stages = None
    if args.resume and args.stages:
        requested_stages = {s.strip() for s in args.stages.split(',')}
        invalid = requested_stages - set(RESUME_STAGES)
        if invalid:
            parser.error(f"Unknown stage(s): {invalid}. Valid: {list(RESUME_STAGES)}")

    # dataset is required unless we're resuming without the generate stage
    needs_dataset = not args.resume or (requested_stages is None or 'generate' in requested_stages)
    if needs_dataset and not args.dataset:
        parser.error('dataset is required (omit only when using --resume --stages without "generate")')

    # Purging is opt-in.  It used to happen on every non-resume start, which
    # deleted the pending ESBMC/LLM tasks of snippets whose rows still said
    # COMPILATION_SUCCESS — stranding them with no record of why.
    if args.purge_queues:
        purge_models = sorted(set(settings.models) | set(models_in_database()))
        log.warning(
            f"--purge-queues: deleting all pending tasks for {len(purge_models)} model(s). "
            f"Snippets mid-flight will need scripts/resume_stuck_snippets.py afterwards."
        )
        clear_rabbitmq_queues(purge_models)

    # Containers outlive an agent that was killed rather than shut down, and keep
    # holding CPU and memory until something removes them.
    remove_stale_containers(logger.get_logger("startup_cleanup"))

    warn_about_unconsumable_queues(log)

    compilation_slots = settings.resource_management.get('compilation_slots', 4)
    verification_slots = settings.resource_management.get('verification_slots', 4)
    resource_manager = ResourceManager(compilation_slots, verification_slots)

    processes = []
    try:
        log.info("Starting Code Verification System...")

        dataset_datapoints = []
        if args.dataset:
            log.info(f"Loading dataset from: {args.dataset}")
            dataset_loader = DatasetLoader(args.dataset)
            dataset_datapoints = dataset_loader.load()

        workflow = WorkflowManager()

        if args.resume:
            stages_label = ', '.join(sorted(requested_stages)) if requested_stages else 'all'
            log.info(f"Resuming workflow — stages: {stages_label}")
            workflow.resume_workflow(
                datapoints=dataset_datapoints or None,
                stages=requested_stages,
            )
        else:
            log.info(f"Populating {len(dataset_datapoints)} datapoints...")
            workflow.populate_datapoints(dataset_datapoints)

        processes = start_agents(resource_manager)

        log.info("All agents started. Pipeline is running via queues. Press Ctrl+C to stop.")
        for process in processes:
            process.join()
        log.info("Code Verification System completed successfully")

    except KeyboardInterrupt:
        log.warning("Received keyboard interrupt, shutting down...")
    except Exception as e:
        log.error(f"Fatal error: {str(e)}", exc_info=True)
    finally:
        shutdown_agents(processes, log)


def shutdown_agents(processes, log):
    """Stop the agents, giving in-flight work a chance to finish first.

    An agent killed outright leaves its Docker containers running and its
    in-flight messages unacked, so the same snippets are re-processed from
    scratch on the next start.  SIGTERM first, with a grace period long enough
    for a container wait to return, and only then SIGKILL.
    """
    if not processes:
        return

    log.info(f"Stopping {len(processes)} agent process(es) (SIGTERM, "
             f"{SHUTDOWN_GRACE_SECONDS}s grace)…")
    for process in processes:
        if process.is_alive():
            process.terminate()  # SIGTERM

    deadline = time.monotonic() + SHUTDOWN_GRACE_SECONDS
    for process in processes:
        remaining = max(0.0, deadline - time.monotonic())
        process.join(timeout=remaining)

    for process in processes:
        if process.is_alive():
            log.warning(f"Process {process.name} did not exit within the grace period — killing.")
            process.kill()
            process.join()

    # Whatever the agents left behind (they may have been killed mid-run).
    remove_stale_containers(log)
    log.info("Cleanup completed")

if __name__ == '__main__':
    main()