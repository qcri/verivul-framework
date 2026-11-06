import re
import pika
import os
from config.settings import settings
from src.utils.logger import logger

log = logger.get_logger("snippet_resumer")

# ---------------------------------------------------------------------------
# Retry signalling
# ---------------------------------------------------------------------------

class RetryableError(Exception):
    """Raised by agent callbacks to signal a *transient* infrastructure failure.

    When the QueueConsumer sees this exception from its callback future it will
    NACK the batch with ``requeue=True`` so RabbitMQ re-delivers the messages
    once the transient condition (DB pool exhaustion, Docker API blip, …) has
    cleared.  All other exceptions are NACKed with ``requeue=False``.
    """


class SlotUnavailableError(RetryableError):
    """No compilation/verification slot became free within the timeout.

    A RetryableError subclass on purpose: running out of slots is back-pressure,
    not a property of the snippet, so the message must go back on the queue
    instead of the snippet being recorded as a compilation/verification failure.
    """


class PublishError(RuntimeError):
    """A message could not be handed to the broker, even after retries.

    Distinct from RetryableError: whether re-delivering the *inbound* message is
    the right response depends on how expensive re-doing the work is, so each
    agent decides.  What must never happen is ignoring it.
    """


# ---------------------------------------------------------------------------
# Message acknowledgement outcomes
# ---------------------------------------------------------------------------

class Outcome:
    """Per-message disposition a consumer callback can return.

    Returning a list of these (one per message, in order) lets a batch be
    acknowledged message-by-message, so one transient failure no longer forces
    fifteen siblings to be re-delivered and re-processed.
    """

    ACK = "ack"        # handled; remove from the queue
    RETRY = "retry"    # transient failure; re-deliver
    DROP = "drop"      # permanent failure, already recorded in the DB; do not re-deliver


def log_stranded(agent_log, snippet_uuid: str, resume_stage: str, reason: str) -> None:
    """Record that a snippet's next-stage task could not be queued.

    The snippet's own row is correct, so re-delivering the inbound message would
    only redo expensive work (an LLM call, an ESBMC run) that already succeeded.
    Instead the failure is logged in a greppable form naming the resume stage
    that picks the snippet back up.
    """
    agent_log.error(
        f"STRANDED snippet {snippet_uuid}: {reason}. Its database row is up to date "
        f"but the next stage was never queued. Recover with: "
        f"python scripts/resume_stuck_snippets.py --stages {resume_stage}"
    )


# ---------------------------------------------------------------------------
# Queue name helpers
# ---------------------------------------------------------------------------

_QUEUE_TYPES = ("llm", "compiler", "esbmc")


def make_queue_name(queue_type: str, model_key: str) -> str:
    """Return a deterministic, RabbitMQ-safe queue name.

    Sanitisation steps applied to *model_key*:
      1. Lower-case the whole string.
      2. Replace every character that is not a-z, 0-9, or underscore with '_'.
      3. Collapse runs of underscores to a single '_'.
      4. Strip leading/trailing underscores.

    The result is joined to *queue_type* with '__' as the separator, e.g.
    ``make_queue_name("llm", "openai/gpt-4o")  →  "llm__openai_gpt_4o"``.

    Args:
        queue_type: One of "llm", "compiler", or "esbmc".
        model_key:  The model identifier as stored in config or in the DB
                    (``snippet.generation_model``).  Any form is accepted;
                    the function normalises it.

    Raises:
        ValueError: If *queue_type* is not one of the known types, or if the
                    sanitised *model_key* is empty.
    """
    if queue_type not in _QUEUE_TYPES:
        raise ValueError(
            f"Unknown queue_type '{queue_type}'. Must be one of {_QUEUE_TYPES}."
        )

    sanitised = model_key.lower()
    sanitised = re.sub(r"[^a-z0-9_]", "_", sanitised)
    sanitised = re.sub(r"_+", "_", sanitised)
    sanitised = sanitised.strip("_")

    if not sanitised:
        raise ValueError(
            f"model_key '{model_key}' produced an empty string after sanitisation."
        )

    return f"{queue_type}__{sanitised}"


def counterpart_queue(task_type: str, generation_model: str) -> str:
    """LLM queue for a counterpart task.  Fixes go to pairing.fix_model when it is set and
    enabled (the generating model is often a weak fixer); injections and everything else
    stay with the model that generated the program.  The message keeps the program's own
    generation_model, so the child flows through that model's compile / verify queues."""
    fixer = (settings.pairing or {}).get('fix_model')
    if task_type == 'vulnerability_fix' and fixer and settings.models.get(fixer, {}).get('enabled', True) \
            and fixer in settings.models:
        return make_queue_name("llm", fixer)
    return make_queue_name("llm", generation_model)

def _connection_params() -> pika.ConnectionParameters:
    user = os.getenv("RABBITMQ_USER")
    password = os.getenv("RABBITMQ_PASS")
    return pika.ConnectionParameters(
        host=os.getenv("RABBITMQ_HOST", settings.rabbitmq['host']),
        port=int(os.getenv("RABBITMQ_PORT", settings.rabbitmq['port'])),
        credentials=pika.PlainCredentials(user, password) if user and password else None,
    )


def queue_names_for_models(model_keys) -> list:
    """Return every queue name (plus dlq/retry variants) used by *model_keys*."""
    names = []
    for model_key in model_keys:
        for qt in _QUEUE_TYPES:
            base = make_queue_name(qt, model_key)
            names.extend([base, f"{base}_dlq", f"{base}_retry"])
    return names


def get_queue_depths(model_keys) -> dict:
    """Return ``{queue_name: message_count}`` for existing queues of *model_keys*.

    Uses passive declares, so a queue that does not exist is simply omitted
    rather than being created as a side effect of the check.
    """
    depths = {}
    try:
        with pika.BlockingConnection(_connection_params()) as connection:
            for queue_name in queue_names_for_models(model_keys):
                channel = connection.channel()
                try:
                    frame = channel.queue_declare(queue=queue_name, passive=True)
                    depths[queue_name] = frame.method.message_count
                except pika.exceptions.ChannelClosedByBroker:
                    pass  # queue does not exist
                except Exception as e:
                    log.debug(f"Could not inspect '{queue_name}': {e}")
                finally:
                    try:
                        if channel.is_open:
                            channel.close()
                    except Exception:
                        pass
    except Exception as e:
        log.warning(f"Could not read queue depths from RabbitMQ: {e}")
    return depths


def clear_rabbitmq_queues(model_keys=None):
    """Purge the queues belonging to *model_keys* (defaults to the enabled models).

    Destructive: every pending task in those queues is deleted while the matching
    database rows keep their current status, which strands them.  Only ever call
    this on an explicit request, and pass the models found in the *database* (not
    just those enabled in config) when the intent is a genuine clean slate —
    queues of disabled models are otherwise unreachable and never purged.
    """
    if model_keys is None:
        model_keys = list(settings.models)
    log.info("Attempting to clear RabbitMQ queues...")
    try:
        with pika.BlockingConnection(_connection_params()) as connection:
            queues_to_clear = queue_names_for_models(model_keys)

            for queue_name in queues_to_clear:
                # Each queue_purge that targets a non-existent queue causes the
                # broker to close the channel with a 404.  Reopen before retrying.
                channel = connection.channel()
                try:
                    purged_frame = channel.queue_purge(queue=queue_name)
                    log.info(
                        f"Purged '{queue_name}': "
                        f"{purged_frame.method.message_count} messages deleted."
                    )
                except pika.exceptions.ChannelClosedByBroker as e:
                    log.warning(f"Queue '{queue_name}' does not exist — skipping. ({e})")
                except Exception as e:
                    log.error(f"Error purging '{queue_name}': {e}", exc_info=True)
                finally:
                    try:
                        if channel.is_open:
                            channel.close()
                    except Exception:
                        pass
        log.info("Successfully attempted to clear RabbitMQ queues.")
    except pika.exceptions.AMQPConnectionError as e:
        log.error(f"Could not connect to RabbitMQ to clear queues: {str(e)}. Please ensure RabbitMQ is running.")
    except Exception as e:
        log.error(f"An unexpected error occurred while clearing RabbitMQ queues: {str(e)}", exc_info=True)
