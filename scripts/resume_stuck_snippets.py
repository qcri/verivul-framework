"""
Recover snippets that are stranded mid-pipeline, without needing live agents.

Unlike ``python main.py --resume --stages ...`` (which only re-publishes RabbitMQ
messages and therefore does nothing unless the agent processes are consuming),
this script performs the *compile* and *verify* work itself in a local
multiprocessing pool and writes the results straight to the database.  Use it
when the pipeline has been stopped, when a queue has been purged, or when a
snippet's next-stage task was lost.

Stages (select with ``--stages``; default is all five, run in this order):

  compile      GENERATION_SUCCESS   → compile locally, write COMPILATION_SUCCESS/FAILED
  compile_fix  COMPILATION_FAILED   → publish a compilation_fix task   [needs a live LLM agent]
  verify       COMPILATION_SUCCESS  → run ESBMC locally, write status/label/witness/CWEs
  inject_fix   VERIFICATION_SUCCESS → publish vulnerability_fix / inject_vulnerability
                                      for originals that have no derived child (a C/C++
                                      VULNERABLE one only once it is REPRODUCED)
                                                                       [needs a live LLM agent]
  reproduce    reproduced = PENDING → publish reproduce_poc (the LLM proof-of-concept round)
                                                                       [needs live LLM + ESBMC agents]

Compilation and verification reuse ``build_compile_script`` /
``build_verification_command`` / ``get_verdict`` from the agents, so a snippet
resumed here is compiled and verified with byte-identical flags and mapped to a
label by identical rules.  Do not inline copies of those commands here.

Only snippets whose ``updated_at`` is older than ``--stuck-minutes`` are touched,
so work that an agent is currently holding in flight is left alone.

Throughput is set by two dials, ``--workers`` and ``--esbmc-timeout``.  Measured
over 5.8k real verifications, mean wall time was 80 s per snippet and 37% ran to
the 120 s limit — consuming 55% of all worker time while producing no usable
label.  Lowering ``--esbmc-timeout`` trades that back for coverage: 90 s is
~1.34x faster and loses a verdict on ~8% of snippets, 60 s is ~1.78x and loses
~17%.  The default keeps ``esbmc.timeout`` from config, i.e. no change in labels.

Run:
  python scripts/resume_stuck_snippets.py                          # all stages
  python scripts/resume_stuck_snippets.py --stages verify
  python scripts/resume_stuck_snippets.py --stages compile,verify
  python scripts/resume_stuck_snippets.py --stages verify --workers 48
  python scripts/resume_stuck_snippets.py --stages verify --esbmc-timeout 60
  python scripts/resume_stuck_snippets.py --stages verify --include-errors
  python scripts/resume_stuck_snippets.py --stages inject_fix --dry-run
  python scripts/resume_stuck_snippets.py --stages verify --models gemma-4-31b-it --limit 500
"""
import argparse
import multiprocessing
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import docker
from docker.errors import APIError, ContainerError, DockerException, ImageNotFound
from docker.types import Mount
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import ReadTimeout
from sqlalchemy.orm import load_only

from src.agents.compiler_agent import (
    build_compile_script,
    install_step_script,
    needs_install_step,
    normalise_install_command,
    normalise_language,
)
from src.agents.esbmc_agent import (
    ESBMC_LANG_EXT,
    VerificationResult,
    build_verification_command,
    build_verification_meta,
    code_hash,
    extract_artifacts,
    get_verdict,
    infer_cwes_from_esbmc_log,
    pair_rejection_reason,
)
from src.db.database import DatabaseManager
from src.db.models import CodeSnippet, Label, Reproduced, Status, Type, ready_for_counterpart
from src.queue.producer import QueueProducer
from src.utils.docker_cleanup import container_labels, reclaim_trap, remove_stale_containers
from src.utils.logger import logger
from src.utils.queue import make_queue_name, counterpart_queue
from config.settings import settings

log = logger.get_logger("snippet_resumer")

# --- Constants ---
STAGES = ("compile", "compile_fix", "verify", "inject_fix", "reproduce")

# Stages that do their work locally in Docker; the rest only publish messages
# and therefore need the corresponding agent to be consuming.
LOCAL_STAGES = ("compile", "verify")

# A snippet is only considered stuck once it has been untouched for this long.
# Must stay above the pipeline's worst-case in-flight time, otherwise this
# script duplicates work an agent is still doing: an ESBMC consumer holds a
# batch of `esbmc_batch_size` snippets and processes them serially, each up to
# `esbmc.timeout` seconds, after waiting up to `esbmc_batch_timeout` for the
# batch to fill.  With the shipped config that is ~40 minutes.
DEFAULT_STUCK_MINUTES = 1

DEFAULT_COMPILE_TIMEOUT = 120
DEFAULT_INSTALL_TIMEOUT = 300
MAX_RETRIES = 3
INITIAL_BACKOFF_SECONDS = 2
DEFAULT_MAX_FIX_ATTEMPTS = 3

# One Docker client per pool worker process (created lazily on first use).
_docker_client = None


def _get_docker_client():
    global _docker_client
    if _docker_client is None:
        _docker_client = docker.from_env()
        _docker_client.ping()
    return _docker_client


def _mem_limit_mb(value: str, default_mb: int = 2048) -> int:
    """Parse a Docker-style memory limit ("2048m", "4g") into MB."""
    text = str(value).strip().lower()
    try:
        if text.endswith("g"):
            return int(float(text[:-1]) * 1024)
        if text.endswith("m"):
            return int(float(text[:-1]))
        return max(1, int(float(text)) // (1024 * 1024))
    except ValueError:
        return default_mb


def default_workers() -> int:
    """Choose a pool size from the machine, bounded by RAM.

    This is the resume script's own concurrency limiter — it does not take
    ResourceManager slots, so sizing it from ``verification_slots`` needlessly
    caps throughput (a measured run sustained ~34 parallel workers).  Half the
    CPUs matches the per-container ``esbmc_cpu_limit`` of 1 while leaving room for
    everything else on the box, and the RAM bound stops N x esbmc_mem_limit from
    exhausting memory.
    """
    cpu_workers = max(1, (os.cpu_count() or 2) // 2)
    mem_per_worker = _mem_limit_mb(settings.resource_management.get("esbmc_mem_limit", "2048m"))
    try:
        with open("/proc/meminfo") as f:
            available_kb = next(
                int(line.split()[1]) for line in f if line.startswith("MemAvailable:")
            )
        mem_workers = max(1, int(available_kb / 1024 / max(1, mem_per_worker) * 0.8))
    except Exception:
        mem_workers = cpu_workers
    return max(1, min(cpu_workers, mem_workers))


# ---------------------------------------------------------------------------
# Docker execution
# ---------------------------------------------------------------------------

def compile_code(
    code: str, language: str, install_command: Optional[str] = None
) -> Tuple[bool, str]:
    """Compile a snippet in Docker using the CompilerAgent's script and flags."""
    language_norm = normalise_language(language)
    image_name = settings.docker_images.get(language_norm)
    if not image_name:
        return False, f"No Docker image configured for language: {language}"

    compile_script, source_filename = build_compile_script(language_norm)
    if not compile_script:
        return False, f"No compiler implementation for language: {language}"

    rm_cfg = settings.resource_management
    timeout = (
        rm_cfg.get('compiler_install_timeout', DEFAULT_INSTALL_TIMEOUT)
        if needs_install_step(install_command)
        else DEFAULT_COMPILE_TIMEOUT
    )

    try:
        client = _get_docker_client()
    except DockerException as e:
        return False, f"Docker connection failed: {e}"

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as host_temp_dir:
        with open(os.path.join(host_temp_dir, source_filename), 'w', encoding='utf-8') as f:
            f.write(code)

        full_script = "#!/bin/bash\nset -eo pipefail\n"
        # The container runs as root; hand /app back to the host user on exit so
        # the temp dir can always be cleaned up.
        full_script += reclaim_trap("/app") + "\n"
        full_script += install_step_script(install_command)
        full_script += compile_script + "\n"

        script_path = os.path.join(host_temp_dir, "run_compile.sh")
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(full_script)
        os.chmod(script_path, 0o755)

        container_name = f"verivul-resume-compile-{language_norm}-{os.urandom(4).hex()}"
        container = None
        try:
            try:
                client.images.get(image_name)
            except ImageNotFound:
                client.images.pull(image_name)

            cpu_limit = rm_cfg.get('compiler_cpu_limit', 0)
            container = client.containers.run(
                image=image_name,
                command=["/bin/bash", "/app/run_compile.sh"],
                mounts=[Mount(target="/app", source=host_temp_dir, type="bind")],
                working_dir="/app",
                stderr=True, stdout=True, detach=True,
                name=container_name,
                mem_limit=rm_cfg.get('compiler_mem_limit', '512m'),
                # Labelled like the agents' containers so a killed run's leftovers
                # are swept up on the next pipeline start.
                labels=container_labels("resume-compile"),
                **({"nano_cpus": int(cpu_limit * 1e9)} if cpu_limit > 0 else {}),
            )
            exit_code = container.wait(timeout=timeout).get("StatusCode", -1)
            logs = container.logs(stdout=True, stderr=True).decode('utf-8', 'replace')
            return exit_code == 0, logs
        except (ReadTimeout, RequestsConnectionError):
            return False, f"Compilation did not complete within {timeout}s ({container_name})."
        except (ContainerError, APIError, ImageNotFound) as e:
            logs = e.stderr.decode('utf-8', 'replace') if getattr(e, "stderr", None) else str(e)
            return False, f"Container execution failed:\n{logs}"
        except Exception as e:
            return False, f"Compilation failed unexpectedly after {timeout}s: {e}"
        finally:
            _remove_container(container)


_image_digest: Optional[str] = None


def _get_image_digest(client, image: str) -> Optional[str]:
    global _image_digest
    if _image_digest is None:
        try:
            _image_digest = client.images.get(image).id
        except Exception:
            _image_digest = ""
    return _image_digest or None


def verify_code(
    code: str, language: str, install_command: Optional[str],
    verification_timeout: Optional[int] = None, path: str = "resume",
    extra_flags: Optional[List[str]] = None,
) -> VerificationResult:
    """Verify a snippet with ESBMC in Docker, mirroring ESBMCAgent.verify_code."""
    started = time.monotonic()
    esbmc_image = settings.esbmc.get('image', 'esbmc:8.4')
    command = ""

    def result(status, label, logs, witness=None, artifacts=None, digest=None):
        meta = build_verification_meta(logs, command, esbmc_image, digest,
                                       time.monotonic() - started, path, artifacts)
        return VerificationResult(status, label, logs, witness, meta)

    language = language.lower().replace("c++", "cpp")
    file_ext = ESBMC_LANG_EXT.get(language)
    if not file_ext:
        return result(Status.VERIFICATION_ERROR, Label.UNKNOWN, f"Unsupported language: {language}")

    rm_cfg = settings.resource_management
    if verification_timeout is None:
        verification_timeout = int(settings.esbmc.get('timeout', 300))

    try:
        client = _get_docker_client()
    except DockerException as e:
        return result(Status.VERIFICATION_ERROR, Label.UNKNOWN, f"Docker connection failed: {e}")
    digest = _get_image_digest(client, esbmc_image)

    container_source_path = f"/work/source.{file_ext}"
    verify_lang = "kt" if language == "kotlin" else language
    # Pass the same budget to ESBMC so it reports a verdict instead of being
    # killed mid-run by the container wait.
    verification_cmd = build_verification_command(
        verify_lang, container_source_path, container_timeout=verification_timeout,
        extra_flags=extra_flags,
    )
    command = verification_cmd
    # Skip placeholder install commands, and never let a failing install stop
    # ESBMC from running (see the note in esbmc_agent.verify_code).
    full_command = (
        f"{{ {normalise_install_command(install_command)} ; }} ; {verification_cmd}"
        if needs_install_step(install_command) else verification_cmd
    )

    temp_file_path = None
    container = None
    container_name = f"verivul-resume-esbmc-{language}-{os.urandom(4).hex()}"
    try:
        with tempfile.NamedTemporaryFile(
            suffix=f".{file_ext}", delete=False, mode='w', encoding='utf-8'
        ) as temp_file:
            temp_file_path = temp_file.name
            temp_file.write(code)
            temp_file.flush()
            os.fsync(temp_file.fileno())

        cpu_limit = rm_cfg.get('esbmc_cpu_limit', 0)
        container = client.containers.create(
            image=esbmc_image,
            command=["sh", "-c", full_command],
            volumes={os.path.abspath(temp_file_path): {'bind': container_source_path, 'mode': 'ro'}},
            working_dir="/work", detach=True, name=container_name,
            mem_limit=rm_cfg.get('esbmc_mem_limit', '4096m'),
            labels=container_labels("resume-esbmc"),
            **({"nano_cpus": int(cpu_limit * 1e9)} if cpu_limit > 0 else {}),
        )
        container.start()
        try:
            exit_code = container.wait(timeout=verification_timeout).get('StatusCode', -1)
        except (ReadTimeout, RequestsConnectionError) as e:
            logs = f"[TIMEOUT] Docker SDK wait timed out after {verification_timeout}s ({container_name}): {e}\n"
            try:
                logs += "\nPartial logs before timeout:\n" + container.logs(
                    stdout=True, stderr=True, tail=50
                ).decode('utf-8', 'replace')
            except Exception as log_err:
                logs += f"[Error retrieving partial logs: {log_err}]"
            return result(Status.VERIFICATION_TIMEOUT, Label.UNKNOWN, logs, digest=digest)

        logs = container.logs(stdout=True, stderr=True).decode('utf-8', 'replace')
        artifacts = extract_artifacts(container)
        status, label = get_verdict(logs, exit_code)
        return result(status, label, logs, artifacts.get('witness_graphml'), artifacts, digest)

    except (ContainerError, APIError) as e:
        return result(Status.VERIFICATION_ERROR, Label.UNKNOWN, f"[Docker Error] {e}", digest=digest)
    except Exception as e:
        return result(Status.VERIFICATION_ERROR, Label.UNKNOWN, f"Verification error: {e}", digest=digest)
    finally:
        _remove_container(container)
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
            except OSError as unlink_err:
                log.error(f"Failed to remove host temporary file {temp_file_path}: {unlink_err}")


def _remove_container(container) -> None:
    if not container:
        return
    try:
        container.remove(force=True)
    except APIError as e:
        log.debug(f"Could not remove container: {e}")
    except Exception as e:
        log.debug(f"Error removing container: {e}")


# ---------------------------------------------------------------------------
# Pool workers — these run in child processes and must never touch the DB
# ---------------------------------------------------------------------------

def compilation_worker(snippet_info: Dict) -> Dict:
    uuid = snippet_info["uuid"]
    try:
        log.info(f"Compiling snippet: {uuid}")
        success, log_output = compile_code(
            snippet_info["code"], snippet_info["language"], snippet_info["install_command"]
        )
        status = Status.COMPILATION_SUCCESS if success else Status.COMPILATION_FAILED
        log.info(f"Compilation for {uuid}: Status: {status.value}")
        return {
            "uuid": uuid,
            "status": status.value,
            "attempt_count": snippet_info.get("attempt_count", 0) + 1,
            "compilation_log": log_output,
        }
    except Exception as e:
        log.error(f"Unexpected error in compilation_worker for {uuid}: {e}", exc_info=True)
        return {
            "uuid": uuid,
            "status": Status.COMPILATION_FAILED.value,
            "attempt_count": snippet_info.get("attempt_count", 0) + 1,
            "compilation_log": f"Worker failed unexpectedly: {e}",
        }


def verification_worker(snippet_info: Dict) -> Dict:
    uuid = snippet_info["uuid"]
    try:
        log.info(f"Verifying snippet: {uuid}")
        status, label, log_output, witness, meta = verify_code(
            snippet_info["code"], snippet_info["language"], snippet_info["install_command"],
            verification_timeout=snippet_info.get("verification_timeout"),
        )
        log.info(f"Verification for {uuid}: Status: {status.value} | Label: {label.value}")
        result = {
            "uuid": uuid,
            "status": status.value,
            "label": label.value,
            "esbmc_log": log_output,
            "witness": witness,
            "verification_meta": meta,
            "verified_code_hash": code_hash(snippet_info["code"]),
        }
        # Same CWE rules as ESBMCAgent.process_message: infer for VULNERABLE,
        # clear inherited CWEs on a fix-derived SAFE snippet.
        if label == Label.VULNERABLE:
            inferred = infer_cwes_from_esbmc_log(log_output)
            if inferred:
                result["cwes"] = ','.join(inferred)
        elif label == Label.SAFE and snippet_info.get("parent_uuid"):
            result["cwes"] = None
        return result
    except Exception as e:
        log.error(f"Unexpected error in verification_worker for {uuid}: {e}", exc_info=True)
        return {
            "uuid": uuid,
            "status": Status.VERIFICATION_ERROR.value,
            "label": Label.UNKNOWN.value,
            "esbmc_log": f"Worker failed unexpectedly: {e}",
        }


# ---------------------------------------------------------------------------
# Database writes
# ---------------------------------------------------------------------------

def update_snippet_with_retry(result: Dict, db_manager: DatabaseManager) -> bool:
    """Update a single snippet, retrying with exponential backoff.

    update_snippet() raises on a real write failure and returns False only when
    the snippet no longer exists, so both are handled explicitly — treating
    "no exception" as success is how a failed write becomes a stuck snippet.
    NUL bytes in ESBMC logs and witnesses are scrubbed by the DB layer.
    """
    uuid = result.get("uuid", "unknown")
    for attempt in range(MAX_RETRIES):
        try:
            if db_manager.update_snippet(uuid=uuid, metadata=result):
                log.info(f"Successfully updated snippet {uuid} on attempt {attempt + 1}.")
                return True
            log.warning(f"Snippet {uuid} no longer exists — skipping.")
            return True
        except Exception as e:
            log.warning(f"Attempt {attempt + 1}/{MAX_RETRIES} to update snippet {uuid} failed: {e}")
            if attempt + 1 < MAX_RETRIES:
                wait_time = INITIAL_BACKOFF_SECONDS * (2 ** attempt)
                log.info(f"Retrying snippet {uuid} in {wait_time} seconds...")
                time.sleep(wait_time)

    log.error(f"Failed to update snippet {uuid} after {MAX_RETRIES} attempts. Adding to pending list.")
    return False


def bulk_update_database(results: List[Dict], db_manager: DatabaseManager) -> None:
    """Final best-effort pass over snippets whose individual update failed."""
    if not results:
        return

    log.info(f"Attempting bulk update for {len(results)} failed snippets.")
    for attempt in range(MAX_RETRIES):
        try:
            for result in results:
                db_manager.update_snippet(uuid=result["uuid"], metadata=result)
            log.info(f"Bulk update of {len(results)} snippets successful on attempt {attempt + 1}.")
            return
        except Exception as e:
            log.warning(f"Attempt {attempt + 1}/{MAX_RETRIES} to bulk update DB failed: {e}")
            if attempt + 1 == MAX_RETRIES:
                log.error(f"Failed to update DB after {MAX_RETRIES} attempts. Giving up on this batch.")
                return
            wait_time = INITIAL_BACKOFF_SECONDS * (2 ** attempt)
            log.info(f"Retrying bulk update in {wait_time} seconds...")
            time.sleep(wait_time)


def prune_invalid_pairs(results: List[Dict], db_manager: DatabaseManager) -> int:
    """Delete derived snippets that did not end up forming a cross-label pair.

    Mirrors ESBMCAgent.process_message: a snippet with a parent must be
    VULNERABLE→SAFE or SAFE→VULNERABLE; anything else is not a usable pair.
    """
    removed = 0
    for result in results:
        snippet = db_manager.get_snippet(uuid=result["uuid"])
        if not snippet or not snippet.parent_uuid:
            continue
        parent = db_manager.get_snippet(uuid=snippet.parent_uuid)
        reason = pair_rejection_reason(parent, snippet.label, snippet.code, snippet.verification_meta)
        if reason:
            db_manager.delete_snippet(uuid=result["uuid"])
            removed += 1
            log.info(f"Removed derived snippet {result['uuid']}: {reason}")
    return removed


# ---------------------------------------------------------------------------
# Stage task collection
# ---------------------------------------------------------------------------

def stuck_cutoff(stuck_minutes: int) -> datetime:
    """Return the naive-UTC ``updated_at`` boundary below which a row counts as stuck.

    ``code_snippets.updated_at`` is a timestamp *without* time zone written by
    the database's ``now()``, and the rest of the codebase reads it as UTC, so
    the cutoff is built in UTC and stripped of its tzinfo to compare in SQL.
    """
    return (datetime.now(timezone.utc) - timedelta(minutes=stuck_minutes)).replace(tzinfo=None)


def _task_info(snippet: CodeSnippet) -> Dict:
    return {
        "uuid": snippet.uuid,
        "code": snippet.code,
        "language": snippet.language,
        "attempt_count": snippet.attempt_count,
        "install_command": snippet.install_command,
        "parent_uuid": snippet.parent_uuid,
    }


def collect_local_tasks(
    session, statuses: List[str], cutoff: datetime,
    models: Optional[List[str]], limit: Optional[int],
) -> List[Dict]:
    """Return task dicts for stuck GENERATED snippets in any of *statuses*."""
    # load_only, not the whole row: `esbmc_log` averages 3.5 KB (up to 5 MB) and
    # `compilation_log` adds more, none of which a compile/verify task needs.
    # Fetching only what the workers use halves the transfer and the memory held
    # while the pool churns through thousands of snippets.
    q = (
        session.query(CodeSnippet)
        .options(load_only(
            CodeSnippet.uuid,
            CodeSnippet.code,
            CodeSnippet.language,
            CodeSnippet.install_command,
            CodeSnippet.attempt_count,
            CodeSnippet.parent_uuid,
            CodeSnippet.updated_at,
        ))
        .filter(CodeSnippet.type == Type.GENERATED.value,
                CodeSnippet.status.in_(statuses),
                CodeSnippet.updated_at < cutoff)
    )
    if models:
        q = q.filter(CodeSnippet.generation_model.in_(models))
    q = q.order_by(CodeSnippet.updated_at)
    if limit:
        q = q.limit(limit)

    return [_task_info(snippet) for snippet in q.yield_per(500)]


def run_pool_stage(
    stage: str, worker, tasks: List[Dict], workers: int, db_manager: DatabaseManager
) -> List[Dict]:
    """Run *worker* over *tasks* in a pool, persisting each result as it lands."""
    if not tasks:
        log.info(f"[{stage}] Nothing to do.")
        return []

    log.info(f"[{stage}] Starting pool of {workers} worker(s) for {len(tasks)} snippet(s).")
    results, pending_updates = [], []
    with multiprocessing.Pool(processes=workers) as pool:
        for result in pool.imap_unordered(worker, tasks):
            results.append(result)
            if not update_snippet_with_retry(result, db_manager):
                pending_updates.append(result)

    bulk_update_database(pending_updates, db_manager)
    log.info(f"[{stage}] Processed {len(results)} snippet(s).")
    return results


# ---------------------------------------------------------------------------
# Publish-only stages
# ---------------------------------------------------------------------------

def enabled_models() -> set:
    """Models that main.py will actually start agents for."""
    return {k for k, cfg in settings.models.items() if cfg.get("enabled", True)}


def warn_unconsumable(models_seen: set, stage: str) -> None:
    """Warn about publishing to queues no agent will ever consume.

    ``start_agents()`` iterates ``settings.models``, so a snippet whose
    generation_model is absent or disabled in config.yaml gets its task queued
    into a queue with no consumer — where it stays forever.
    """
    orphaned = models_seen - enabled_models()
    if orphaned:
        log.warning(
            f"[{stage}] Published tasks for model(s) not enabled in config.yaml: "
            f"{', '.join(sorted(orphaned))}. No agent will consume these queues — "
            f"enable the model in config/config.yaml or those snippets stay stuck."
        )


def _publish(producer: QueueProducer, queue_name: str, message: Dict, dry_run: bool) -> bool:
    """Publish a task, treating a False return as a failure worth reporting.

    publish_message() swallows broker errors and returns False; callers that
    ignore it are how a snippet ends up with a committed status and no
    downstream task — exactly the orphan state this script cleans up.
    """
    if dry_run:
        log.info(f"[dry-run] would publish {message.get('task_type', 'task')} "
                 f"{message['uuid']} → {queue_name}")
        return True
    if producer.publish_message(queue_name, message):
        return True
    log.error(
        f"PUBLISH FAILED for {message['uuid']} → {queue_name}. The snippet is still "
        f"stranded; re-run this stage once RabbitMQ is healthy."
    )
    return False


def stage_compile_fix(
    session, producer: QueueProducer, cutoff: datetime,
    models: Optional[List[str]], limit: Optional[int], max_attempts: int, dry_run: bool,
) -> None:
    """Re-publish compilation_fix tasks for stuck COMPILATION_FAILED snippets."""
    q = session.query(CodeSnippet).filter(
        CodeSnippet.type == Type.GENERATED.value,
        CodeSnippet.status == Status.COMPILATION_FAILED.value,
        CodeSnippet.updated_at < cutoff,
    )
    if models:
        q = q.filter(CodeSnippet.generation_model.in_(models))

    queued = skipped = failed = 0
    models_seen = set()
    for snippet in q.order_by(CodeSnippet.updated_at).yield_per(500):
        if snippet.attempt_count >= max_attempts:
            skipped += 1
            continue
        models_seen.add(snippet.generation_model)
        ok = _publish(
            producer,
            make_queue_name("llm", snippet.generation_model),
            {'uuid': snippet.uuid, 'task_type': 'compilation_fix',
             'attempt_count': snippet.attempt_count},
            dry_run,
        )
        queued += ok
        failed += not ok
        if limit and queued >= limit:
            break

    log.info(
        f"[compile_fix] Queued {queued} compilation_fix task(s); "
        f"{skipped} exhausted max retries ({max_attempts}); {failed} publish failure(s)."
    )
    warn_unconsumable(models_seen, "compile_fix")


def stage_reproduce(
    session, producer: QueueProducer, cutoff: datetime,
    models: Optional[List[str]], limit: Optional[int], dry_run: bool,
) -> None:
    """Re-publish the proof-of-concept task for VULNERABLE snippets left PENDING (its
    reproduce_poc or replay_poc message was lost)."""
    q = session.query(CodeSnippet.uuid, CodeSnippet.generation_model).filter(
        CodeSnippet.reproduced == Reproduced.PENDING.value,
        CodeSnippet.label == Label.VULNERABLE.value,
        CodeSnippet.updated_at < cutoff,
    )
    if models:
        q = q.filter(CodeSnippet.generation_model.in_(models))
    queued = failed = 0
    models_seen = set()
    for row in q.order_by(CodeSnippet.updated_at).yield_per(500):
        models_seen.add(row.generation_model)
        ok = _publish(producer, make_queue_name("llm", row.generation_model),
                      {'uuid': row.uuid, 'task_type': 'reproduce_poc', 'round': 1, 'tried': []}, dry_run)
        queued += ok
        failed += not ok
        if limit and queued >= limit:
            break
    log.info(f"[reproduce] Queued {queued} reproduce_poc task(s); {failed} publish failure(s).")
    warn_unconsumable(models_seen, "reproduce")


def stage_inject_fix(
    session, producer: QueueProducer, cutoff: datetime,
    models: Optional[List[str]], limit: Optional[int], dry_run: bool,
    retry_exhausted: bool = False,
) -> None:
    """Re-publish vulnerability_fix / inject_vulnerability tasks for verified
    originals (SAFE or VULNERABLE) that never produced a derived child."""
    child_parent_uuids = {
        row[0] for row in
        session.query(CodeSnippet.parent_uuid).filter(CodeSnippet.parent_uuid.isnot(None))
    }

    q = session.query(CodeSnippet).filter(
        CodeSnippet.type == Type.GENERATED.value,
        CodeSnippet.parent_uuid.is_(None),
        CodeSnippet.status == Status.VERIFICATION_SUCCESS.value,
        CodeSnippet.label.in_([Label.SAFE.value, Label.VULNERABLE.value]),
        CodeSnippet.updated_at < cutoff,
        # Originals that used up pairing.max_attempts were retried by the pipeline already;
        # queueing them again costs an LLM call and an ESBMC run for a low chance of a pair.
        *([] if retry_exhausted else [CodeSnippet.pair_attempts < int(settings.pairing.get('max_attempts', 3))]),
        *([ready_for_counterpart()] if settings.esbmc.get('dynamic_confirm', True) else []),
    )
    if models:
        q = q.filter(CodeSnippet.generation_model.in_(models))
    if child_parent_uuids:
        q = q.filter(CodeSnippet.uuid.notin_(child_parent_uuids))

    fix_count = inject_count = failed = 0
    models_seen = set()
    for snippet in q.order_by(CodeSnippet.updated_at).yield_per(500):
        log.warning(f"Snippet {snippet.uuid} is stuck in VERIFICATION_SUCCESS ({snippet.label}).")
        models_seen.add(snippet.generation_model)
        base_msg = {
            "uuid": snippet.uuid,
            "seed_uuid": snippet.seed_uuid,
            "generation_model": snippet.generation_model,
            "language": snippet.language,
            "project": snippet.project or "",
            "cwes": [cwe.id for cwe in snippet.cwes] if snippet.cwes else [],
            "commit_message": snippet.commit_message or "",
            "install_command": snippet.install_command or "",
        }
        task_type = ("vulnerability_fix" if snippet.label == Label.VULNERABLE.value
                     else "inject_vulnerability")
        ok = _publish(
            producer,
            counterpart_queue(task_type, snippet.generation_model),
            {**base_msg, "task_type": task_type},
            dry_run,
        )
        if ok and retry_exhausted and snippet.pair_attempts and not dry_run:
            snippet.pair_attempts = 0  # a fresh budget for the improved fix / inject prompts
        if not ok:
            failed += 1
        elif task_type == "vulnerability_fix":
            fix_count += 1
        else:
            inject_count += 1

        if limit and (fix_count + inject_count) >= limit:
            break

    log.info(
        f"[inject_fix] Queued {fix_count} vulnerability_fix and {inject_count} "
        f"inject_vulnerability task(s); {failed} publish failure(s)."
    )
    warn_unconsumable(models_seen, "inject_fix")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def resume_stuck_snippets(
    stages: Tuple[str, ...],
    stuck_minutes: int,
    workers: int,
    models: Optional[List[str]] = None,
    limit: Optional[int] = None,
    include_errors: bool = False,
    include_timeouts: bool = False,
    esbmc_timeout: Optional[int] = None,
    max_fix_attempts: int = DEFAULT_MAX_FIX_ATTEMPTS,
    dry_run: bool = False,
    retry_exhausted: bool = False,
) -> None:
    log.info(
        f"Starting stuck snippets resumption — stages: {', '.join(stages)}; "
        f"stuck threshold: {stuck_minutes} min; workers: {workers}"
        + (f"; models: {', '.join(models)}" if models else "")
        + (f"; limit per stage: {limit}" if limit else "")
        + (" [DRY RUN]" if dry_run else "")
    )

    # Containers left behind by a killed agent or a previous resume run keep
    # consuming CPU and memory; a live owner's containers are left alone.
    remove_stale_containers(log)

    db_manager = DatabaseManager(caller="SnippetResumer")
    producer = None
    if {"compile_fix", "inject_fix", "reproduce"} & set(stages) and not dry_run:
        producer = QueueProducer(
            caller="SnippetResumer",
            host=settings.rabbitmq["host"],
            port=settings.rabbitmq["port"],
        )

    cutoff = stuck_cutoff(stuck_minutes)
    log.info(f"Treating snippets untouched since {cutoff.isoformat()} (UTC) as stuck.")

    try:
        # --- compile: GENERATION_SUCCESS → compile locally -------------------
        compiled_ok: List[str] = []
        if "compile" in stages:
            with db_manager.session_scope() as session:
                tasks = collect_local_tasks(
                    session, [Status.GENERATION_SUCCESS.value], cutoff, models, limit,
                )
            log.info(f"[compile] {len(tasks)} stuck snippet(s) awaiting compilation.")
            if dry_run:
                log.info(f"[dry-run] would compile {len(tasks)} snippet(s).")
            else:
                results = run_pool_stage("compile", compilation_worker, tasks, workers, db_manager)
                compiled_ok = [
                    r["uuid"] for r in results
                    if r.get("status") == Status.COMPILATION_SUCCESS.value
                ]

        # --- verify: COMPILATION_SUCCESS → run ESBMC locally -----------------
        if "verify" in stages:
            statuses = [Status.COMPILATION_SUCCESS.value]
            if include_errors:
                statuses.append(Status.VERIFICATION_ERROR.value)
            if include_timeouts:
                # Deliberately separate from --include-errors: a timeout is
                # reproducible, so re-running one costs a full esbmc timeout to
                # land on the same verdict.  At 11k timed-out snippets that is
                # ~380 worker-hours, which is only worth spending together with a
                # different --esbmc-timeout or different ESBMC flags.
                statuses.append(Status.VERIFICATION_TIMEOUT.value)
            with db_manager.session_scope() as session:
                tasks = collect_local_tasks(session, statuses, cutoff, models, limit)
                # Snippets this run just compiled are newer than the threshold,
                # so chain them in explicitly instead of forcing a second run.
                already = {t["uuid"] for t in tasks}
                for uuid in compiled_ok:
                    if uuid in already:
                        continue
                    snippet = session.query(CodeSnippet).filter(
                        CodeSnippet.uuid == uuid).first()
                    if snippet:
                        tasks.append(_task_info(snippet))
            for task in tasks:
                task["verification_timeout"] = esbmc_timeout
            log.info(
                f"[verify] {len(tasks)} snippet(s) awaiting verification "
                f"(statuses: {', '.join(statuses)}"
                + (f"; +{len(compiled_ok)} just compiled" if compiled_ok else "")
                + ")."
            )
            if dry_run:
                log.info(f"[dry-run] would verify {len(tasks)} snippet(s).")
            else:
                results = run_pool_stage("verify", verification_worker, tasks, workers, db_manager)
                removed = prune_invalid_pairs(results, db_manager)
                if removed:
                    log.info(f"[verify] Removed {removed} non-conclusive derived snippet(s).")

        # --- publish-only stages --------------------------------------------
        if {"compile_fix", "inject_fix", "reproduce"} & set(stages):
            with db_manager.session_scope() as session:
                if "compile_fix" in stages:
                    stage_compile_fix(session, producer, cutoff, models,
                                      limit, max_fix_attempts, dry_run)
                if "inject_fix" in stages:
                    stage_inject_fix(session, producer, cutoff, models, limit, dry_run, retry_exhausted)
                if "reproduce" in stages:
                    stage_reproduce(session, producer, cutoff, models, limit, dry_run)

    except Exception as e:
        log.error(f"An error occurred during snippet resumption: {e}", exc_info=True)
        raise
    finally:
        if producer:
            producer.close()


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--stages", default=",".join(STAGES), metavar="STAGE[,STAGE...]",
        help=(f"Comma-separated stages to run, in fixed order. Available: "
              f"{', '.join(STAGES)}. Locally executed (no agents needed): "
              f"{', '.join(LOCAL_STAGES)}. Default: all."),
    )
    parser.add_argument(
        "--stuck-minutes", type=int, default=DEFAULT_STUCK_MINUTES,
        help=(f"Only touch snippets untouched for this many minutes "
              f"(default: {DEFAULT_STUCK_MINUTES}). Lowering this below the "
              f"pipeline's in-flight time duplicates work the agents are still doing."),
    )
    parser.add_argument(
        "--workers", type=int, default=None,
        help=("Pool size for the compile/verify stages. Default: half the CPUs, "
              "capped by available RAM / esbmc_mem_limit — this is the main "
              "throughput dial, since each worker owns one container at a time. "
              "Pass a small value (e.g. verification_slots) when running "
              "alongside a live pipeline so the two do not oversubscribe the box."),
    )
    parser.add_argument(
        "--esbmc-timeout", type=int, default=None, metavar="SECONDS",
        help=("Per-snippet ESBMC budget (default: esbmc.timeout from config). This "
              "is the second throughput dial and a coverage trade-off: 37%% of "
              "snippets run to the current 120s wall and consume 55%% of all worker "
              "time while yielding no usable label. Measured on 5.8k real "
              "verifications: 60s gives ~1.8x throughput and loses a verdict on "
              "~17%% of snippets; 90s gives ~1.34x and loses ~8%%."),
    )
    parser.add_argument(
        "--models", default=None, metavar="MODEL[,MODEL...]",
        help="Restrict to these generation_model values (default: all models in the DB).",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Cap the number of snippets handled per stage (default: no cap).",
    )
    parser.add_argument(
        "--include-errors", action="store_true",
        help=("In the verify stage, also retry VERIFICATION_ERROR snippets — some "
              "of those were infrastructure failures, and no other stage ever "
              "revisits them."),
    )
    parser.add_argument(
        "--include-timeouts", action="store_true",
        help=("Also retry VERIFICATION_TIMEOUT snippets. Separate from "
              "--include-errors on purpose: a timeout reproduces, so each retry "
              "costs a full --esbmc-timeout to reach the same verdict. Only worth "
              "it together with a different --esbmc-timeout or ESBMC flags."),
    )
    parser.add_argument(
        "--max-fix-attempts", type=int, default=DEFAULT_MAX_FIX_ATTEMPTS,
        help=f"compile_fix retry budget per snippet (default: {DEFAULT_MAX_FIX_ATTEMPTS}).",
    )
    parser.add_argument(
        "--retry-exhausted", action="store_true",
        help=("inject_fix: also re-queue originals that used up pairing.max_attempts, resetting their "
              "attempt count (for a new fix / inject prompt)."),
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report what each stage would do without compiling, verifying, or publishing.",
    )
    args = parser.parse_args(argv)

    requested = [s.strip() for s in args.stages.split(",") if s.strip()]
    unknown = set(requested) - set(STAGES)
    if unknown:
        parser.error(f"Unknown stage(s): {sorted(unknown)}. Valid: {list(STAGES)}")
    if not requested:
        parser.error("--stages must name at least one stage")
    # Preserve the canonical order regardless of how they were listed.
    args.stage_tuple = tuple(s for s in STAGES if s in requested)

    args.model_list = [m.strip() for m in args.models.split(",")] if args.models else None

    if args.workers is None:
        args.workers = default_workers()
    if args.workers < 1:
        parser.error("--workers must be >= 1")

    return args


if __name__ == "__main__":
    args = parse_args()
    log.info("Manual trigger of snippet resumer script.")
    resume_stuck_snippets(
        stages=args.stage_tuple,
        stuck_minutes=args.stuck_minutes,
        workers=args.workers,
        models=args.model_list,
        limit=args.limit,
        include_errors=args.include_errors,
        include_timeouts=args.include_timeouts,
        esbmc_timeout=args.esbmc_timeout,
        max_fix_attempts=args.max_fix_attempts,
        dry_run=args.dry_run,
        retry_exhausted=args.retry_exhausted,
    )
    log.info("Snippet resumer script finished its run.")
