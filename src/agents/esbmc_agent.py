import base64
import shutil
import uuid as uuid_lib
import tempfile
import tarfile
import io
import os
import re
import time
import docker
import shlex
from docker.errors import APIError, ImageNotFound, ContainerError
from typing import Dict, Tuple, Optional, List
from sqlalchemy.exc import OperationalError, TimeoutError as SATimeoutError

from ..queue.consumer import QueueConsumer
from ..queue.producer import QueueProducer
from ..db.database import DatabaseManager
from ..db.models import Status, Label, Reproduced
from ..utils.logger import logger
from ..utils.queue import Outcome, RetryableError, counterpart_queue, log_stranded, make_queue_name
from config.settings import settings
from ..utils.resource_manager import ResourceManager
from .compiler_agent import needs_install_step, normalise_install_command
from ..utils.docker_cleanup import container_labels, remove_own_containers
from ..utils.shutdown import install_shutdown_handler
from ..utils.provenance import violation_context
from ..utils.dynamic_confirm import (counterexample_hints, finalize, parse_runner_output, reproduction_fields,
                                     runner_args, summary, target_property, write_job)

# ---------------------------------------------------------------------------
# Verification primitives
#
# The flag list and the CWE mapping live in esbmc_verification so that the agent,
# scripts/resume_stuck_snippets.py and the tests all share one definition; see
# that module's docstring.  They are re-exported here because callers (notably
# resume_stuck_snippets) import them from this module.
# ---------------------------------------------------------------------------
from .esbmc_verification import (  # noqa: F401  (re-exported)
    VerificationResult,
    build_verification_command,
    build_verification_meta,
    code_hash,
    cwes_from_esbmc_annotation,
    esbmc_budget,
    extract_artifacts,
    extract_witness,
    infer_cwes_from_esbmc_log,
    pair_rejection_reason,
)


UNSUPPORTED_RE = re.compile(r"^Violated property:\n(?:.*\n)\s*Unsupported function '[^']*' is reached", re.M)


def get_verdict(logs: str, exit_code: int) -> Tuple[Status, Label]:
    """Map an ESBMC run's output and exit code onto a (Status, Label) verdict."""
    if 'VERIFICATION SUCCESSFUL' in logs and 'VERIFICATION FAILED' not in logs:
        return Status.VERIFICATION_SUCCESS, Label.SAFE
    elif 'VERIFICATION FAILED' in logs and UNSUPPORTED_RE.search(logs):
        # The Python front end reports reaching a library function it does not model
        # ("Unsupported function 'read' is reached") as a violated property: a limit of
        # the verifier, not a defect of the program.
        return Status.VERIFICATION_ERROR, Label.UNKNOWN
    elif 'VERIFICATION FAILED' in logs:
        return Status.VERIFICATION_SUCCESS, Label.VULNERABLE
    elif 'VERIFICATION UNKNOWN' in logs:
        return Status.VERIFICATION_SUCCESS, Label.UNKNOWN
    elif ("timeout" in logs or "Timeout" in logs or "TIMEOUT" in logs
          or re.search(r"^ERROR: Timed out", logs, re.M)):  # ESBMC's own --timeout message
        return Status.VERIFICATION_TIMEOUT, Label.UNKNOWN
    elif 'Aborted' in logs or 'core dumped' in logs or 'Segmentation fault' in logs:
        return Status.VERIFICATION_ERROR, Label.UNKNOWN
    elif 'ERROR:' in logs or exit_code != 0:
        return Status.VERIFICATION_ERROR, Label.UNKNOWN
    return Status.VERIFICATION_ERROR, Label.UNKNOWN


# Map of snippet language → the file extension ESBMC expects.
ESBMC_LANG_EXT = {"c": "c", "cpp": "cpp", "python": "py", "solidity": "sol", "kotlin": "kt", "cuda": "cu"}


class ESBMCAgent:
    def __init__(self, resource_manager: ResourceManager):
        self.log = logger.get_logger("esbmc_agent")
        self.log.info("Initializing ESBMC Agent")
        self.resource_manager = resource_manager

        try:
            # Pool size comes from config (database.pool_size); it must cover
            # esbmc_concurrency worker threads.
            self.db = DatabaseManager(caller="ESBMCAgent", db_url=settings.database['url'])
            self.producer = QueueProducer(
                caller="ESBMCAgent",
                host=settings.rabbitmq['host'],
                port=settings.rabbitmq['port']
            )

            self.verification_timeout = settings.esbmc.get('timeout', 300)
            self.esbmc_image = settings.esbmc.get('image', "esbmc:8.4")
            if not self.esbmc_image:
                raise ValueError("ESBMC Docker image ('image' under 'esbmc') not specified in settings")

            self.log.info(f"Using ESBMC Docker image: {self.esbmc_image}, timeout: {self.verification_timeout}s")

            try:
                self.docker_client = docker.from_env()
                self.docker_client.ping()
                self.log.info("Docker client initialized successfully.")
                self.esbmc_image_digest: Optional[str] = None
                try:
                    self.log.info(f"Checking Docker image: {self.esbmc_image}...")
                    self.esbmc_image_digest = self.docker_client.images.get(self.esbmc_image).id
                    self.log.info(f"Docker image {self.esbmc_image} is available ({self.esbmc_image_digest}).")
                except APIError as img_err:
                    self.log.warning(f"Could not find image locally {self.esbmc_image}. Please build it with given Dockerfile: {img_err}")
                except ImageNotFound:
                    self.log.warning(f"Docker image {self.esbmc_image} not found locally. Please build it.")


            except Exception as docker_err:
                self.log.error(f"Failed to initialize Docker client or connect to Docker daemon: {docker_err}", exc_info=True)
                raise ConnectionError(f"Docker connection failed: {docker_err}") from docker_err

        except Exception as e:
            self.log.error(f"Failed to initialize ESBMC Agent: {str(e)}", exc_info=True)
            raise

    def _cleanup_container(self, container):
        if not container:
            return
        container_id = container.id[:12]
        try:
            self.log.debug(f"Attempting to stop container {container_id}...")
            container.stop(timeout=10)
        except APIError as e:
            self.log.warning(f"Could not stop container {container_id}: {e}. Attempting force remove.")
        except Exception as e:
            self.log.warning(f"Error stopping container {container_id}: {e}. Attempting force remove.")
        try:
            self.log.debug(f"Attempting to remove container {container_id}...")
            container.remove(force=True)
            self.log.debug(f"Container {container_id} removed.")
        except APIError as e:
            if "removal of container" in str(e) and "already in progress" in str(e):
                self.log.debug(f"Container {container_id} removal already in progress — ignoring.")
            else:
                self.log.warning(f"Could not remove container {container_id}: {e}")
        except Exception as e:
            self.log.warning(f"Error removing container {container_id}: {e}")

    def _get_verdict(self, logs: str, exit_code: int) -> Tuple[Status, Label]:
        status, label = get_verdict(logs, exit_code)
        if status is Status.VERIFICATION_SUCCESS:
            self.log.info(f"Verification completed (via Docker) — label: {label.value}")
        else:
            self.log.warning(
                f"Verification did not produce a verdict: {status.value}. Exit code: {exit_code}"
            )
            self.log.debug(f"Full ESBMC Logs (Docker):\n{logs}")
        return status, label

    def _build_verification_command(self, language: str, source_path: str,
                                    container_timeout: Optional[int] = None) -> str:
        return build_verification_command(language, source_path, container_timeout=container_timeout)

    def _extract_witness(self, container) -> Optional[str]:
        return extract_witness(container)

    def _result(self, status, label, logs, witness=None, command="", started=None,
                artifacts=None) -> VerificationResult:
        meta = build_verification_meta(
            logs, command, self.esbmc_image, getattr(self, 'esbmc_image_digest', None),
            (time.monotonic() - started) if started is not None else None,
            'agent', artifacts)
        return VerificationResult(status, label, logs, witness, meta)

    def verify_code(self, code: str, language: str, install_command: Optional[str],
                    timeout: Optional[int] = None) -> VerificationResult:
        """Run ESBMC in a Docker container and return a VerificationResult.

        *timeout* overrides esbmc.timeout (seconds) for this run; ESBMC itself is given 10 s less.
        """
        timeout = int(timeout or self.verification_timeout)
        started = time.monotonic()
        language = language.lower().replace("c++", "cpp")
        file_ext = ESBMC_LANG_EXT.get(language)
        if not file_ext:
            self.log.error(f"Unsupported language: {language}")
            return self._result(Status.VERIFICATION_ERROR, Label.UNKNOWN,
                                f"Unsupported language: {language}", started=started)

        rm_cfg    = settings.resource_management
        mem_limit = rm_cfg.get('esbmc_mem_limit', '4096m')
        cpu_limit = rm_cfg.get('esbmc_cpu_limit', 0)
        nano_cpus = int(cpu_limit * 1e9) if cpu_limit > 0 else None

        self.log.info(f"Acquiring verification slot for ESBMC verification ({language})")
        with self.resource_manager.verification_slot():
            self.log.info(f"Verification slot acquired for ESBMC verification ({language})")
            temp_file_path = None
            container = None  # local — never shared between threads
            logs = ""
            exit_code = -1
            witness_xml: Optional[str] = None
            artifacts: Dict[str, Optional[str]] = {}
            verification_cmd = ""
            container_name = f"verivul-esbmc-{language}-{os.urandom(4).hex()}"

            try:
                self.log.info(f"Starting code verification in Docker for language: {language}")
                self.log.debug(f"Code length: {len(code)}")
                if install_command:
                    self.log.info(f"Will execute install command first: '{install_command}'")
                with tempfile.NamedTemporaryFile(suffix=f".{file_ext}", delete=False, mode='w', encoding='utf-8') as temp_file:
                    temp_file_path = temp_file.name
                    temp_file.write(code)
                    temp_file.flush()
                    os.fsync(temp_file.fileno())
                host_temp_file_path = os.path.abspath(temp_file_path)
                container_source_path = f"/work/source.{file_ext}"
                self.log.debug(f"Created temporary file on host: {host_temp_file_path}")
                self.log.debug(f"Will mount to container path: {container_source_path}")

                verify_lang = "kt" if language == "kotlin" else language
                verification_cmd = self._build_verification_command(verify_lang, container_source_path, timeout)
                # Skip placeholder install commands, and never let a failing
                # install stop ESBMC from running: ESBMC models libc itself, so a
                # missing package cannot invalidate the verdict, whereas `install
                # && esbmc` turned every PEP 668 refusal into a VERIFICATION_ERROR
                # with no verification attempted.
                full_command_str = (
                    f"{{ {normalise_install_command(install_command)} ; }} ; {verification_cmd}"
                    if needs_install_step(install_command) else verification_cmd
                )
                self.log.debug(f"Full command inside container (via sh -c): {full_command_str}")
                self.log.info(f"Verification command for {language}: {full_command_str}")
                container_command = ["sh", "-c", full_command_str]
                volumes = {host_temp_file_path: {'bind': container_source_path, 'mode': 'ro'}}
                try:
                    self.log.debug(f"Creating container {container_name} from image {self.esbmc_image}...")
                    container = self.docker_client.containers.create(
                        image=self.esbmc_image, command=container_command, volumes=volumes,
                        working_dir="/work", detach=True, name=container_name,
                        mem_limit=mem_limit,
                        # Labelled so a killed agent's containers can be found and
                        # removed instead of running forever.
                        labels=container_labels("esbmc"),
                        **({"nano_cpus": nano_cpus} if nano_cpus else {}),
                    )
                    self.log.debug(f"Starting container {container.id[:12]}...")
                    container.start()
                    self.log.debug(f"Waiting for container {container.id[:12]} completion (timeout: {timeout}s)...")
                    result = container.wait(timeout=timeout)
                    exit_code = result.get('StatusCode', -1)
                    self.log.debug(f"Container {container.id[:12]} finished with exit code: {exit_code}")
                    logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
                    artifacts = extract_artifacts(container)
                    witness_xml = artifacts.get('witness_graphml')
                except (ContainerError, APIError) as docker_run_err:
                    self.log.error(f"Docker container execution error: {docker_run_err}", exc_info=True)
                    try:
                        if container:
                            logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace') + \
                                f"\n[Docker Error] Container execution failed: {docker_run_err}"
                        else:
                            logs = f"[Docker Error] Container creation or execution failed early: {docker_run_err}"
                    except Exception as log_err:
                        logs = f"[Docker Error] Container execution failed: {docker_run_err}. Failed to retrieve logs: {log_err}"
                    return Status.VERIFICATION_ERROR, Label.UNKNOWN, logs, None
                except Exception as e:
                    container_id = container.id[:12] if container else "UNKNOWN"
                    self.log.warning(f"Container {container_id} timed out or failed after {timeout}s: {e}")
                    logs = f"[TIMEOUT] Docker SDK wait timed out after {timeout}s for container {container_id}.\n"
                    if container:
                        try:
                            partial_logs = container.logs(stdout=True, stderr=True, tail=50).decode('utf-8', errors='replace')
                            logs += "\nPartial logs before timeout:\n" + partial_logs
                        except Exception as log_err:
                            logs += f"[Error retrieving partial logs: {log_err}]"
                    return self._result(Status.VERIFICATION_TIMEOUT, Label.UNKNOWN, logs,
                                        command=verification_cmd, started=started)
                finally:
                    self._cleanup_container(container)
                    container = None
                self.log.debug(f"Container final exit code: {exit_code}")
                self.log.debug(f"Output preview: {logs[:500].replace(chr(10), '[LF]')}[...]. Full length: {len(logs)}")
                status, label = self._get_verdict(logs=logs, exit_code=exit_code)
                return self._result(status, label, logs, witness_xml, verification_cmd, started, artifacts)
            except KeyError as e:
                self.log.error(f"Unsupported language provided: {e}")
                return self._result(Status.VERIFICATION_ERROR, Label.UNKNOWN,
                                    f"Unsupported language: {e}", command=verification_cmd, started=started)
            except Exception as e:
                self.log.error(f"Verification setup or Docker interaction failed: {str(e)}", exc_info=True)
                return self._result(Status.VERIFICATION_ERROR, Label.UNKNOWN,
                                    f"Verification error: {str(e)}", command=verification_cmd, started=started)
            finally:
                if temp_file_path and os.path.exists(temp_file_path):
                    try:
                        os.unlink(temp_file_path)
                        self.log.debug(f"Removed host temporary file: {temp_file_path}")
                    except OSError as unlink_err:
                        self.log.error(f"Failed to remove host temporary file {temp_file_path}: {unlink_err}")
                if container:
                    self._cleanup_container(container)
                # verification_slot() context manager releases the slot here.


    def _run_sanitizer(self, code: str, language: str, label: str, esbmc_log: str, vmeta: Optional[Dict],
                       seeds: Optional[List[bytes]] = None, seed: int = 1, runs: Optional[int] = None) -> Dict:
        """Run the sanitizer search on a verified C/C++ program and return its confirmation record.

        Mirrors verify_code: a verification slot, a labelled throw-away container, the
        same memory limit, a source file in the system temp dir mounted read-only, and
        cleanup in a ``finally``.  Never raises: any problem is returned as a
        ``runner_error`` record, so the sanitizer cannot change or lose the ESBMC verdict.
        *seeds* (an LLM proof of concept, a parent's crashing input) are tried first;
        *runs* = len(seeds) replays only them.
        """
        cfg = settings.esbmc
        budget = float(cfg.get('confirm_budget', 40))
        ext = 'cpp' if language == 'cpp' else 'c'
        rm_cfg = settings.resource_management
        container = None
        td = None
        try:
            cat, fn, line = target_property(label, esbmc_log, vmeta)
            with self.resource_manager.verification_slot():
                td = tempfile.mkdtemp(prefix='verivul-san-')
                write_job(td, code, ext, counterexample_hints(esbmc_log, vmeta, seeds=seeds))
                os.chmod(td, 0o755)
                cpu_limit = rm_cfg.get('esbmc_cpu_limit', 0)
                container = self.docker_client.containers.create(
                    image=self.esbmc_image, command=runner_args(ext, seed, budget, runs=runs)[1:], entrypoint=['python3'],
                    volumes={td: {'bind': '/work', 'mode': 'ro'}}, working_dir='/work', detach=True,
                    name=f"verivul-san-{ext}-{os.urandom(4).hex()}", network_mode='none',
                    mem_limit=rm_cfg.get('esbmc_mem_limit', '4096m'),
                    labels=container_labels('esbmc'),
                    nano_cpus=int((cpu_limit if cpu_limit > 0 else 2) * 1e9),
                )
                container.start()
                container.wait(timeout=budget + 180)
                out = container.logs(stdout=True, stderr=False).decode('utf-8', errors='replace')
                run = parse_runner_output(out)
            return summary(finalize(run, label, cat, fn, line))
        except Exception as e:
            self.log.warning(f"Sanitizer run failed (verdict unaffected): {e}")
            return {'result': 'runner_error', 'error': str(e)[:400]}
        finally:
            self._cleanup_container(container)
            if td:
                shutil.rmtree(td, ignore_errors=True)

    @staticmethod
    def _sanitizer_language(snippet) -> Optional[str]:
        language = (snippet.language or '').lower().replace('c++', 'cpp')
        return language if language in ('c', 'cpp') else None

    def _confirm_and_store(self, snippet, label, status, esbmc_log: str, vmeta: Optional[Dict],
                           seeds: Optional[List[bytes]] = None, seed: int = 1) -> Optional[Dict]:
        """Sanitizer confirmation, stored in verification_meta['confirmation'] and, for a
        VULNERABLE label, in the reproduced / sanitizer_log / poc_input / sanitizer_cwes
        columns.  Returns the record, or None when it does not apply (disabled, not a
        definite verdict, not C/C++).  A runner_error leaves `reproduced` unset."""
        if not settings.esbmc.get('dynamic_confirm', True):
            return None
        if status is not Status.VERIFICATION_SUCCESS or label not in (Label.SAFE, Label.VULNERABLE):
            return None
        language = self._sanitizer_language(snippet)
        if not language:
            return None
        meta = dict(vmeta or {})
        conf = self._run_sanitizer(snippet.code, language, label.value, esbmc_log, vmeta, seeds=seeds, seed=seed)
        meta['confirmation'] = conf
        fields = {} if conf.get('result') == 'runner_error' else reproduction_fields(conf, label.value)
        self.db.update_snippet(uuid=snippet.uuid, metadata={'verification_meta': meta, **fields})
        self.log.info(f"Sanitizer for {snippet.uuid}: {conf.get('result')}")
        return conf

    @staticmethod
    def _needs_poc(conf: Optional[Dict], label) -> bool:
        """A VULNERABLE verdict the search ran on and could not crash."""
        return (label == Label.VULNERABLE and conf is not None and not conf.get('finding')
                and conf.get('result') not in ('runner_error', 'compile_error'))

    def _request_poc(self, snippet, round_: int, tried: List[str]) -> None:
        """Ask the generating model for a crashing input; the answer comes back as a replay_poc task."""
        self.db.update_snippet(uuid=snippet.uuid, metadata={'reproduced': Reproduced.PENDING.value})
        queue = make_queue_name("llm", snippet.generation_model)
        if not self.producer.publish_message(queue, {'uuid': snippet.uuid, 'task_type': 'reproduce_poc',
                                                     'round': round_, 'tried': tried[-9:]}):
            log_stranded(self.log, snippet.uuid, "reproduce", f"could not queue reproduce_poc on '{queue}'")

    def _parent_crash_persists(self, parent, child, esbmc_log: str, vmeta: Optional[Dict]) -> Optional[str]:
        """A fix must remove the crash that backs its parent's label: replay the parent's input."""
        if not (parent and parent.reproduced == Reproduced.REPRODUCED.value and parent.poc_input
                and settings.esbmc.get('dynamic_confirm', True) and self._sanitizer_language(child)):
            return None
        poc = base64.b64decode(parent.poc_input)
        conf = self._run_sanitizer(child.code, self._sanitizer_language(child), Label.SAFE.value, esbmc_log, vmeta,
                                   seeds=[poc], runs=1)
        f = conf.get('finding')
        return f"the parent's crashing input still crashes the fix ({f['kind']} at line {f.get('line')})" if f else None

    def _process_replay(self, message: Dict) -> str:
        """Replay an LLM proof of concept for a VULNERABLE snippet the search did not crash."""
        snippet = self.db.get_snippet(uuid=message['uuid'])
        if not snippet or snippet.label != Label.VULNERABLE.value or snippet.reproduced == Reproduced.REPRODUCED.value:
            return Outcome.ACK
        round_ = int(message.get('round', 1))
        tried = list(message.get('tried') or [])
        seeds = [base64.b64decode(x) for x in message.get('seeds') or []]
        conf = None
        if seeds:
            conf = self._confirm_and_store(snippet, Label.VULNERABLE, Status.VERIFICATION_SUCCESS, snippet.esbmc_log or '',
                                           snippet.verification_meta, seeds=seeds, seed=round_ + 1)
        if conf and conf.get('result') == 'runner_error':
            return Outcome.RETRY
        if conf and conf.get('finding'):
            self.log.info(f"Proof of concept reproduced {snippet.uuid} in round {round_}: {conf['finding'].get('kind')}")
            if not snippet.parent_uuid:
                self._advance(self.db.get_snippet(uuid=snippet.uuid), Label.VULNERABLE)
            return Outcome.ACK
        if round_ < int(settings.esbmc.get('poc_rounds', 2)):
            self._request_poc(snippet, round_ + 1, tried)
        else:
            self._give_up(snippet)
        return Outcome.ACK

    def _give_up(self, snippet) -> None:
        """No crash after every stage: the VULNERABLE label is not backed by a real failure."""
        self.db.update_snippet(uuid=snippet.uuid, metadata={'reproduced': Reproduced.NOT_REPRODUCED.value})
        if snippet.parent_uuid:
            parent = self.db.get_snippet(uuid=snippet.parent_uuid)
            self.db.delete_snippet(uuid=snippet.uuid)
            self.log.info(f"Removed injected snippet {snippet.uuid}: no sanitizer report on any input")
            if parent is not None:
                self._retry_pairing(parent, 'the injected defect could not be triggered on a real run',
                                    snippet.code, snippet.esbmc_log, snippet.verification_meta)
        else:
            self._regenerate(snippet)

    def _regenerate(self, snippet) -> None:
        """Generate a new program for the same seed, telling the model why the last one failed."""
        attempts = int(snippet.reproduce_attempts or 0)
        if attempts >= int(settings.esbmc.get('max_regenerations', 2)):
            self.log.info(f"{snippet.uuid}: not reproduced and {attempts} regeneration(s) used; leaving NOT_REPRODUCED")
            return
        seed = self.db.get_snippet(uuid=snippet.seed_uuid)
        if seed is None:
            return
        prop = ((snippet.verification_meta or {}).get('violated_properties') or [{}])[0]
        feedback = ("A previous program generated for this seed was rejected: the verifier reported "
                    f"\"{prop.get('description', 'a violation')}\" at line {prop.get('line')}, but no input read by the "
                    "program made it crash under AddressSanitizer/UndefinedBehaviorSanitizer. Write a program whose "
                    "defect is reached by a concrete input on stdin, with any format checks the input can pass.")
        msg = {'uuid': str(uuid_lib.uuid4()), 'task_type': 'generate', 'seed_uuid': seed.uuid,
               'generation_model': snippet.generation_model, 'code': seed.code, 'language': snippet.language,
               'project': seed.project or '', 'label': Label.UNKNOWN.value,
               'cwes': [c.id for c in snippet.cwes] if snippet.cwes else [],
               'commit_message': seed.commit_message or '', 'metrics': seed.metrics or {},
               'install_command': seed.install_command or '# No command found',
               'slice_context': seed.slice_code or '', 'feedback': feedback, 'reproduce_attempts': attempts + 1}
        queue = make_queue_name("llm", snippet.generation_model)
        if self.producer.publish_message(queue, msg):
            self.log.info(f"Regenerating seed {seed.uuid} after {snippet.uuid} was not reproduced (attempt {attempts + 1})")
        else:
            log_stranded(self.log, snippet.uuid, "regenerate", f"could not queue generate on '{queue}'")

    MAX_FIX_DEPTH = 2  # how many chained fix attempts are allowed per vulnerable snippet

    @staticmethod
    def _attempt_feedback(reason: str, child_code: Optional[str], child_log: Optional[str],
                          child_meta: Optional[Dict]) -> str:
        """What went wrong with a rejected fix / injection, for the model's next attempt."""
        parts = [f"Your previous attempt (shown below) was rejected: {reason}."]
        if child_code and child_log and 'VERIFICATION FAILED' in child_log:
            where = violation_context(child_code, child_log, child_meta)
            if where:
                parts.append("On that attempt the verifier reported:\n" + where)
        elif child_log is not None and 'unknown' in reason.lower():
            parts.append("The verifier could not finish on that attempt within its time budget. Keep the change as "
                         "small as possible: add a bound check or guard at the faulty spot rather than new loops, "
                         "helper functions or restructured control flow, which make the program harder to verify.")
        return '\n'.join(parts)

    def _retry_pairing(self, parent, reason: str, child_code: Optional[str] = None,
                       child_log: Optional[str] = None, child_meta: Optional[Dict] = None) -> None:
        """Re-queue the counterpart task for *parent* while pairing.max_attempts remain.  With the
        rejected child, the next attempt starts from it and is told what the verifier found, so a
        program with a second defect converges instead of restarting from the parent every time."""
        max_attempts = int(settings.pairing.get('max_attempts', 3))
        attempts = self.db.increment_pair_attempts(parent.uuid)
        if attempts >= max_attempts:
            self.log.info(f"Pairing for {parent.uuid} exhausted after {attempts} attempt(s); last reason: {reason}")
            return
        task_type = 'vulnerability_fix' if parent.label == Label.VULNERABLE.value else 'inject_vulnerability'
        llm_queue = counterpart_queue(task_type, parent.generation_model)
        msg = {
            'uuid': parent.uuid, 'seed_uuid': parent.seed_uuid,
            'generation_model': parent.generation_model, 'language': parent.language,
            'project': parent.project or '',
            'cwes': [cwe.id for cwe in parent.cwes] if parent.cwes else [],
            'commit_message': parent.commit_message or '',
            'install_command': parent.install_command or '',
            'task_type': task_type, 'pair_attempt': attempts + 1,
        }
        if child_code:
            msg['previous_code'] = child_code
            msg['feedback'] = self._attempt_feedback(reason, child_code, child_log, child_meta)
        if self.producer.publish_message(llm_queue, msg):
            self.log.info(f"Re-queued {task_type} for {parent.uuid} (attempt {attempts + 1}/{max_attempts}): {reason}")
        else:
            log_stranded(self.log, parent.uuid, "inject_fix", f"could not re-queue {task_type} on '{llm_queue}'")

    def _get_fix_depth(self, snippet_uuid: str) -> int:
        """Walk the parent_uuid chain to determine how many fix iterations have occurred."""
        depth = 0
        current_uuid = snippet_uuid
        for _ in range(self.MAX_FIX_DEPTH + 2):  # +2 as a safety bound
            snippet = self.db.get_snippet(uuid=current_uuid)
            if not snippet or not snippet.parent_uuid:
                break
            depth += 1
            current_uuid = snippet.parent_uuid
        return depth

    def _advance(self, snippet, label) -> None:
        """Queue the counterpart task for an original verified snippet: fix a VULNERABLE one,
        inject into a SAFE one."""
        if not settings.queues.get('auto_advance', True):
            self.log.info(
                f"auto_advance disabled — {snippet.uuid} left as {label.value} "
                f"for manual inject_fix stage"
            )
            return

        llm_queue = make_queue_name("llm", snippet.generation_model)
        base_msg = {
            'uuid': snippet.uuid,
            'seed_uuid': snippet.seed_uuid,
            'generation_model': snippet.generation_model,
            'language': snippet.language,
            'project': snippet.project or '',
            'cwes': [cwe.id for cwe in snippet.cwes] if snippet.cwes else [],
            'commit_message': snippet.commit_message or '',
            'install_command': snippet.install_command or '',
        }

        # VULNERABLE → send for vulnerability fix (creates a SAFE paired child)
        if label == Label.VULNERABLE:
            fix_depth = self._get_fix_depth(snippet.uuid)
            fix_queue = counterpart_queue('vulnerability_fix', snippet.generation_model)
            if fix_depth >= self.MAX_FIX_DEPTH:
                self.log.warning(
                    f"Max fix depth ({self.MAX_FIX_DEPTH}) reached for {snippet.uuid}. "
                    f"Leaving as VULNERABLE without further fix attempts."
                )
            elif self.producer.publish_message(fix_queue, {**base_msg, 'task_type': 'vulnerability_fix'}):
                self.log.info(
                    f"Published vulnerability_fix task for {snippet.uuid} → {fix_queue} "
                    f"(fix depth {fix_depth + 1}/{self.MAX_FIX_DEPTH})"
                )
            else:
                # The verdict is already stored; re-delivering this message
                # would repeat a full ESBMC run for nothing.
                log_stranded(self.log, snippet.uuid, "inject_fix",
                             f"could not queue the vulnerability_fix task on '{fix_queue}'")

        # SAFE original snippet → send for vulnerability injection (creates a VULNERABLE paired child)
        # Only inject into original snippets (no parent_uuid) to avoid infinite loops.
        elif label == Label.SAFE and not snippet.parent_uuid:
            if self.producer.publish_message(llm_queue, {**base_msg, 'task_type': 'inject_vulnerability'}):
                self.log.info(
                    f"Published inject_vulnerability task for {snippet.uuid} → {llm_queue}"
                )
            else:
                log_stranded(self.log, snippet.uuid, "inject_fix",
                             f"could not queue the inject_vulnerability task on '{llm_queue}'")


    def process_message(self, messages: List[Dict]) -> List[str]:
        """Verify each snippet in the batch, returning one Outcome per message.

        Per-message outcomes matter especially here: an ESBMC run costs up to
        `esbmc.timeout` seconds, so re-delivering a whole batch of 16 because one
        message hit a transient error used to throw away ~30 minutes of work.
        """
        return [self._process_one(message) for message in messages]

    def _process_one(self, message: Dict) -> str:
        snippet_uuid = message['uuid']
        if message.get('task') == 'replay_poc':
            try:
                return self._process_replay(message)
            except RetryableError as e:
                self.log.warning(f"Deferring replay for {snippet_uuid} — {e}")
                return Outcome.RETRY
            except (OperationalError, SATimeoutError, ConnectionError) as e:
                self.log.error(f"Transient infrastructure error replaying {snippet_uuid}: {e}")
                return Outcome.RETRY
            except Exception as e:
                self.log.error(f"Replay for {snippet_uuid} failed: {e}", exc_info=True)
                return Outcome.DROP
        self.log.info(f"Processing verification request for snippet: {snippet_uuid}")
        try:
            snippet = self.db.get_snippet(uuid=snippet_uuid)
            if not snippet:
                self.log.error(f"No snippet found with UUID: {snippet_uuid}")
                return Outcome.DROP

            # A redelivered message (broker restart, consumer reconnect, requeue) for a
            # snippet whose current code already has a verdict would cost a full ESBMC
            # run for the same answer, and republish its follow-up tasks.
            if (snippet.verified_code_hash and snippet.verified_code_hash == code_hash(snippet.code)
                    and snippet.status in (Status.VERIFICATION_SUCCESS.value, Status.VERIFICATION_ERROR.value,
                                           Status.VERIFICATION_TIMEOUT.value)):
                self.log.info(f"Snippet {snippet_uuid} already verified ({snippet.status}) for its current code; "
                              f"skipping duplicate delivery.")
                return Outcome.ACK

            # A fix must remove the crash that backs its parent's label.  Replaying the parent's
            # input takes seconds; a fix that still crashes is rejected before a long ESBMC run.
            if snippet.parent_uuid:
                parent = self.db.get_snippet(uuid=snippet.parent_uuid)
                reason = self._parent_crash_persists(parent, snippet, '', None) \
                    if parent is not None and parent.label == Label.VULNERABLE.value else None
                if reason:
                    self.db.delete_snippet(uuid=snippet_uuid)
                    self.log.info(f"Removed derived snippet {snippet_uuid} before verification: {reason}")
                    self._retry_pairing(parent, reason, snippet.code)
                    return Outcome.ACK

            verified_code = snippet.code
            # A fix/injection child has a parent that already verified within the normal budget,
            # and most rejected children were rejected for running out of it (no verdict), so
            # derived programs get a longer one.
            derived_timeout = settings.esbmc.get('derived_timeout') if snippet.parent_uuid else None
            status, label, esbmc_log, witness, vmeta = self.verify_code(
                code=verified_code,
                language=snippet.language,
                install_command=snippet.install_command,
                timeout=derived_timeout,
            )

            self.log.info(f"Verification completed for {snippet_uuid}. Status: {status.value}, Label: {label.value}")

            metadata = {'label': label.value, 'esbmc_log': esbmc_log, 'status': status.value,
                        'witness': witness, 'verification_meta': vmeta,
                        'verified_code_hash': code_hash(verified_code)}

            # CWE assignment rules:
            #  • `cwes` comes from our seed -> CWE mapping (the target CWE the snippet
            #    was generated for) and is never overwritten by the verifier.
            #  • `esbmc_cwes` records what ESBMC itself reports for a VULNERABLE verdict
            #    (its own annotation, else the regex rules); [] for any other label.
            #  • SAFE (fix-derived): clear the inherited `cwes` — a fixed snippet has none.
            if label == Label.VULNERABLE:
                inferred = infer_cwes_from_esbmc_log(esbmc_log)
                metadata['esbmc_cwes'] = inferred
                self.log.info(f"ESBMC CWEs for {snippet_uuid}: {inferred}")
            else:
                metadata['esbmc_cwes'] = []
                if label == Label.SAFE and snippet.parent_uuid:
                    metadata['cwes'] = None

            self.db.update_snippet(uuid=snippet_uuid, metadata=metadata)

            # Derived snippets (have a parent_uuid) must form a cross-label pair:
            # VULNERABLE→SAFE (fix) or SAFE→VULNERABLE (injection).
            # If the label is the same as the parent, or inconclusive (UNKNOWN),
            # delete the snippet — it is not a useful pair.
            if snippet.parent_uuid:
                parent = self.db.get_snippet(uuid=snippet.parent_uuid)
                reason = pair_rejection_reason(parent, label.value, verified_code, vmeta)
                if not reason:
                    conf = self._confirm_and_store(snippet, label, status, esbmc_log, vmeta)
                    if self._needs_poc(conf, label):  # an injection must crash like any VULNERABLE program
                        self._request_poc(snippet, 1, [])
                        return Outcome.ACK
                if reason:
                    self.db.delete_snippet(uuid=snippet_uuid)
                    self.log.info(f"Removed derived snippet {snippet_uuid}: {reason}")
                    if parent is not None:
                        self._retry_pairing(parent, reason, verified_code, esbmc_log, vmeta)
                # Valid or not, derived snippets never trigger a second-level fix/injection.
                return Outcome.ACK

            conf = self._confirm_and_store(snippet, label, status, esbmc_log, vmeta)
            if self._needs_poc(conf, label):
                # The fix task waits until a crash backs the label (or regeneration replaces it).
                self._request_poc(snippet, 1, [])
                return Outcome.ACK

            self._advance(snippet, label)
            return Outcome.ACK

        except RetryableError as e:
            # Back-pressure (no free verification slot).  Nothing was written and
            # the snippet is fine — put the message back on the queue.
            self.log.warning(f"Deferring {snippet_uuid} — {e}")
            return Outcome.RETRY
        except (OperationalError, SATimeoutError, ConnectionError) as e:
            # Transient infrastructure failure — re-queue without touching the DB.
            self.log.error(
                f"Transient infrastructure error processing {snippet_uuid} — "
                f"re-queuing message: {e}"
            )
            return Outcome.RETRY
        except Exception as e:
            self.log.error(f"Error processing message for {snippet_uuid}: {str(e)}", exc_info=True)
            try:
                self.db.update_snippet(uuid=snippet_uuid, metadata={'info': f"ESBMC Agent Error: {e}", 'status': Status.VERIFICATION_ERROR.value})
            except Exception as db_err:
                self.log.error(f"Failed to update DB status to VERIFICATION_ERROR for {snippet_uuid}: {db_err}")
            return Outcome.DROP

def start_esbmc_agent(model_name: str, resource_manager: ResourceManager):
    log = logger.get_logger(f"esbmc_{model_name}_agent_starter")
    log.info("Starting ESBMC Agent (Dockerized Verification)")

    consumer = None
    try:
        agent = ESBMCAgent(resource_manager)
        consumer = QueueConsumer(
            make_queue_name("esbmc", model_name),
            agent.process_message,
            host=settings.rabbitmq['host'],
            port=settings.rabbitmq['port'],
            batch_size=settings.queues.get('esbmc_batch_size', 1),
            batch_timeout=settings.queues.get('esbmc_batch_timeout', 1.0),
            max_workers=settings.queues.get('esbmc_concurrency', 4),
        )
        install_shutdown_handler(log, consumer, agent)

        log.info("Starting message consumption")
        consumer.start_consuming()

    except Exception as e:
        log.error(f"Failed to start ESBMC Agent: {str(e)}", exc_info=True)
        raise
    finally:
        if consumer:
            consumer.close()
        remove_own_containers(log)
