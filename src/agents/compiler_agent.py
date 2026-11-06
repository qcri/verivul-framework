import os
import re
import shutil
import tempfile
from typing import Dict, Tuple, Optional, List
import docker
from docker.errors import DockerException, ImageNotFound, APIError, ContainerError
from docker.types import Mount
from sqlalchemy.exc import OperationalError, TimeoutError as SATimeoutError

from ..queue.consumer import QueueConsumer
from ..queue.producer import QueueProducer
from ..db.database import DatabaseManager
from ..db.models import Status
from ..utils.logger import logger
from ..utils.queue import Outcome, RetryableError, log_stranded, make_queue_name
from config.settings import settings
from ..utils.program_guards import check_program
from ..utils.resource_manager import ResourceManager
from ..utils.docker_cleanup import container_labels, reclaim_trap, remove_own_containers
from ..utils.shutdown import install_shutdown_handler
from .esbmc_verification import FRONTEND_CHECK_LANGUAGES, build_frontend_check_command, frontend_failure_message

def normalise_language(language: str) -> str:
    """Return the canonical language key used for Docker images and compile scripts."""
    return language.lower().replace('/', '').replace('+', 'p')


# Shell statements that install nothing.  The LLM agent's fallback is
# "echo 'No install command provided'" and the workflow manager's is
# "# No command found", so most snippets carry a placeholder rather than a real
# command.
_NO_OP_COMMANDS = ("echo", "true", ":", "#")


def needs_install_step(install_command: Optional[str]) -> bool:
    """True only if *install_command* actually installs something.

    Worth being precise about: the compile script prefixes `apt update -y` before
    running the install command, which costs ~8 s of network round-trips.  Two
    thirds of snippets carry a placeholder like "echo 'No install command
    provided'", so treating any non-empty string as an install step made the
    common case 7x slower than it needed to be (9.1 s vs 1.2 s per compile).
    """
    if not install_command or not install_command.strip():
        return False
    # Split on statement separators; a command is a no-op only if *every*
    # statement is one (so "echo hi && apt-get install x" still installs).
    statements = re.split(r"&&|\|\||;|\n", install_command)
    for statement in statements:
        stripped = statement.strip()
        if not stripped:
            continue
        head = stripped.split()[0] if stripped.split() else stripped
        if not head.startswith(_NO_OP_COMMANDS):
            return True
    return False


_PIP_INVOCATION = re.compile(r"\b(pip3?|python3?\s+-m\s+pip)\s+install\b")


def normalise_install_command(install_command: Optional[str]) -> Optional[str]:
    """Make a generated install command work in the pipeline's images.

    ``pip install`` fails outright in the ESBMC image, which is Debian-based and
    ships a PEP 668 ``EXTERNALLY-MANAGED`` marker::

        error: externally-managed-environment
        × This environment is externally managed

    Because the verification command was ``install && esbmc …``, that refusal
    short-circuited the whole run and ESBMC never executed — 438 snippets were
    recorded as VERIFICATION_ERROR without a single verification actually being
    attempted.  ``--break-system-packages`` is the sanctioned override and is
    accepted by pip >= 23 (the ESBMC image ships 24.0).
    """
    if not install_command:
        return install_command
    if "--break-system-packages" in install_command:
        return install_command
    return _PIP_INVOCATION.sub(
        lambda m: f"{m.group(0)} --break-system-packages", install_command
    )


def install_step_script(install_command: Optional[str], apt_update: bool = True) -> str:
    """Return the shell lines that run the install step *without* being able to fail the run.

    An install command is a hint from the model, not a precondition: package names
    are frequently hallucinated (433 snippets carry apt's "Unable to locate
    package").  Under ``set -e`` a bad name aborted the script before the
    compiler ever ran, so the recorded failure described apt rather than the code.
    Letting the step fail soft means the compiler — or ESBMC — produces the real
    verdict, and a genuinely missing header still shows up as a compiler error.
    """
    if not needs_install_step(install_command):
        return ""
    command = normalise_install_command(install_command)
    prefix = "apt update -y && " if apt_update else ""
    return (
        f"if ! {{ {prefix}{command} ; }}; then\n"
        f"  echo 'WARNING: install step failed; continuing anyway' >&2\n"
        f"fi\n"
    )


def build_compile_script(language_norm: str) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(compile_script, source_filename)`` for a normalised language.

    Returns ``(None, None)`` when the language has no compilation implementation.

    Module-level (not a CompilerAgent method) so out-of-band tooling —
    scripts/resume_stuck_snippets.py in particular — compiles with *exactly* the
    same compiler flags as the agent.  A divergence here means a snippet can
    compile under one path and fail under the other.
    """
    if language_norm in ['c', 'cpp']:
        file_ext = '.cpp' if language_norm == 'cpp' else '.c'
        source_filename = f"source{file_ext}"
        # Common linker libs and standard pre-includes to cover the most frequent
        # missing-header failures (time.h, unistd.h, arpa/inet.h, etc.) that the
        # LLM generates without explicit #include directives.
        common_includes = (
            "-include stdio.h -include stdlib.h -include string.h "
            "-include unistd.h -include sys/types.h -include sys/socket.h "
            "-include arpa/inet.h -include netinet/in.h -include time.h "
            "-include errno.h -include fcntl.h -include signal.h "
            "-include stdint.h -include stdbool.h -include stdarg.h "
            "-include limits.h"
        )
        common_libs = "-lm -lpthread -lrt -ldl"
        if language_norm == 'cpp':
            compile_script = (
                f"g++ -std=c++17 -o /app/output /app/{source_filename} "
                f"{common_includes} {common_libs}"
            )
        else:
            compile_script = (
                f"gcc -std=gnu11 -o /app/output /app/{source_filename} "
                f"{common_includes} {common_libs}"
            )
        return compile_script, source_filename

    elif language_norm == 'kotlin':
        source_filename = "Main.kt"
        compile_script = "\n".join([
            # 1. Kotlin does not have 'new'; LLMs frequently emit Java-style throws.
            "sed -i 's/throw new /throw /g' /app/Main.kt",
            # 2. Inject common Java stdlib imports that LLMs routinely omit.
            #    The heredoc is quoted (PYEOF) so bash does no expansion inside.
            #    The script inserts the block right after the 'package' line (if
            #    present) or at the very top, so Kotlin's source order is respected.
            "python3 - << 'PYEOF'",
            "import re",
            "code = open('/app/Main.kt').read()",
            "IMPORTS = [",
            "    'import javax.xml.parsers.*',",
            "    'import javax.xml.transform.*',",
            "    'import javax.xml.transform.dom.*',",
            "    'import javax.xml.transform.stream.*',",
            "    'import org.xml.sax.*',",
            "    'import org.xml.sax.helpers.*',",
            "    'import java.io.*',",
            "    'import java.nio.file.*',",
            "    'import java.nio.channels.*',",
            "    'import java.util.*',",
            "    'import java.util.concurrent.*',",
            "    'import java.util.regex.*',",
            "    'import java.util.zip.*',",
            "    'import java.util.logging.*',",
            "    'import java.net.*',",
            "    'import java.math.*',",
            "    'import java.security.*',",
            "    'import java.text.*',",
            "    'import java.time.*',",
            "    'import java.time.format.*',",
            "]",
            "m = re.search(r'^package ', code, re.MULTILINE)",
            "pos = code.find('\\n', m.start()) + 1 if m else 0",
            "block = '\\n'.join(IMPORTS) + '\\n'",
            "open('/app/Main.kt', 'w').write(code[:pos] + block + code[pos:])",
            "PYEOF",
            # 3. Compile with JVM target 1.8 to allow static interface methods
            #    (e.g. Path.of()) and enable -include-runtime for the full stdlib.
            "kotlinc /app/Main.kt -include-runtime -jvm-target 1.8 -d /app/output.jar",
        ])
        return compile_script, source_filename

    elif language_norm == 'python':
        source_filename = "script.py"
        # Use ast.parse instead of py_compile: py_compile always writes
        # __pycache__ regardless of PYTHONDONTWRITEBYTECODE (that flag is
        # ignored by the py_compile module). The container runs as root, so
        # root-owned __pycache__ is left in the bind-mounted host temp dir,
        # causing PermissionError on cleanup. ast.parse checks syntax with
        # no file I/O at all.
        compile_script = (
            f"python -c \"import ast, sys; "
            f"code = open('/app/{source_filename}').read(); "
            f"ast.parse(code, filename='/app/{source_filename}')\""
        )
        return compile_script, source_filename

    elif language_norm == 'solidity':
        source_filename = "contract.sol"
        return f"solc --optimize --combined-json abi,bin /app/{source_filename}", source_filename

    elif language_norm == 'cuda':
        return "nvcc -o /app/output /app/source.cu", "source.cu"

    return None, None


class CompilerAgent:
    DEFAULT_TIMEOUT = 120
    # Longer timeout for snippets that need to download packages via apt/pip/etc.
    # before compilation.  Configurable via resource_management.compiler_install_timeout.
    DEFAULT_INSTALL_TIMEOUT = 300

    def __init__(self, resource_manager: ResourceManager):
        self.log = logger.get_logger("compiler_agent")
        self.log.info("Initializing CompilerAgent")
        self.resource_manager = resource_manager

        try:
            # Load Docker image names from config
            self.DOCKER_IMAGES = {}
            compiler_configs = settings.docker_images
            for lang, image_name in compiler_configs.items():
                normalized_lang = lang.lower().replace('/', '').replace('+', 'p')
                self.DOCKER_IMAGES[normalized_lang] = image_name

            self.log.info(f"Loaded Docker image configurations: {self.DOCKER_IMAGES}")

            # Define default images if not configured (optional, based on needs)
            if 'c' not in self.DOCKER_IMAGES: self.DOCKER_IMAGES['c'] = 'gcc:latest'
            if 'cpp' not in self.DOCKER_IMAGES: self.DOCKER_IMAGES['cpp'] = 'gcc:latest'
            if 'kotlin' not in self.DOCKER_IMAGES: self.DOCKER_IMAGES['kotlin'] = 'esbmc:8.4'
            if 'python' not in self.DOCKER_IMAGES: self.DOCKER_IMAGES['python'] = 'python:3.12-slim'
            if 'solidity' not in self.DOCKER_IMAGES: self.DOCKER_IMAGES['solidity'] = 'esbmc:8.4'
            if 'cuda' not in self.DOCKER_IMAGES: self.DOCKER_IMAGES['cuda'] = 'nvidia/cuda:12.3.2-devel-ubuntu22.04'

            # Pool size comes from config (database.pool_size); it must cover
            # compiler_concurrency worker threads.
            self.db = DatabaseManager(caller="CompilerAgent", db_url=settings.database['url'])
            self.producer = QueueProducer(
                caller="CompilerAgent",
                host=settings.rabbitmq['host'],
                port=settings.rabbitmq['port']
            )

            # Initialize Docker client
            try:
                self.docker_client = docker.from_env()
                self.docker_client.ping() # Test connection
                self.log.info("Docker client initialized and connected.")
            except DockerException as e:
                self.log.error(f"Failed to connect to Docker daemon: {str(e)}", exc_info=True)
                raise ConnectionError(f"Docker daemon connection failed: {str(e)}") from e

            self.log.info("CompilerAgent initialized successfully")

        except Exception as e:
            self.log.error(f"Failed to initialize CompilerAgent: {str(e)}", exc_info=True)
            raise

    def _compile_in_docker(
        self,
        language: str,
        code: str,
        install_command: Optional[str],
        compile_script: str,
        source_filename: str,
        timeout: int = DEFAULT_TIMEOUT
    ) -> Tuple[bool, Optional[str]]:
        # Validate image availability BEFORE consuming a slot.
        image_name = self.DOCKER_IMAGES.get(language)
        if not image_name:
            return False, f"No Docker image configured for language: {language}"

        rm_cfg   = settings.resource_management
        mem_limit = rm_cfg.get('compiler_mem_limit', '512m')
        cpu_limit = rm_cfg.get('compiler_cpu_limit', 0)
        nano_cpus = int(cpu_limit * 1e9) if cpu_limit > 0 else None

        self.log.info(f"Acquiring compilation slot for {language} compilation")
        with self.resource_manager.compilation_slot():
            self.log.info(f"Compilation slot acquired for {language} compilation")
            self.log.debug(f"Using Docker image: {image_name}")
            container_name = f"verivul-compiler-{language}-{os.urandom(4).hex()}"
            container = None

            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as host_temp_dir:
                try:
                    host_source_path = os.path.join(host_temp_dir, source_filename)
                    with open(host_source_path, 'w', encoding='utf-8') as f:
                        f.write(code)
                    self.log.debug(f"Source code written to host path: {host_source_path}")

                    container_script_path = "/app/run_compile.sh"
                    full_script = "#!/bin/bash\nset -eo pipefail\n"
                    # The container runs as root; hand /app back to the host user
                    # on exit so the temp dir can always be cleaned up.
                    full_script += reclaim_trap("/app") + "\n"

                    install_lines = install_step_script(install_command)
                    if install_lines:
                        self.log.info(f"Executing install command: '{install_command}'")
                        full_script += "echo '--- Running Installation ---'\n"
                        full_script += install_lines
                        full_script += "echo '--- Installation Complete ---'\n\n"
                    else:
                        self.log.info("No installation command provided.")

                    full_script += f"echo '--- Starting Compilation for /app/{source_filename} ---'\n"
                    full_script += compile_script + "\n"
                    full_script += "echo '--- Compilation Finished ---'\n"

                    host_script_path = os.path.join(host_temp_dir, "run_compile.sh")
                    with open(host_script_path, 'w', encoding='utf-8') as f:
                        f.write(full_script)
                    os.chmod(host_script_path, 0o755)
                    self.log.debug(f"Execution script written to host path: {host_script_path}")
                    self.log.debug(f"Script content:\n{full_script}")

                    self.log.info(f"Running container {container_name} from image {image_name}")
                    try:
                        self.docker_client.images.get(image_name)
                    except ImageNotFound:
                        self.log.info(f"Image {image_name} not found locally, pulling...")
                        self.docker_client.images.pull(image_name)
                        self.log.info(f"Image {image_name} pulled.")
                    except APIError as img_err:
                        self.log.error(f"Docker API error checking/pulling image {image_name}: {img_err}", exc_info=True)
                        return False, f"Docker API error with image {image_name}: {img_err}"

                    mount = Mount(target="/app", source=host_temp_dir, type="bind", read_only=False)
                    container = self.docker_client.containers.run(
                        image=image_name,
                        command=["/bin/bash", container_script_path],
                        mounts=[mount],
                        working_dir="/app",
                        stderr=True,
                        stdout=True,
                        detach=True,
                        name=container_name,
                        mem_limit=mem_limit,
                        # Labelled so a killed agent's containers can be found and
                        # removed instead of running forever.
                        labels=container_labels("compiler"),
                        **({"nano_cpus": nano_cpus} if nano_cpus else {}),
                    )
                    result = container.wait(timeout=timeout)
                    exit_code = result.get("StatusCode", -1)
                    success = exit_code == 0
                    self.log.info(f"Container {container_name} finished with exit code: {exit_code}")
                    logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
                    self.log.debug(f"Container logs (length {len(logs)}):\n{logs[:1000]}...")
                    return success, logs
                except ContainerError as e:
                    logs = e.stderr.decode('utf-8', errors='replace') if e.stderr else "Unknown container error"
                    self.log.error(f"Container execution error: {logs}", exc_info=True)
                    return False, f"Container execution failed:\n{logs}"
                except APIError as e:
                    self.log.error(f"Docker API error during container run: {str(e)}", exc_info=True)
                    return False, f"Docker API error: {str(e)}"
                except Exception as e:
                    # Catches ReadTimeout from container.wait() and any other unexpected errors
                    self.log.error(f"Container {container_name} failed or timed out after {timeout}s: {e}")
                    logs = f"Compilation failed or timed out after {timeout}s for container {container_name}.\n"
                    if container:
                        try:
                            partial_logs = container.logs(stdout=True, stderr=True, tail=50).decode('utf-8', errors='replace')
                            logs += "\nPartial logs:\n" + partial_logs
                        except Exception as log_err:
                            logs += f"[Error retrieving partial logs: {log_err}]"
                    return False, logs
                finally:
                    if container:
                        try:
                            container.remove(force=True)
                            self.log.debug(f"Container {container_name} removed.")
                        except APIError as e:
                            self.log.warning(f"Could not remove container {container_name}: {str(e)}")
            # compilation_slot() context manager releases the slot here.


    FRONTEND_CHECK_TIMEOUT = 120

    def _esbmc_frontend_check(self, language_norm: str, code: str) -> Tuple[bool, Optional[str]]:
        """Run ESBMC's front end over a program the regular compiler accepted.

        Returns (False, message) only when ESBMC itself reported an error; a Docker or
        timeout problem returns (True, None) so an infrastructure hiccup never marks a
        good program as failed.
        """
        ext = {'c': 'c', 'cpp': 'cpp', 'python': 'py'}[language_norm]
        command = build_frontend_check_command(language_norm, f"/work/source.{ext}")
        image = settings.esbmc.get('image', 'esbmc:8.4')
        container = None
        td = None
        try:
            with self.resource_manager.compilation_slot():
                td = tempfile.mkdtemp(prefix='verivul-fe-')
                os.chmod(td, 0o755)
                with open(os.path.join(td, f"source.{ext}"), 'w', encoding='utf-8') as f:
                    f.write(code)
                container = self.docker_client.containers.create(
                    image=image, entrypoint=['bash', '-c'], command=[command],
                    volumes={td: {'bind': '/work', 'mode': 'ro'}}, working_dir='/work', detach=True,
                    name=f"verivul-fecheck-{language_norm}-{os.urandom(4).hex()}",
                    network_mode='none', mem_limit='2g', nano_cpus=int(1e9),
                    labels=container_labels("compiler"),
                )
                container.start()
                exit_code = container.wait(timeout=self.FRONTEND_CHECK_TIMEOUT).get("StatusCode", -1)
                logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
            if exit_code == 0:
                return True, None
            message = frontend_failure_message(logs)
            if message is None:
                self.log.warning(f"ESBMC front-end check exited {exit_code} without an error message; ignoring.")
                return True, None
            return False, message
        except Exception as e:
            self.log.warning(f"ESBMC front-end check could not run ({e}); skipping it.")
            return True, None
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            if td:
                shutil.rmtree(td, ignore_errors=True)

    def compile_code(self, code: str, language: str, install_command: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        self.log.info(f"Received compilation request for language: {language}")
        self.log.debug(f"Code length: {len(code)}")
        if install_command:
            self.log.info(f"Install command provided: {install_command}")

        language_norm = normalise_language(language)

        try:
            compile_script, source_filename = build_compile_script(language_norm)
            if not compile_script:
                self.log.error(f"No compilation implementation for language: {language} (normalized: {language_norm})")
                return False, f"No compiler implementation for language: {language}"

            # Use a longer timeout when the snippet needs to install packages
            # first (apt/pip downloads can easily exceed the default 120 s).
            if needs_install_step(install_command):
                timeout = settings.resource_management.get(
                    'compiler_install_timeout', self.DEFAULT_INSTALL_TIMEOUT
                )
            else:
                timeout = self.DEFAULT_TIMEOUT

            success, logs = self._compile_in_docker(
                language=language_norm,
                code=code,
                install_command=install_command,
                compile_script=compile_script,
                source_filename=source_filename,
                timeout=timeout,
            )
            if (success and language_norm in FRONTEND_CHECK_LANGUAGES
                    and settings.esbmc.get('frontend_check', True)):
                ok, message = self._esbmc_frontend_check(language_norm, code)
                if not ok:
                    return False, message
            return success, logs
        except Exception as e:
            error_msg = f"Error preparing compilation for {language}: {str(e)}"
            self.log.error(error_msg, exc_info=True)
            return False, error_msg

    def _send_to_llm_for_fix(self, uuid: str, max_retries=3):
        try:
            snippet = self.db.get_snippet(uuid=uuid)
            if not snippet:
                self.log.error(f"No snippet found with UUID: {uuid}")
                return False

            if snippet.attempt_count >= max_retries:
                self.log.warning(f"Reached maximum compilation fix attempts ({max_retries}) for {uuid}. Not sending for fix.")
                return False

            model_identifier = snippet.generation_model
            if not model_identifier:
                self.log.error(f"Cannot send to LLM for fix: generation_model is missing for snippet {uuid}")
                return False

            new_attempt_count = snippet.attempt_count + 1
            self.db.update_snippet(uuid=uuid, metadata={"attempt_count": new_attempt_count, "status": Status.COMPILATION_FAILED.value})
            self.log.info(f"Incremented attempt count for {uuid} to {new_attempt_count}")

            queue_name = make_queue_name("llm", model_identifier)
            self.log.info(f"Publishing to {queue_name} queue for compilation fix: {uuid} (Attempt {new_attempt_count}/{max_retries})")
            message_payload = {
                'uuid': uuid,
                'task_type': 'compilation_fix',
                'attempt_count': new_attempt_count
            }

            if not self.producer.publish_message(queue_name, message_payload):
                log_stranded(self.log, uuid, "compile_fix",
                             f"could not queue the compilation_fix task on '{queue_name}'")
                return False
            return True

        except Exception as e:
            self.log.error(f"Failed to send to LLM for fixing {uuid}: {str(e)}", exc_info=True)
            return False

    def process_message(self, messages: List[Dict]) -> List[str]:
        """Compile each snippet in the batch, returning one Outcome per message.

        Per-message outcomes matter here: with `compiler_batch_size` of 16 a
        single transient failure used to re-deliver the whole batch, re-running
        fifteen compilations that had already succeeded.
        """
        return [self._process_one(message) for message in messages]

    def _process_one(self, message: Dict) -> str:
        snippet_uuid = message['uuid']
        self.log.info(f"Processing compilation request for snippet: {snippet_uuid}")

        try:
            snippet = self.db.get_snippet(uuid=snippet_uuid)
            if not snippet:
                self.log.error(f"No snippet found with UUID: {snippet_uuid}")
                return Outcome.DROP

            reasons = check_program(snippet.code, snippet.language, settings.guards)
            if reasons:
                self.db.update_snippet(uuid=snippet_uuid, metadata={
                    'status': Status.GENERATION_FAILED.value,
                    'info': 'rejected by guards: ' + '; '.join(reasons)})
                self.log.info(f"Rejected {snippet_uuid} before compilation: {reasons}")
                return Outcome.ACK

            success, compilation_log = self.compile_code(
                code=snippet.code,
                language=snippet.language,
                install_command=snippet.install_command
            )

            metadata = {
                'compilation_log': compilation_log,
            }

            if success:
                metadata['status'] = Status.COMPILATION_SUCCESS.value
                self.log.info(f"Compilation successful for {snippet_uuid}")
                self.db.update_snippet(uuid=snippet_uuid, metadata=metadata)

                if settings.queues.get('auto_advance', True):
                    esbmc_queue_name = make_queue_name("esbmc", snippet.generation_model)
                    self.log.info(f"Publishing to ESBMC queue '{esbmc_queue_name}': {snippet_uuid}")
                    # The status is already committed, so re-delivering this
                    # message would recompile a snippet that compiled fine.  Record
                    # the strand instead and let the resume path pick it up.
                    if not self.producer.publish_message(esbmc_queue_name, {'uuid': snippet_uuid}):
                        log_stranded(self.log, snippet_uuid, "verify",
                                     f"could not queue the ESBMC task on '{esbmc_queue_name}'")
                else:
                    self.log.info(f"auto_advance disabled — {snippet_uuid} left as COMPILATION_SUCCESS for manual verify stage")
            else:
                metadata['status'] = Status.COMPILATION_FAILED.value
                self.log.warning(f"Compilation failed for {snippet_uuid}")
                self.db.update_snippet(uuid=snippet_uuid, metadata=metadata)
                if settings.queues.get('auto_advance', True):
                    self._send_to_llm_for_fix(uuid=snippet_uuid)
                else:
                    self.log.info(f"auto_advance disabled — {snippet_uuid} left as COMPILATION_FAILED for manual compile_fix stage")

            return Outcome.ACK

        except RetryableError as e:
            # Back-pressure (no free compilation slot).  Nothing was written and
            # nothing is wrong with the snippet — put the message back.
            self.log.warning(f"Deferring {snippet_uuid} — {e}")
            return Outcome.RETRY
        except (OperationalError, SATimeoutError, ConnectionError) as e:
            # Transient infrastructure failure (DB pool exhausted, Docker socket
            # unreachable, …).  Do NOT write anything to the DB — we may not have
            # a connection — and re-queue the message for a later attempt.
            self.log.error(
                f"Transient infrastructure error processing {snippet_uuid} — "
                f"re-queuing message: {e}"
            )
            return Outcome.RETRY
        except Exception as e:
            self.log.error(f"Error processing message for {snippet_uuid}: {str(e)}", exc_info=True)
            try:
                self.db.update_snippet(
                    uuid=snippet_uuid,
                    metadata={'info': f"Compiler Agent Error: {str(e)}", 'status': Status.COMPILATION_FAILED.value}
                )
            except Exception as db_err:
                self.log.error(f"Failed to update status to COMPILATION_FAILED for {snippet_uuid} after processing error: {db_err}")
            return Outcome.DROP

def start_compiler_agent(model_name: str, resource_manager: ResourceManager):
    log = logger.get_logger(f"compiler_{model_name}_agent_starter")
    log.info(f"Starting CompilerAgent for model: {model_name}")

    consumer = None
    try:
        agent = CompilerAgent(resource_manager)
        consumer = QueueConsumer(
            make_queue_name("compiler", model_name),
            agent.process_message,
            host=settings.rabbitmq['host'],
            port=settings.rabbitmq['port'],
            batch_size=settings.queues.get('compiler_batch_size', 1),
            batch_timeout=settings.queues.get('compiler_batch_timeout', 1.0),
            max_workers=settings.queues.get('compiler_concurrency', 4),
        )
        install_shutdown_handler(log, consumer, agent)

        log.info("Starting message consumption")
        consumer.start_consuming()

    except Exception as e:
        log.error(f"Failed to start CompilerAgent: {str(e)}", exc_info=True)
        raise
    finally:
        if consumer:
            consumer.close()
        remove_own_containers(log)
