from typing import Optional, Dict, Any, Tuple, List
from pathlib import Path
import openai
import base64
import re
import uuid
import asyncio
import threading
from azure.ai.inference.aio import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential
from ..queue.consumer import QueueConsumer
from ..queue.producer import QueueProducer
from ..db.database import DatabaseManager
from ..db.models import Status, CodeSnippet, Label, Type
from ..utils.logger import logger
from ..utils.queue import Outcome, RetryableError, counterpart_queue, log_stranded, make_queue_name
from ..utils.shutdown import install_shutdown_handler
from ..utils.program_guards import FILE_INPUT_RE, check_program
from ..utils.provenance import violation_context
from ..utils.poc import build_prompt as build_poc_prompt, describe as describe_input, parse_candidates
from ..agents.esbmc_verification import code_hash
from config.settings import settings
from sqlalchemy.exc import OperationalError, TimeoutError as SATimeoutError

def guards_for(parent: Optional[CodeSnippet]) -> Dict[str, Any]:
    """Guard settings for a program derived from *parent*: a fix or injection keeps its
    parent's input model, so a parent that already reads a file does not get its
    counterpart rejected for doing the same."""
    cfg = dict(settings.guards or {})
    if parent is not None and FILE_INPUT_RE.search(parent.code or ''):
        cfg['reject_non_stdin_input'] = False
    return cfg


class LLMAgent:
    def __init__(self, model_key: str):
        self.log = logger.get_logger(f"llm_agent_{model_key}")
        self.log.info(f"Initializing LLM Agent for model: {model_key}")
        
        try:
            self._load_prompts()
            if model_key not in settings.models:
                raise ValueError(f"Model key '{model_key}' not found in settings.")

            model_config = settings.models[model_key]
            self.model_provider = model_config['provider']
            self.model_name = model_config['model_name']
            self.model_key = model_key
            client_params = model_config['client_config']

            self.log.info(f"Model config loaded: Provider='{self.model_provider}', ModelName='{self.model_name}'")

            # Each agent runs llm_batch_size x llm_concurrency requests at once (256 with the
            # defaults).  A model server with a smaller KV cache queues the excess, answers
            # everything slowly and times requests out, so it can be capped per model.  A
            # threading semaphore because batches run on different threads/event loops.
            max_requests = int(model_config.get('max_concurrent_requests') or 0)
            self._request_slots = threading.BoundedSemaphore(max_requests) if max_requests > 0 else None
            if self._request_slots:
                self.log.info(f"Capping in-flight requests to {self.model_key} at {max_requests}")

            # Initialize the appropriate async client
            if self.model_provider in ['vllm', 'openai', 'deepseek']:
                if not client_params.get('api_key') or not client_params.get('base_url'):
                     raise ValueError(f"Missing api_key or base_url for model '{model_key}'")
                self.client = openai.AsyncOpenAI(**client_params)
            
            elif self.model_provider == "azureinference":
                if not client_params.get('endpoint') or not client_params.get('api_key'):
                     raise ValueError(f"Missing endpoint or api_key for model '{model_key}'")
                credential = AzureKeyCredential(client_params['api_key'])
                self.client = ChatCompletionsClient(endpoint=client_params['endpoint'], credential=credential)
                
            elif self.model_provider == "azureopenai":
                 if not all(k in client_params for k in ['api_key', 'api_version', 'azure_endpoint', 'azure_deployment']):
                     raise ValueError(f"Missing one or more required Azure OpenAI parameters for model '{model_key}'")
                 self.client = openai.AsyncAzureOpenAI(**client_params)
            
            else:
                raise ValueError(f"Unsupported provider: {self.model_provider}")

            # Pool size comes from config (database.pool_size).  It has to cover
            # llm_concurrency worker threads: DB calls are individually brief, but
            # they are synchronous, so every thread that reaches one needs a
            # connection at that moment or it waits out pool_timeout and the task
            # fails for a reason that has nothing to do with the snippet.
            self.db = DatabaseManager(caller="LLMAgent", db_url=settings.database['url'])
            self.producer = QueueProducer(caller="LLMAgent", host=settings.rabbitmq['host'], port=settings.rabbitmq['port'])
            
            self.log.info(f"LLM Agent for '{model_key}' initialized successfully.")
            
        except (KeyError, ValueError) as e:
             self.log.error(f"Failed to initialize LLM Agent due to configuration error: {e}", exc_info=True)
             raise
        except Exception as e:
            self.log.error(f"An unexpected error occurred during LLM Agent initialization for '{model_key}': {e}", exc_info=True)
            raise

    def _load_prompts(self):
        try:
            assets_dir = Path("assets")
            with open(assets_dir / "generation_system_prompt.txt") as f: self.generation_system_prompt = f.read()
            with open(assets_dir / "fix_vulnerability_system_prompt.txt") as f: self.fixing_system_prompt = f.read()
            with open(assets_dir / "generation_user_prompt.txt") as f: self.generation_user_prompt = f.read()
            with open(assets_dir / "fix_vulnerability_user_prompt.txt") as f: self.fixing_user_prompt = f.read()
            with open(assets_dir / "compilation_system_prompt.txt") as f: self.compilation_system_prompt = f.read()
            with open(assets_dir / "compilation_user_prompt.txt") as f: self.compilation_user_prompt = f.read()
            with open(assets_dir / "inject_vulnerability_system_prompt.txt") as f: self.inject_vulnerability_system_prompt = f.read()
            with open(assets_dir / "inject_vulnerability_user_prompt.txt") as f: self.inject_vulnerability_user_prompt = f.read()
            with open(assets_dir / "poc_user_prompt.txt") as f: self.poc_user_prompt = f.read()
            self.log.info("Successfully loaded all prompts")
        except Exception as e:
            self.log.error(f"Failed to load prompts: {e}", exc_info=True)
            raise

    def _format_context(self, message: dict) -> str:
        cwes = message.get('cwes')
        target = ', '.join(cwes) if isinstance(cwes, list) else str(cwes or '')
        line = f"- CWE Category: {target}"
        if message.get('target_cwe_source') == 'assigned' and message.get('seed_cwes'):
            line += f" (the seed is declared as {', '.join(message['seed_cwes'])}; reproduce {target})"
        return (f"- Project: {message['project']}\n"
                f"{line}\n"
                f"- Associated Commit Message (if any): {message['commit_message']}\n"
                f"- Target Language: {message['language']}")

    def _format_metrics(self, metrics: dict) -> str:
        return (f"Target Metrics:\n"
                f"- Program Length: {metrics['loc']} lines\n"
                f"- Cyclomatic Complexity: {metrics['cc']}\n"
                f"- Maximum Nesting Depth: {metrics['nd']}")

    def _format_code(self, code: str):
        if "<snippet>" in code:
            code = code.split("<snippet>")[-1].replace("</snippet>", "")
        lines = code.split('\n')
        if '`' in lines[0]:
            code = '\n'.join(lines[1:])
        return code.replace("```", "").strip()

    def _format_install_command(self, install_command: str):
        default = "echo 'No install command provided'"
        if "<install_command>" in install_command:
            cmd = install_command.split("<install_command>")[-1].replace("</install_command>", "")
        else:
            cmd = install_command

        cmd = cmd.replace("```sh", "").replace("```bash", "").replace("```", "").replace("sudo", "").strip()

        if not cmd or len(cmd) < 5 or cmd.startswith("["):
            return default
        # Accept any recognisable package-manager or no-op echo command
        VALID_MANAGERS = ("apt", "pip", "pip3", "npm", "gem", "cargo", "go ", "wget", "curl", "echo")
        if not any(mgr in cmd for mgr in VALID_MANAGERS):
            return default
        # Reject compile-step commands that sneak in
        if "gcc " in cmd or "g++ " in cmd or "make " in cmd:
            return default
        return cmd

    def _parse_response(self, response: str) -> Tuple[str, str]:
        # Strip chain-of-thought blocks produced by thinking models (e.g. Qwen3,
        # DeepSeek-R1). The content inside <think>…</think> is internal reasoning
        # and must never be compiled or stored as generated code.
        response = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL).strip()

        snippet_match = re.search(r"<snippet>(.*?)</snippet>", response, re.DOTALL)
        install_command_match = re.search(r"<install_command>(.*?)</install_command>", response, re.DOTALL)

        snippet = snippet_match.group(1).strip() if snippet_match else ""
        install_command = install_command_match.group(1).strip() if install_command_match else ""

        if not snippet:
            self.log.warning("No <snippet> tag found in LLM response after stripping think blocks; treating as refusal.")

        return snippet, install_command

    # Seconds a task waits before being handed back to the queue after the model server
    # failed it.  RETRY re-delivers immediately, so without this a server that is down
    # (restarting, overloaded) would see every queued task cycle through at full speed.
    TRANSIENT_BACKOFF_SECONDS = 15

    async def _defer_transient(self, error: Exception, uuid_: str) -> None:
        """A model-server failure (connection refused/reset, timeout, 5xx, rate limit) says
        nothing about the task, so re-queue it instead of dropping it as "no code generated"."""
        self.log.warning(f"Model server unavailable for {uuid_} ({type(error).__name__}: {error}); "
                         f"re-queuing after {self.TRANSIENT_BACKOFF_SECONDS}s.")
        await asyncio.sleep(self.TRANSIENT_BACKOFF_SECONDS)
        raise RetryableError(f"model server unavailable: {error}") from error

    async def _call_llm_api(self, messages: List[Dict[str, str]]) -> Any:
        model_config = settings.models[self.model_key]
        max_tokens = model_config.get('max_tokens') or settings.sampling_params['max_tokens']
        # Small-context models (e.g. an 8B served with a 16k window) reject a request when
        # prompt + max_tokens exceeds the window, so the completion budget is whatever
        # the prompt leaves.  Prompt size is over-estimated (2.5 chars/token) to stay safe.
        context_length = model_config.get('context_length')
        if context_length:
            prompt_tokens = int(sum(len(m['content']) for m in messages) / 2.5)
            room = int(context_length) - prompt_tokens - 256
            if room < 1024:
                self.log.warning(f"Prompt (~{prompt_tokens} tokens) leaves only {room} tokens in the "
                                 f"{context_length}-token window of {self.model_key}; skipping the call.")
                return None
            max_tokens = min(max_tokens, room)
        common_params = {
            "model": self.model_name,
            "messages": messages,
            "temperature": settings.sampling_params['temperature'],
            "max_tokens": max_tokens,
            "top_p": settings.sampling_params['top_p'],
        }
        # Wait for a slot before the request starts, so the wait is not counted against the
        # client's request timeout.
        if self._request_slots:
            await asyncio.to_thread(self._request_slots.acquire)
        try:
            if self.model_provider in ['vllm', 'azureopenai', 'openai', 'deepseek']:
                extra_body = model_config.get('extra_body')
                if extra_body and self.model_provider in ('vllm', 'openai', 'deepseek'):
                    return await self.client.chat.completions.create(**common_params, extra_body=extra_body)
                return await self.client.chat.completions.create(**common_params)
            elif self.model_provider == "azureinference":
                return await self.client.complete(**common_params)
            else:
                self.log.error(f"Unsupported provider '{self.model_provider}' for API call.")
                return None
        finally:
            if self._request_slots:
                self._request_slots.release()

    async def generate_code(self, message: dict) -> Tuple[str, str]:
        metrics_section = f"\n\n# Target Metrics:\n{self._format_metrics(message['metrics'])}" if message.get('metrics') else ""
        slice_section = f"\n\n# Slice Context (extracted from a real vulnerability — use as structural inspiration):\n{message['slice_context']}" if message.get('slice_context') else ""
        feedback_section = f"\n\n# Feedback on an earlier attempt:\n{message['feedback']}" if message.get('feedback') else ""
        formatted_user_prompt = (f"# Instruction:\n{self.generation_user_prompt}\n\n"
                                 f"# Context:\n{self._format_context(message)}"
                                 f"{metrics_section}"
                                 f"{slice_section}"
                                 f"{feedback_section}\n\n"
                                 f"# Target Code:\n```\n{message['code']}\n```")
        messages = [{"role": "user", "content": self.generation_system_prompt + "\n\n" + formatted_user_prompt}]
        
        try:
            response = await self._call_llm_api(messages)
            if response and response.choices:
                return self._parse_response(response.choices[0].message.content)
        except (openai.APIConnectionError, openai.APITimeoutError, openai.InternalServerError, openai.RateLimitError) as e:
            await self._defer_transient(e, message['uuid'])
        except Exception as e:
            self.log.error(f"Code generation API call failed for {message['uuid']}: {e}", exc_info=True)
        return "", ""

    @staticmethod
    def _attempt_section(message: Optional[Dict[str, Any]]) -> str:
        """The rejected previous attempt and why, when this is a retry."""
        if not message or not message.get('feedback'):
            return ""
        prev = message.get('previous_code')
        return (f"# Previous attempt:\n{message['feedback']}\n\n"
                + (f"```\n{prev}\n```\n\nStart from the original program above and make the change that "
                   f"avoids this outcome.\n\n" if prev else ""))

    @staticmethod
    def _crash_section(snippet: CodeSnippet) -> str:
        """The sanitizer report and input that make the program fail on a real run."""
        if snippet.reproduced != 'REPRODUCED' or not snippet.sanitizer_log:
            return ""
        report = snippet.sanitizer_log
        if len(report) > 4000:
            report = report[:4000] + "\n..."
        try:
            shown = describe_input(base64.b64decode(snippet.poc_input or ''), 300)
        except ValueError:
            shown = ""
        return ("# Crash on a real run (AddressSanitizer / UndefinedBehaviorSanitizer):\n"
                + (f"Input that triggers it: {shown}\n" if shown else "")
                + f"```\n{report}\n```\nThe fixed program must not fail on this input or on any other.\n\n")

    async def fix_vuln_code(self, snippet: CodeSnippet, message: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
        esbmc_log = (snippet.esbmc_log or "").split("property:")[-1].strip()
        try:
            where = violation_context(snippet.code, snippet.esbmc_log or "", snippet.verification_meta)
        except Exception as e:  # the context is an aid; never block the fix on it
            self.log.warning(f"Could not build violation context for {snippet.uuid}: {e}")
            where = ""
        where_section = f"# Where the violation happens:\n{where}\n\n" if where else ""
        formatted_user_prompt = (f"# Instruction:\n{self.fixing_user_prompt}\n\n"
                                 f"# Vulnerable Code:\n```\n{snippet.code}\n```\n\n"
                                 f"{where_section}"
                                 f"# ESBMC Log:\n{esbmc_log}\n\n"
                                 f"{self._crash_section(snippet)}"
                                 f"{self._attempt_section(message)}")
        messages = [{"role": "user", "content": self.fixing_system_prompt + "\n\n" + formatted_user_prompt}]

        try:
            response = await self._call_llm_api(messages)
            if response and response.choices:
                return self._parse_response(response.choices[0].message.content)
        except (openai.APIConnectionError, openai.APITimeoutError, openai.InternalServerError, openai.RateLimitError) as e:
            await self._defer_transient(e, snippet.uuid)
        except Exception as e:
            self.log.error(f"Vulnerability fix API call failed for {snippet.uuid}: {e}", exc_info=True)
        return "", ""

    async def inject_vuln_code(self, snippet: CodeSnippet, message: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
        target_cwes = ', '.join(c.id for c in snippet.cwes) if snippet.cwes else 'not specified'
        formatted_user_prompt = (f"# Instruction:\n{self.inject_vulnerability_user_prompt}\n\n"
                                 f"# Target CWE:\n{target_cwes}\n\n"
                                 f"# Safe Code:\n```\n{snippet.code}\n```\n\n"
                                 f"{self._attempt_section(message)}")
        messages = [{"role": "user", "content": self.inject_vulnerability_system_prompt + "\n\n" + formatted_user_prompt}]

        try:
            response = await self._call_llm_api(messages)
            if response and response.choices:
                return self._parse_response(response.choices[0].message.content)
        except (openai.APIConnectionError, openai.APITimeoutError, openai.InternalServerError, openai.RateLimitError) as e:
            await self._defer_transient(e, snippet.uuid)
        except Exception as e:
            self.log.error(f"Vulnerability injection API call failed for {snippet.uuid}: {e}", exc_info=True)
        return "", ""

    async def fix_compilation(self, snippet: CodeSnippet) -> Tuple[str, str]:
        formatted_user_prompt = (f"# Instruction:\n{self.compilation_user_prompt}\n\n"
                                 f"# Language:\n{snippet.language}\n\n"
                                 f"# Code with Compilation Errors:\n```\n{snippet.code}\n```\n\n"
                                 f"# Compiler Output:\n```\n{snippet.compilation_log}\n```")
        messages = [{"role": "user", "content": self.compilation_system_prompt + "\n\n" + formatted_user_prompt}]

        try:
            response = await self._call_llm_api(messages)
            if response and response.choices:
                return self._parse_response(response.choices[0].message.content)
        except (openai.APIConnectionError, openai.APITimeoutError, openai.InternalServerError, openai.RateLimitError) as e:
            await self._defer_transient(e, snippet.uuid)
        except Exception as e:
            self.log.error(f"Compilation fix API call failed for {snippet.uuid}: {e}", exc_info=True)
        return "", ""

    def _create_and_publish_snippet(self, **kwargs):
        snippet_uuid = kwargs.get("uuid", "N/A")
        try:
            snippet_data = {
                'snippet_type': Type.GENERATED.value, 'status': Status.GENERATION_SUCCESS.value,
                'label': Label.UNKNOWN.value, **kwargs
            }
            self.db.create_snippet(snippet_data=snippet_data)
            if settings.queues.get('auto_advance', True):
                queue_name = make_queue_name("compiler", kwargs["generation_model"])
                if self.producer.publish_message(queue_name, {'uuid': snippet_uuid}):
                    self.log.info(f"Successfully created and published snippet {snippet_uuid}")
                else:
                    # The snippet row exists, so re-delivering the inbound task
                    # would spend another LLM call and — for fix/inject tasks,
                    # whose child uuid is freshly minted — create a duplicate child.
                    log_stranded(self.log, snippet_uuid, "compile",
                                 f"could not queue the compilation task on '{queue_name}'")
            else:
                self.log.info(f"auto_advance disabled — snippet {snippet_uuid} saved as GENERATION_SUCCESS, skipping compiler publish")
        except Exception as e:
            self.log.error(f"Failed to create/publish snippet {snippet_uuid}: {e}", exc_info=True)
            raise

    def process_message_batch(self, messages: List[Dict[str, Any]]) -> List[str]:
        return asyncio.run(self.process_message_batch_async(messages))

    async def process_message_batch_async(self, messages: List[Dict[str, Any]]) -> List[str]:
        """Handle a batch concurrently, returning one Outcome per message.

        The handlers run under asyncio.gather with return_exceptions=True so one
        failing task cannot cancel its siblings mid-LLM-call, and each message is
        acknowledged on its own merits.
        """
        if not messages:
            return []
        self.log.info(f"Processing batch of {len(messages)} messages.")

        tasks = []
        for msg in messages:
            task_type = msg.get('task_type')
            if task_type == 'generate':
                tasks.append(self._handle_single_generation(msg))
            elif task_type == 'vulnerability_fix':
                tasks.append(self._handle_single_generation(msg, is_vuln_fix=True))
            elif task_type == 'compilation_fix':
                tasks.append(self._handle_single_compilation_fix(msg))
            elif task_type == 'inject_vulnerability':
                tasks.append(self._handle_single_generation(msg, is_vuln_inject=True))
            elif task_type == 'reproduce_poc':
                tasks.append(self._handle_reproduce_poc(msg))
            else:
                self.log.warning(f"Unknown task type '{task_type}' for message UUID {msg.get('uuid')}")
                tasks.append(self._unknown_task(msg))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        outcomes = []
        for msg, result in zip(messages, results):
            if isinstance(result, RetryableError):
                self.log.warning(f"Deferring {msg.get('uuid')} — {result}")
                outcomes.append(Outcome.RETRY)
            elif isinstance(result, (OperationalError, SATimeoutError, ConnectionError)):
                self.log.error(
                    f"Transient infrastructure error on {msg.get('uuid')} — "
                    f"re-queuing message: {result}"
                )
                outcomes.append(Outcome.RETRY)
            elif isinstance(result, BaseException):
                self.log.error(
                    f"Task for {msg.get('uuid')} failed: {result}", exc_info=result
                )
                outcomes.append(Outcome.DROP)
            else:
                outcomes.append(Outcome.ACK)
        return outcomes

    async def _unknown_task(self, message: Dict[str, Any]) -> None:
        """Placeholder so an unknown task_type still gets an outcome (a DROP)."""
        raise ValueError(f"Unknown task type '{message.get('task_type')}'")

    async def _handle_single_generation(self, message: Dict[str, Any], is_vuln_fix: bool = False, is_vuln_inject: bool = False):
        seed_uuid = message['seed_uuid']
        if not is_vuln_fix:
            seed_snippet = self.db.get_snippet(uuid=seed_uuid)
            if not seed_snippet or seed_snippet.type != Type.SEED.value:
                return

        code, install_command = "", ""
        if is_vuln_fix:
            vulnerable_snippet = self.db.get_snippet(uuid=message['uuid'])
            if not vulnerable_snippet:
                self.log.error(f"Cannot fix vulnerability: Snippet {message['uuid']} not found.")
                return
            new_snippet_uuid = str(uuid.uuid4())
            self.log.info(f"Fixing vulnerability for {message['uuid']}. New UUID: {new_snippet_uuid}")
            code, install_command = await self.fix_vuln_code(vulnerable_snippet, message)
            parent_uuid = message['uuid']
        elif is_vuln_inject:
            safe_snippet = self.db.get_snippet(uuid=message['uuid'])
            if not safe_snippet:
                self.log.error(f"Cannot inject vulnerability: Snippet {message['uuid']} not found.")
                return
            new_snippet_uuid = str(uuid.uuid4())
            self.log.info(f"Injecting vulnerability for {message['uuid']}. New UUID: {new_snippet_uuid}")
            code, install_command = await self.inject_vuln_code(safe_snippet, message)
            parent_uuid = message['uuid']
        else:
            new_snippet_uuid = message['uuid']
            self.log.info(f"Generating code for seed {seed_uuid}. New UUID: {new_snippet_uuid}")
            code, install_command = await self.generate_code(message)
            parent_uuid = None

        if code:
            code = self._format_code(code)
            parent = vulnerable_snippet if is_vuln_fix else safe_snippet if is_vuln_inject else None
            reasons = check_program(code, message['language'], guards_for(parent))
            if parent is not None and code_hash(code) == (parent.code_hash or code_hash(parent.code)):
                reasons.append('counterpart is byte-identical to the parent')
            if reasons:
                self.log.info(f"Rejected {message.get('task_type')} output for {new_snippet_uuid}: {reasons}")
                if parent is not None:
                    self._pair_attempt_failed(message, '; '.join(reasons), code)
                else:
                    self._record_rejected_generation(new_snippet_uuid, message, code, reasons)
                return
            cwes_value = message.get('cwes', [])
            if isinstance(cwes_value, list):
                cwes_str = ','.join(str(c) for c in cwes_value)
            else:
                cwes_str = str(cwes_value)
            self._create_and_publish_snippet(
                uuid=new_snippet_uuid, code=code,
                install_command=self._format_install_command(install_command),
                seed_uuid=seed_uuid, parent_uuid=parent_uuid,
                language=message['language'], generation_model=message['generation_model'],
                project=message.get('project', ''),
                commit_message=message.get('commit_message', ''),
                metrics=message.get('metrics', {}),
                cwes=cwes_str,
                reproduce_attempts=message.get('reproduce_attempts', 0),
                **({'info': f"counterpart written by {self.model_key}"}
                   if parent is not None and self.model_key != message['generation_model'] else {}),
            )
        else:
            self.log.warning(f"No code generated for task {message.get('task_type')} on snippet {new_snippet_uuid}. Skipping.")

    def _record_rejected_generation(self, snippet_uuid, message, code, reasons):
        """Keep a GENERATION_FAILED row so rejection rates are measurable per model."""
        try:
            self.db.create_snippet(snippet_data={
                'uuid': snippet_uuid, 'code': code, 'seed_uuid': message['seed_uuid'],
                'generation_model': message['generation_model'], 'language': message['language'],
                'snippet_type': Type.GENERATED.value, 'status': Status.GENERATION_FAILED.value,
                'label': Label.UNKNOWN.value, 'info': 'rejected by guards: ' + '; '.join(reasons),
                'project': message.get('project', ''), 'commit_message': message.get('commit_message', ''),
                'metrics': message.get('metrics', {}),
            })
        except Exception as e:
            self.log.error(f"Could not record rejected generation {snippet_uuid}: {e}")

    def _pair_attempt_failed(self, message: Dict[str, Any], reason: str, code: Optional[str] = None):
        """Count a failed counterpart attempt and re-queue it, with the rejected code and why,
        while attempts remain."""
        parent_uuid = message['uuid']
        max_attempts = int(settings.pairing.get('max_attempts', 3))
        attempts = self.db.increment_pair_attempts(parent_uuid)
        if attempts >= max_attempts:
            self.log.info(f"Pairing for {parent_uuid} exhausted after {attempts} attempt(s): {reason}")
            return
        if settings.queues.get('auto_advance', True):
            queue_name = counterpart_queue(message.get('task_type', ''), message['generation_model'])
            retry = {**message, 'pair_attempt': attempts + 1}
            if code:
                retry.update(previous_code=code, feedback=f"Your previous attempt (shown below) was rejected before "
                                                          f"verification: {reason}.")
            self.producer.publish_message(queue_name, retry)

    async def _handle_reproduce_poc(self, message: Dict[str, Any]):
        """Write candidate crashing inputs for a VULNERABLE snippet and send them to be replayed."""
        snippet = self.db.get_snippet(uuid=message['uuid'])
        if not snippet or snippet.label != Label.VULNERABLE.value:
            return
        tried = list(message.get('tried') or [])
        prompt = build_poc_prompt(self.poc_user_prompt, snippet.code, snippet.esbmc_log or '',
                                  snippet.verification_meta, tried)
        candidates = []
        try:
            response = await self._call_llm_api([{"role": "user", "content": prompt}])
            if response and response.choices:
                candidates = parse_candidates(response.choices[0].message.content or '')
        except (openai.APIConnectionError, openai.APITimeoutError, openai.InternalServerError, openai.RateLimitError) as e:
            await self._defer_transient(e, snippet.uuid)
        self.log.info(f"Proof of concept round {message.get('round', 1)} for {snippet.uuid}: {len(candidates)} candidate(s)")
        tried += [describe_input(c) for c in candidates] or ['(no parseable candidate)']
        queue_name = make_queue_name("esbmc", snippet.generation_model)
        if not self.producer.publish_message(queue_name, {
                'uuid': snippet.uuid, 'task': 'replay_poc', 'round': message.get('round', 1), 'tried': tried,
                'seeds': [base64.b64encode(c).decode() for c in candidates]}):
            log_stranded(self.log, snippet.uuid, "reproduce", f"could not queue replay_poc on '{queue_name}'")

    async def _handle_single_compilation_fix(self, message: Dict[str, Any]):
        snippet = self.db.get_snippet(uuid=message['uuid'])
        if not snippet:
            self.log.error(f"Snippet {message['uuid']} not found for compilation fix.")
            return

        if snippet.attempt_count >= 3:
            self.log.warning(f"Max attempts reached for snippet {message['uuid']}. Skipping compilation fix.")
            return

        fixed_code, install_command = await self.fix_compilation(snippet)
        if fixed_code:
            fixed_code = self._format_code(fixed_code)
            parent = self.db.get_snippet(uuid=snippet.parent_uuid) if snippet.parent_uuid else None
            reasons = check_program(fixed_code, snippet.language, guards_for(parent or snippet))
            if reasons:
                self.db.update_snippet(uuid=message['uuid'], metadata={
                    'status': Status.GENERATION_FAILED.value,
                    'info': 'rejected by guards after compilation fix: ' + '; '.join(reasons)})
                return
            metadata = {
                'code': fixed_code,
                'install_command': self._format_install_command(install_command),
                'status': Status.GENERATION_SUCCESS.value
            }
            self.db.update_snippet(uuid=message['uuid'], metadata=metadata)
            if settings.queues.get('auto_advance', True):
                queue_name = make_queue_name("compiler", snippet.generation_model)
                if self.producer.publish_message(queue_name, {'uuid': message['uuid']}):
                    self.log.info(f"Successfully submitted compilation fix for {message['uuid']} (Attempt {snippet.attempt_count + 1})")
                else:
                    log_stranded(self.log, message['uuid'], "compile",
                                 f"could not queue the compilation task on '{queue_name}'")
            else:
                self.log.info(f"auto_advance disabled — compilation fix saved for {message['uuid']} (Attempt {snippet.attempt_count + 1}), skipping compiler publish")
        else:
            self.log.warning(f"No compilation fix generated for {message['uuid']}. Skipping update.")

def start_llm_agent(model_name: str):
    log = logger.get_logger("llm_agent_starter")
    log.info(f"Starting LLM Agent for model: {model_name}")
    
    consumer = None
    try:
        agent = LLMAgent(model_name)
        queue_name = make_queue_name("llm", model_name)

        batch_size = settings.queues.get('llm_batch_size', 8)
        batch_timeout = settings.queues.get('llm_batch_timeout', 2.0)
        concurrency = settings.queues.get('llm_concurrency', 2)

        log.info(f"Creating consumer for queue: {queue_name} with batch_size={batch_size}, concurrency={concurrency}")
        consumer = QueueConsumer(
            queue_name=queue_name,
            callback=agent.process_message_batch,
            host=settings.rabbitmq['host'],
            port=settings.rabbitmq['port'],
            batch_size=batch_size,
            batch_timeout=batch_timeout,
            max_workers=concurrency,
        )
        install_shutdown_handler(log, consumer, agent)

        log.info("Starting message consumption")
        consumer.start_consuming()

    except Exception as e:
        log.error(f"Error starting LLM Agent for {model_name}: {str(e)}", exc_info=True)
        raise
    finally:
        if consumer:
            consumer.close()
