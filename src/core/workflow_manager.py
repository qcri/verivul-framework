import uuid
import random
import re
import hashlib
import numpy as np
from typing import Dict, Any, List, Optional, Set

from sqlalchemy.orm import aliased

from ..queue.producer import QueueProducer
from ..db.database import DatabaseManager
from ..db.models import CodeSnippet, Type, Status, Label, ready_for_counterpart
from ..utils.logger import logger
from ..utils.queue import make_queue_name, counterpart_queue
from config.settings import settings

# Ordered stage names exposed to callers and the CLI.
RESUME_STAGES = ("generate", "compile", "compile_fix", "verify", "inject_fix")


def _code_hash(code: str) -> str:
    """Return the SHA-256 hex digest of the code string (used to deduplicate seeds)."""
    return hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest()

class WorkflowManager:
    def __init__(self):
        self.log = logger.get_logger("workflow_manager")
        self.log.info("Initializing WorkflowManager")
        self.producer = QueueProducer(
            caller="WorkflowManager",
            host=settings.rabbitmq['host'],
            port=settings.rabbitmq['port']
        )
        self.db = DatabaseManager(caller="WorkflowManager", db_url=settings.database['url'])
        self.log.info("WorkflowManager initialized successfully")

    def _extract_metrics(self, snippet: str) -> dict:
        lines = [line for line in snippet.splitlines() if line.strip()]
        loc = len(lines)
        
        decision_keywords = r'\b(if|for|while|case|catch|elif|else\s+if)\b'
        decisions = re.findall(decision_keywords, snippet)
        cc = 1 + len(decisions)
        
        if "{" in snippet and "}" in snippet:
            max_depth = 0
            current_depth = 0
            for char in snippet:
                if char == '{':
                    current_depth += 1
                    max_depth = max(max_depth, current_depth)
                elif char == '}':
                    current_depth = max(0, current_depth - 1)
            nd = max_depth
        else:
            indent_levels = []
            for line in lines:
                match = re.match(r'^(\s+)', line)
                if match:
                    indent_levels.append(len(match.group(1)) // 4)
                else:
                    indent_levels.append(0)
            nd = max(indent_levels) if indent_levels else 0
        
        return {"loc": loc, "cc": cc, "nd": nd}

    def _select_metrics(self, reference_snippet: Optional[str] = None) -> dict:
        overhead_loc = random.randint(80, 500) 
        overhead_cc = random.randint(5, 80) 
        overhead_nd = random.randint(0, 5)  
    
        if reference_snippet:
            ref = self._extract_metrics(reference_snippet)
            program_loc = ref["loc"] + overhead_loc
            program_cc = ref["cc"] + overhead_cc
            program_nd = max(ref["nd"], overhead_nd)
            
            program_cc = max(1, int(program_cc * random.uniform(0.9, 1.1)))
            program_loc = max(program_loc, int(program_loc * random.uniform(0.95, 1.05)))
            program_nd = min(program_cc, max(0, int(program_nd * random.uniform(0.9, 1.1))))
            return {"cc": program_cc, "loc": program_loc, "nd": program_nd}
        else:
            cc = max(1, int(np.random.poisson(lam=3)))
            loc = max(cc, int(np.random.lognormal(mean=3, sigma=0.6)))
            nd = min(random.choices(range(6), weights=[60, 25, 10, 3, 1, 1])[0], cc)
            
            program_loc = loc + overhead_loc
            program_cc = cc + overhead_cc
            program_nd = nd
            return {"cc": program_cc, "loc": program_loc, "nd": program_nd}

    def _resolve_language(self, language: str) -> str:
        """Normalise the generation target language.
        Java seeds exist in the dataset but Java is not a supported generation
        target (no compilation or verification). Remap to Kotlin so the seed
        drives Kotlin generation instead."""
        if language.lower() == 'java':
            return 'kotlin'
        return language

    def populate_datapoints(self, datapoints: List[Dict[str, Any]]):
        self.log.info(f"Populating {len(datapoints)} datapoints...")

        # Pre-load existing seed hashes so we can skip duplicates without
        # hitting the DB once per datapoint.
        with self.db.session_scope() as _s:
            existing_hashes: set = {
                row[0] for row in
                _s.query(CodeSnippet.code_hash)
                .filter(CodeSnippet.type == Type.SEED.value,
                        CodeSnippet.code_hash.isnot(None))
            }
            # Likewise for (seed, model) pairs.  This used to be a
            # get_snippets_by_seed() call *inside the per-model loop* — one query
            # per datapoint per model, each loading whole snippet objects
            # (code + logs), so populating 1000 datapoints across 3 models meant
            # 3000 queries pulling tens of MB to answer a set-membership question.
            existing_generations: set = {
                (row[0], row[1]) for row in
                _s.query(CodeSnippet.seed_uuid, CodeSnippet.generation_model)
                .filter(CodeSnippet.type == Type.GENERATED.value)
            }
        self.log.info(
            f"Found {len(existing_hashes)} existing seed hashes and "
            f"{len(existing_generations)} existing generations in DB."
        )

        seen_hashes: set = set()  # deduplicate within this batch too
        for i, dp in enumerate(datapoints):
            self.log.info(f"Populating datapoint {i+1}/{len(datapoints)}")

            if 'uuid' not in dp or not dp['uuid']:
                dp['uuid'] = str(uuid.uuid4())
                self.log.warning(f"Datapoint missing UUID, generated: {dp['uuid']}")

            dp_hash = _code_hash(dp['code'])
            if dp_hash in existing_hashes or dp_hash in seen_hashes:
                self.log.info(f"Skipping duplicate seed (hash={dp_hash[:12]}…) for datapoint {dp['uuid']}")
                continue
            seen_hashes.add(dp_hash)

            raw_cwes = dp.get('cwes', [])
            cwes_str = ','.join(str(c) for c in raw_cwes) if isinstance(raw_cwes, list) else str(raw_cwes or '')
            target_cwe = dp.get('target_cwe') or (raw_cwes[0] if isinstance(raw_cwes, list) and raw_cwes else '')
            metrics = self._select_metrics(dp['code'])
            metrics.update({'target_cwe': target_cwe, 'seed_cwes': raw_cwes if isinstance(raw_cwes, list) else [raw_cwes], 'target_cwe_source': dp.get('target_cwe_source', 'seed'),
                            'criterion_source': dp.get('criterion_source')})
            seed_snippet_data = {
                'uuid': dp['uuid'],
                'seed_uuid': dp['uuid'],
                'generation_model': "seed",
                'code': dp['code'],
                'code_hash': dp_hash,
                'label': Label.UNKNOWN.value,
                'status': Status.GROUND_TRUTH.value,
                'snippet_type': Type.SEED.value,
                'language': dp['language'],
                'info': dp.get('info', ''),
                'project': dp.get('project', ''),
                'commit_message': dp.get('commit_message', ''),
                'metrics': metrics,
                'install_command': dp.get('install_command', '# No command found'),
                'slice_code': dp.get('slice_code', None),
                'dataset': dp.get('dataset', None),
                'repo_url': dp.get('repo_url', None),
                'commit_hash': dp.get('commit_hash', None),
                'cve': dp.get('cve', None),
                # Our seed -> CWE mapping (target_cwe) is the main source; the dataset's
                # own CWEs are kept in metrics['seed_cwes'].
                'cwes': target_cwe or cwes_str,
            }
            self.db.create_snippet(snippet_data=seed_snippet_data)
            self.log.info(f"Created SEED Snippet: {seed_snippet_data['uuid']}")

            for model_key in settings.models.keys():
                model_config = settings.models[model_key]
                if model_config.get('enabled', True):
                    already_generated_for_model = (
                        seed_snippet_data['uuid'], model_key
                    ) in existing_generations

                    if self._resolve_language(dp['language']).lower() in settings.skip_languages:
                        continue

                    if not already_generated_for_model:
                        generation_task_message = {
                            'uuid': str(uuid.uuid4()),
                            'task_type': 'generate',
                            'seed_uuid': seed_snippet_data['uuid'],
                            'generation_model': model_key,
                            'code': dp['code'],
                            'language': self._resolve_language(dp['language']),
                            'project': dp.get('project', ''),
                            'label': Label.UNKNOWN.value,
                            'cwes': [target_cwe] if target_cwe else dp.get('cwes', []),
                            'seed_cwes': dp.get('cwes', []),
                            'target_cwe_source': dp.get('target_cwe_source', 'seed'),
                            'commit_message': dp.get('commit_message', ''),
                            'metrics': metrics,
                            'install_command': dp.get('install_command', '# No command found'),
                            'slice_context': dp.get('slice_code', ''),
                        }
                        self.log.info(f"Publishing generation task to queue: {make_queue_name('llm', model_key)} for seed {seed_snippet_data['uuid']}")
                        self.producer.publish_message(make_queue_name("llm", model_key), generation_task_message)

    def start_verification_workflow(self, seed_uuid: str, model_key: str):
        self.log.info(f"Starting verification process for seed_uuid: {seed_uuid} and model: {model_key}")
        
        snippets_for_seed = self.db.get_snippets_by_seed(seed_uuid)
        snippet_to_verify = next((s for s in snippets_for_seed if s.generation_model == model_key and s.type == Type.GENERATED.value and s.status in [Status.COMPILATION_FAILED.value, Status.VERIFICATION_FAILED.value, Status.GENERATION_SUCCESS.value]), None)

        if snippet_to_verify:
            self.log.info(f"Found snippet {snippet_to_verify.uuid} for re-verification. Status: {snippet_to_verify.status}")
            
            queue_map = {
                Status.GENERATION_SUCCESS.value: (make_queue_name("compiler", model_key), 'compile'),
                Status.COMPILATION_FAILED.value: (make_queue_name("llm", model_key), 'compilation_fix'),
                Status.VERIFICATION_FAILED.value: (make_queue_name("llm", model_key), 'vulnerability_fix')
            }
            
            if snippet_to_verify.status in queue_map:
                queue_name, task_type = queue_map[snippet_to_verify.status]
                task_message = {
                    'uuid': snippet_to_verify.uuid,
                    'task_type': task_type,
                    'language': snippet_to_verify.language,
                    'code': snippet_to_verify.code,
                    'seed_uuid': snippet_to_verify.seed_uuid,
                    'generation_model': snippet_to_verify.generation_model,
                    'compilation_log': snippet_to_verify.compilation_log,
                    'esbmc_log': snippet_to_verify.esbmc_log,
                    'parent_uuid': snippet_to_verify.parent_uuid,
                    'attempt_count': snippet_to_verify.attempt_count
                }
                self.log.info(f"Re-publishing task '{task_type}' for snippet {snippet_to_verify.uuid} to queue: {queue_name}")
                self.producer.publish_message(queue_name, task_message)
        else:
            self.log.warning(f"No generated snippet found for seed {seed_uuid} and model {model_key} requiring verification.")

    # ------------------------------------------------------------------
    # Individual resume stages
    # ------------------------------------------------------------------

    def _resume_generate(self, datapoints: List[Dict[str, Any]], models: Optional[Set[str]] = None) -> None:
        """Ensure every seed exists in the DB and has a generate task queued for
        each enabled model that hasn't produced a snippet yet."""
        with self.db.session_scope() as session:
            existing_seed_uuids = {
                row[0] for row in session.query(CodeSnippet.uuid)
                .filter(CodeSnippet.type == Type.SEED.value)
            }
            existing_generations_set = {
                (row[0], row[1]) for row in
                session.query(CodeSnippet.seed_uuid, CodeSnippet.generation_model)
                .filter(CodeSnippet.type == Type.GENERATED.value)
            }

        # Also load existing code hashes to avoid content duplicates.
        with self.db.session_scope() as _s:
            existing_hashes: set = {
                row[0] for row in
                _s.query(CodeSnippet.code_hash)
                .filter(CodeSnippet.type == Type.SEED.value,
                        CodeSnippet.code_hash.isnot(None))
            }

        self.log.info(
            f"[generate] {len(existing_seed_uuids)} seeds, "
            f"{len(existing_generations_set)} existing generated snippets in DB."
        )
        queued = 0
        seen_hashes: set = set()
        for i, dp in enumerate(datapoints):
            seed_uuid = dp.get('uuid')
            if not seed_uuid:
                seed_uuid = str(uuid.uuid4())
                dp['uuid'] = seed_uuid

            dp_hash = _code_hash(dp['code'])
            if dp_hash in seen_hashes:
                self.log.info(f"[generate] Skipping intra-batch duplicate seed (hash={dp_hash[:12]}…) {seed_uuid}")
                continue
            seen_hashes.add(dp_hash)

            if seed_uuid not in existing_seed_uuids and dp_hash not in existing_hashes:
                raw_cwes = dp.get('cwes', [])
                cwes_str = ','.join(str(c) for c in raw_cwes) if isinstance(raw_cwes, list) else str(raw_cwes or '')
                self.db.create_snippet(snippet_data={
                    'uuid': seed_uuid,
                    'seed_uuid': seed_uuid,
                    'generation_model': "seed",
                    'code': dp['code'],
                    'code_hash': dp_hash,
                    'label': Label.UNKNOWN.value,
                    'status': Status.GROUND_TRUTH.value,
                    'snippet_type': Type.SEED.value,
                    'language': dp['language'],
                    'info': dp.get('info', ''),
                    'project': dp.get('project', ''),
                    'commit_message': dp.get('commit_message', ''),
                    'metrics': self._select_metrics(dp['code']),
                    'install_command': dp.get('install_command', '# No command found'),
                    'slice_code': dp.get('slice_code', None),
                    'dataset': dp.get('dataset', None),
                    'repo_url': dp.get('repo_url', None),
                    'commit_hash': dp.get('commit_hash', None),
                    'cve': dp.get('cve', None),
                    'cwes': dp.get('target_cwe') or cwes_str,
                })
                existing_seed_uuids.add(seed_uuid)
                self.log.info(f"[generate] Created missing SEED {seed_uuid}")

            for model_key, model_config in settings.models.items():
                if (models is None or model_key in models) and model_config.get('enabled', True) \
                        and (seed_uuid, model_key) not in existing_generations_set \
                        and self._resolve_language(dp['language']).lower() not in settings.skip_languages:
                    self.producer.publish_message(make_queue_name("llm", model_key), {
                        'uuid': str(uuid.uuid4()),
                        'task_type': 'generate',
                        'seed_uuid': seed_uuid,
                        'generation_model': model_key,
                        'code': dp['code'],
                        'language': self._resolve_language(dp['language']),
                        'project': dp.get('project', ''),
                        'label': Label.UNKNOWN.value,
                        'cwes': [dp['target_cwe']] if dp.get('target_cwe') else dp.get('cwes', []),
                        'seed_cwes': dp.get('cwes', []),
                        'target_cwe_source': dp.get('target_cwe_source', 'seed'),
                        'commit_message': dp.get('commit_message', ''),
                        'metrics': self._select_metrics(dp['code']),
                        'install_command': dp.get('install_command', '# No command found'),
                        'slice_context': dp.get('slice_code', ''),
                    })
                    queued += 1

        self.log.info(f"[generate] Queued {queued} missing generate task(s).")

    # These stages only need a handful of scalar columns to build a queue message.
    # Querying whole CodeSnippet objects dragged `code`, `esbmc_log`, `witness` and
    # `compilation_log` along with them — ~12 KB of text per row, i.e. ~95 MB to
    # re-queue the 8k snippets awaiting verification.  Selecting columns keeps
    # these scans ~10x faster and flat in memory.

    def _resume_compile(self, session) -> None:
        """Re-queue GENERATION_SUCCESS snippets waiting for the compiler."""
        rows = session.query(CodeSnippet.uuid, CodeSnippet.generation_model).filter(
            CodeSnippet.type == Type.GENERATED.value,
            CodeSnippet.status == Status.GENERATION_SUCCESS.value,
        ).all()
        failed = 0
        for row in rows:
            if not self.producer.publish_message(
                make_queue_name("compiler", row.generation_model), {'uuid': row.uuid},
            ):
                failed += 1
        self.log.info(
            f"[compile] Re-queued {len(rows) - failed} snippet(s) for compilation"
            + (f"; {failed} publish failure(s)." if failed else ".")
        )

    def _resume_compile_fix(self, session) -> None:
        """Re-queue COMPILATION_FAILED snippets that still have retry budget."""
        rows = session.query(
            CodeSnippet.uuid, CodeSnippet.generation_model, CodeSnippet.attempt_count,
        ).filter(
            CodeSnippet.type == Type.GENERATED.value,
            CodeSnippet.status == Status.COMPILATION_FAILED.value,
        ).all()
        queued = skipped = failed = 0
        for row in rows:
            if row.attempt_count >= 3:
                skipped += 1
                continue
            if self.producer.publish_message(
                make_queue_name("llm", row.generation_model),
                {'uuid': row.uuid, 'task_type': 'compilation_fix',
                 'attempt_count': row.attempt_count},
            ):
                queued += 1
            else:
                failed += 1
        self.log.info(
            f"[compile_fix] Re-queued {queued} snippet(s); "
            f"{skipped} exhausted max retries — skipped"
            + (f"; {failed} publish failure(s)." if failed else ".")
        )

    def _resume_verify(self, session) -> None:
        """Re-queue COMPILATION_SUCCESS snippets waiting for ESBMC."""
        rows = session.query(CodeSnippet.uuid, CodeSnippet.generation_model).filter(
            CodeSnippet.type == Type.GENERATED.value,
            CodeSnippet.status == Status.COMPILATION_SUCCESS.value,
        ).all()
        failed = 0
        for row in rows:
            if not self.producer.publish_message(
                make_queue_name("esbmc", row.generation_model), {'uuid': row.uuid},
            ):
                failed += 1
        self.log.info(
            f"[verify] Re-queued {len(rows) - failed} snippet(s) for ESBMC verification"
            + (f"; {failed} publish failure(s)." if failed else ".")
        )

    def _resume_inject_fix(self, session) -> None:
        """Re-queue vulnerability_fix / inject_vulnerability tasks for every
        verified original snippet (SAFE or VULNERABLE) that has no derived child yet."""
        # NOT IN against a materialised python set forced every parent_uuid into
        # memory; a correlated NOT EXISTS lets Postgres use ix_snippets_parent_uuid.
        child = aliased(CodeSnippet)
        has_child = (
            session.query(child.uuid)
            .filter(child.parent_uuid == CodeSnippet.uuid)
            .exists()
        )
        rows = session.query(
            CodeSnippet.uuid, CodeSnippet.seed_uuid, CodeSnippet.generation_model,
            CodeSnippet.language, CodeSnippet.project, CodeSnippet.commit_message,
            CodeSnippet.install_command, CodeSnippet.label,
        ).filter(
            CodeSnippet.type == Type.GENERATED.value,
            CodeSnippet.parent_uuid.is_(None),
            CodeSnippet.label.in_([Label.SAFE.value, Label.VULNERABLE.value]),
            CodeSnippet.status == Status.VERIFICATION_SUCCESS.value,
            ~has_child,
            *([ready_for_counterpart()] if settings.esbmc.get('dynamic_confirm', True) else []),
        ).all()

        fix_count = inject_count = failed = 0
        for row in rows:
            base_msg = {
                'uuid': row.uuid,
                'seed_uuid': row.seed_uuid,
                'generation_model': row.generation_model,
                'language': row.language,
                'project': row.project or '',
                'cwes': [],
                'commit_message': row.commit_message or '',
                'install_command': row.install_command or '',
            }
            task_type = ('vulnerability_fix' if row.label == Label.VULNERABLE.value
                         else 'inject_vulnerability')
            if not self.producer.publish_message(
                counterpart_queue(task_type, row.generation_model),
                {**base_msg, 'task_type': task_type},
            ):
                failed += 1
            elif task_type == 'vulnerability_fix':
                fix_count += 1
            else:
                inject_count += 1

        self.log.info(
            f"[inject_fix] Re-queued {fix_count} vulnerability_fix and "
            f"{inject_count} inject_vulnerability task(s)"
            + (f"; {failed} publish failure(s)." if failed else ".")
        )

    # ------------------------------------------------------------------
    # Orchestrating resume entry point
    # ------------------------------------------------------------------

    def resume_workflow(
        self,
        datapoints: List[Dict[str, Any]] = None,
        stages: Optional[Set[str]] = None,
        models: Optional[Set[str]] = None,
    ) -> None:
        """Resume the pipeline for the given stages.

        Args:
            datapoints: Required only when the ``"generate"`` stage is included.
            stages:     Set of stage names to run.  Pass ``None`` to run all stages.
                        Valid values: ``"generate"``, ``"compile"``, ``"compile_fix"``,
                        ``"verify"``, ``"inject_fix"``.
            models:     Limit the ``"generate"`` stage to these model keys (default: all enabled).
        """
        active = set(RESUME_STAGES) if stages is None else set(stages)
        unknown = active - set(RESUME_STAGES)
        if unknown:
            raise ValueError(f"Unknown resume stage(s): {unknown}. Valid: {RESUME_STAGES}")

        self.log.info(f"Resuming workflow — active stages: {sorted(active)}")

        if "generate" in active:
            if not datapoints:
                self.log.warning("[generate] stage requested but no datapoints provided — skipping.")
            else:
                self._resume_generate(datapoints, models)

        # All remaining stages work purely from DB state — open one session for them.
        db_stages = {"compile", "compile_fix", "verify", "inject_fix"} & active
        if db_stages:
            with self.db.session_scope() as session:
                if "compile" in active:
                    self._resume_compile(session)
                if "compile_fix" in active:
                    self._resume_compile_fix(session)
                if "verify" in active:
                    self._resume_verify(session)
                if "inject_fix" in active:
                    self._resume_inject_fix(session)

        self.log.info("Resume complete.")