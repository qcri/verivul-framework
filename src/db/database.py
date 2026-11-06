from sqlalchemy import create_engine, update, func
from sqlalchemy.orm import sessionmaker, scoped_session, joinedload
from sqlalchemy.exc import (
    DBAPIError,
    InterfaceError,
    OperationalError,
    TimeoutError as SATimeoutError,
)
from contextlib import contextmanager
from typing import Optional, List, Dict, Any
from .models import (
    Base,
    CodeSnippet,
    Status,
    Label,
    Type,
    CWE,
    Stats,
    code_snippet_cwe_association,
)
from ..utils.logger import logger
from config.settings import settings
import os
import threading
import time
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Errors that mean "the connection or pool let us down, try again on a fresh
# connection" rather than "this statement is wrong".  InterfaceError covers a
# connection closed underneath us (common behind pgbouncer); a DBAPIError is
# transient only when SQLAlchemy has flagged it as a disconnect.
_TRANSIENT_DB_ERRORS = (OperationalError, SATimeoutError, InterfaceError)

# Text columns that can receive tool output containing bytes Postgres rejects.
_TEXT_FIELDS = ("esbmc_log", "compilation_log", "witness", "info", "code", "slice_code")


def _sha256_code(code: str) -> str:
    import hashlib
    return hashlib.sha256((code or "").encode("utf-8", errors="replace")).hexdigest()


def _is_transient(exc: Exception) -> bool:
    if isinstance(exc, _TRANSIENT_DB_ERRORS):
        return True
    return isinstance(exc, DBAPIError) and exc.connection_invalidated


def scrub_text(value: Any) -> Any:
    """Remove NUL bytes from a string value.

    Postgres rejects 0x00 in text ("A string literal cannot contain NUL (0x00)
    characters"), and ESBMC logs, GraphML witnesses and compiler output all
    occasionally contain them.  Left unscrubbed the whole write fails and the
    snippet silently keeps its previous status.
    """
    if isinstance(value, str) and "\x00" in value:
        return value.replace("\x00", "")
    return value


def scrub_payload(payload: Optional[Dict[str, Any]], log=None) -> Optional[Dict[str, Any]]:
    """Return *payload* with NUL bytes stripped from its text fields."""
    if not payload:
        return payload
    cleaned = dict(payload)
    for field in _TEXT_FIELDS:
        if field in cleaned:
            scrubbed = scrub_text(cleaned[field])
            if scrubbed is not cleaned[field]:
                if log:
                    log.warning(
                        f"Stripped NUL byte(s) from '{field}' of "
                        f"{cleaned.get('uuid', 'unknown snippet')} before writing."
                    )
                cleaned[field] = scrubbed
    return cleaned


class DatabaseManager:
    def __init__(self, caller: str, db_url: Optional[str] = None,
                 pool_size: Optional[int] = None, max_overflow: Optional[int] = None):
        self.log = logger.get_logger(f"database_manager_{caller}")
        self.log.info(f"Initializing DatabaseManager (called by: {caller})")

        # The pool has to cover every thread that can want a connection at the
        # same moment.  An agent runs `*_concurrency` worker threads, so a pool
        # smaller than that guarantees "QueuePool limit ... connection timed out"
        # under load — which older runs then recorded as a compilation or
        # verification *failure* on an innocent snippet.  pgbouncer sits in front
        # in transaction mode, so client-side connections are cheap.
        db_cfg = getattr(settings, "database", {}) or {}
        if pool_size is None:
            pool_size = db_cfg.get("pool_size", 16)
        if max_overflow is None:
            max_overflow = db_cfg.get("max_overflow", 8)
        pool_timeout = db_cfg.get("pool_timeout", 30)
        self.log.info(
            f"Connection pool: size={pool_size}, max_overflow={max_overflow}, "
            f"timeout={pool_timeout}s"
        )

        user = os.getenv("POSTGRES_USER", "user")
        password = os.getenv("POSTGRES_PASSWORD", "password")
        host = os.getenv("POSTGRES_HOST", "localhost")
        port = os.getenv("POSTGRES_PORT", "5432")
        dbname = os.getenv("POSTGRES_DB", "verivul")
        
        if db_url is None:
            db_url = f"postgresql://{user}:{password}@{host}:{port}/{dbname}?gssencmode=disable"

        self.log.debug(f"Database URL: {db_url}")
        
        if port in ["5432", "6432"]:
            try:
                admin_port = "5432" if port == "6432" else port
                conn = psycopg2.connect(
                    user=user,
                    password=password,
                    host=host,
                    port=admin_port,
                    dbname="postgres"
                )
                conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (dbname,))
                exists = cursor.fetchone()
                if not exists:
                    cursor.execute(f"CREATE DATABASE {dbname}")
                    self.log.info(f"Database '{dbname}' created.")
                cursor.close()
                conn.close()
            except Exception as e:
                self.log.error(f"Failed to create database '{dbname}': {str(e)}", exc_info=True)

        try:
            if "sqlite" in db_url:
                self.engine = create_engine(db_url, connect_args={"timeout": 15})
            else:
                self.engine = create_engine(
                    db_url,
                    pool_pre_ping=True,
                    pool_size=pool_size,
                    max_overflow=max_overflow,
                    # Raise after pool_timeout seconds waiting for a free slot
                    # rather than blocking indefinitely under load.
                    pool_timeout=pool_timeout,
                    # Recycle connections after 5 minutes so they're replaced
                    # before the server-side idle timeout kills them.
                    pool_recycle=300,
                    connect_args={
                        # Tag connections so pg_stat_activity is readable.
                        "application_name": f"verivul_{caller}",
                        # TCP keepalives prevent firewalls/OS from silently
                        # dropping idle connections mid-pool.
                        "keepalives": 1,
                        "keepalives_idle": 30,
                        "keepalives_interval": 10,
                        "keepalives_count": 5,
                    },
                )

            Base.metadata.create_all(self.engine)
            self._apply_migrations()

            # Aggregate-stats cache (see refresh_stats/get_stats).  Guarded by a
            # lock because every worker thread shares this DatabaseManager.
            self._stats_lock = threading.Lock()
            self._stats_cache: Optional[Dict[str, Any]] = None
            self._stats_cached_at = 0.0

            self._session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
            # Kept for callers that still reach for Session.remove() (the web API).
            # New code should use session_scope(), which hands out an independent
            # session per call — see the note there.
            self.Session = scoped_session(self._session_factory)
            self.log.info("Database connection and session factory established successfully.")

        except Exception as e:
            self.log.error(f"Failed to initialize database (called by {caller}): {str(e)}", exc_info=True)
            raise

    # Columns added, and indexes needed, after the initial deployment.
    #
    # Without these every dashboard query, every resume scan and the pairs
    # self-join was a sequential scan of the whole table (124 MB of heap at 75k
    # rows), so their cost grew linearly with the dataset.  The ordering of the
    # composite indexes matches how the queries filter and sort, so Postgres can
    # satisfy filter + ORDER BY + LIMIT from one index walk with no sort step.
    MIGRATIONS = [
        "ALTER TABLE code_snippets ADD COLUMN IF NOT EXISTS code_hash VARCHAR(64)",
        "ALTER TABLE code_snippets ADD COLUMN IF NOT EXISTS witness TEXT",
        "ALTER TABLE code_snippets ADD COLUMN IF NOT EXISTS verification_meta JSONB",
        "ALTER TABLE code_snippets ADD COLUMN IF NOT EXISTS verified_code_hash VARCHAR(64)",
        "ALTER TABLE code_snippets ADD COLUMN IF NOT EXISTS esbmc_cwes JSONB",
        "ALTER TABLE code_snippets ADD COLUMN IF NOT EXISTS pair_attempts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE code_snippets ADD COLUMN IF NOT EXISTS reproduced VARCHAR(20)",
        "ALTER TABLE code_snippets ADD COLUMN IF NOT EXISTS sanitizer_log TEXT",
        "ALTER TABLE code_snippets ADD COLUMN IF NOT EXISTS poc_input TEXT",
        "ALTER TABLE code_snippets ADD COLUMN IF NOT EXISTS sanitizer_cwes JSONB",
        "ALTER TABLE code_snippets ADD COLUMN IF NOT EXISTS reproduce_attempts INTEGER NOT NULL DEFAULT 0",
        "CREATE INDEX IF NOT EXISTS ix_code_snippets_reproduced ON code_snippets (reproduced)",
        "CREATE INDEX IF NOT EXISTS ix_code_snippets_code_hash ON code_snippets (code_hash)",
        # Default ordering for /snippets, /seeds and every "most recent" view.
        "CREATE INDEX IF NOT EXISTS ix_snippets_updated_at ON code_snippets (updated_at DESC)",
        # Resume scans and the type+status dashboard filters; the leading columns
        # also serve type-only and type+status lookups.
        "CREATE INDEX IF NOT EXISTS ix_snippets_type_status_updated "
        "ON code_snippets (type, status, updated_at DESC)",
        # Status-only filters (dashboard) and status-ordered listings.
        "CREATE INDEX IF NOT EXISTS ix_snippets_status_updated "
        "ON code_snippets (status, updated_at DESC)",
        # The seeds page filters type='SEED' and sorts by updated_at.  Seeds are
        # the *oldest* rows, so walking ix_snippets_updated_at means skipping tens
        # of thousands of generated rows first — and the planner mis-estimates
        # that as cheap.  A partial index makes the seeds path unambiguously the
        # cheapest plan, in 392 kB.
        "CREATE INDEX IF NOT EXISTS ix_snippets_seed_updated "
        "ON code_snippets (updated_at DESC) WHERE type = 'SEED'",
        # The pairs self-join, child lookups, and the "verified but has no child"
        # queries.  Partial: only ~5% of rows are derived, so the index stays tiny.
        "CREATE INDEX IF NOT EXISTS ix_snippets_parent_uuid "
        "ON code_snippets (parent_uuid) WHERE parent_uuid IS NOT NULL",
        # Per-model filtering and the distinct-model startup check.
        "CREATE INDEX IF NOT EXISTS ix_snippets_generation_model "
        "ON code_snippets (generation_model)",
        # The CWE association's PK starts with code_snippet_uuid, so grouping by
        # cwe_id (the stats CWE distribution) had no usable index.
        "CREATE INDEX IF NOT EXISTS ix_snippet_cwe_cwe_id ON code_snippet_cwe (cwe_id)",
    ]

    def _apply_migrations(self):
        """Add post-deployment columns and indexes, idempotently.

        Every statement is IF NOT EXISTS, so agents starting concurrently are safe:
        the first one does the work and the rest are no-ops.
        """
        from sqlalchemy import text as _text
        with self.engine.connect() as conn:
            for ddl in self.MIGRATIONS:
                try:
                    conn.execute(_text(ddl))
                    conn.commit()
                except Exception as e:
                    # A concurrent creator can make CREATE INDEX IF NOT EXISTS race;
                    # the index exists either way, so this must not block startup.
                    conn.rollback()
                    self.log.warning(f"Migration step skipped ({e}): {ddl[:80]}")

    @contextmanager
    def session_scope(self):
        """Yield an independent session, committing on success and rolling back on error.

        Each call gets its **own** session rather than a thread-local one.  A
        thread-local session is shared by every coroutine running on that thread
        (the LLM agent gathers up to `llm_batch_size` coroutines per worker
        thread), so one finishing its scope would close the session another is
        still using.  A fresh session per scope also makes nesting safe.
        """
        session = self._session_factory()
        self.log.debug("Created new database session")
        try:
            yield session
            session.commit()
            self.log.debug("Session committed successfully")
        except Exception as e:
            self.log.error(f"Session error, rolling back: {str(e)}", exc_info=True)
            try:
                session.rollback()
            except Exception as rollback_err:
                self.log.warning(f"Rollback failed (connection likely dead): {rollback_err}")
            raise
        finally:
            session.close()
            self.log.debug("Session closed")

    def _execute_with_retry(self, fn, retries: int = 3, backoff: float = 1.0):
        """Run *fn(session)* inside a session, retrying on connection/pool errors.

        Covers a server-dropped connection (OperationalError/InterfaceError), a
        pool timeout (all slots occupied), and any DBAPIError SQLAlchemy has
        marked as a disconnect.  Each transient failure disposes of the broken
        connection so the next attempt gets a healthy one.

        Anything else — a bad value, a constraint violation, NUL bytes in text —
        propagates immediately: retrying cannot help, and swallowing it is how a
        failed write turns into a snippet that silently never moves again.
        """
        last_exc = None
        for attempt in range(retries):
            try:
                with self.session_scope() as session:
                    return fn(session)
            except Exception as e:
                if not _is_transient(e):
                    raise
                last_exc = e
                if not isinstance(e, SATimeoutError):
                    # The connection itself is broken: replace the pool so the next
                    # attempt does not pick the same dead connection back up.
                    # close=False leaves connections other threads are currently
                    # using alone — closing them would break healthy callers.
                    # A pool *timeout* is different: nothing is broken, the pool is
                    # merely busy, so disposing it would only punish other threads.
                    try:
                        self.engine.dispose(close=False)
                    except Exception as dispose_err:
                        self.log.debug(f"Engine dispose failed: {dispose_err}")
                if attempt < retries - 1:
                    delay = backoff * (2 ** attempt)
                    self.log.warning(
                        f"DB transient error (attempt {attempt + 1}/{retries}), "
                        f"retrying in {delay:.1f}s: {e}"
                    )
                    time.sleep(delay)
                else:
                    self.log.error(f"DB error after {retries} attempts: {e}", exc_info=True)
        raise last_exc

    # ------------------------------------------------------------------
    # Aggregate statistics
    #
    # Stats used to be maintained incrementally inside every create/update
    # transaction, with `SELECT ... FOR UPDATE` on the single Stats row.  That
    # made one row the serialisation point for the entire pipeline: every worker
    # thread in every agent process queued behind the same lock while holding a
    # pooled connection, which is how pool timeouts started being recorded as
    # snippet failures.  It also drifted, because a snippet re-verified after a
    # resume was counted twice.
    #
    # The counters are now derived on demand with grouped queries (tens of
    # milliseconds over this table) and cached in the Stats row for readers.
    # ------------------------------------------------------------------

    STATS_CACHE_TTL_SECONDS = 30

    def _compute_stats(self, session) -> Dict[str, Any]:
        """Derive every counter from the snippets table with grouped queries."""
        verification_statuses = [s.value for s in Status if s.value.startswith("VERIFICATION_")]

        status_counts = {
            status: count
            for status, count in session.query(CodeSnippet.status, func.count(CodeSnippet.uuid))
            .filter(CodeSnippet.status != Status.GROUND_TRUTH.value)
            .group_by(CodeSnippet.status)
        }
        model_counts = {
            model: count
            for model, count in session.query(
                CodeSnippet.generation_model, func.count(CodeSnippet.uuid)
            )
            .filter(CodeSnippet.status != Status.GROUND_TRUTH.value)
            .group_by(CodeSnippet.generation_model)
        }
        label_counts = {
            label: count
            for label, count in session.query(CodeSnippet.label, func.count(CodeSnippet.uuid))
            .filter(CodeSnippet.status.in_(verification_statuses))
            .group_by(CodeSnippet.label)
        }
        cwe_distribution = {
            cwe_id: count
            for cwe_id, count in session.query(
                code_snippet_cwe_association.c.cwe_id, func.count()
            )
            .join(
                CodeSnippet,
                CodeSnippet.uuid == code_snippet_cwe_association.c.code_snippet_uuid,
            )
            .filter(CodeSnippet.status.in_(verification_statuses))
            .group_by(code_snippet_cwe_association.c.cwe_id)
        }

        return {
            "total_snippets": sum(status_counts.values()),
            "status_counts": status_counts,
            "model_counts": model_counts,
            "label_counts": label_counts,
            "cwe_distribution": cwe_distribution,
            "vulnerable_count": label_counts.get(Label.VULNERABLE.value, 0),
            "safe_count": label_counts.get(Label.SAFE.value, 0),
        }

    def refresh_stats(self, session=None) -> Dict[str, Any]:
        """Recompute the aggregate counters and write them to the Stats row."""
        def _do(sess):
            values = self._compute_stats(sess)
            stats = sess.query(Stats).first()
            if not stats:
                stats = Stats()
                sess.add(stats)
            for field, value in values.items():
                setattr(stats, field, value)
            return values

        values = _do(session) if session is not None else self._execute_with_retry(_do)
        with self._stats_lock:
            self._stats_cache = values
            self._stats_cached_at = time.monotonic()
        return values

    def get_stats(self, max_age_seconds: Optional[float] = None) -> Dict[str, Any]:
        """Return the aggregate counters, recomputing them if the cache is stale."""
        ttl = self.STATS_CACHE_TTL_SECONDS if max_age_seconds is None else max_age_seconds
        with self._stats_lock:
            if self._stats_cache is not None and (time.monotonic() - self._stats_cached_at) < ttl:
                return self._stats_cache
        return self.refresh_stats()

    def create_snippet(self, snippet_data: dict) -> CodeSnippet:
        snippet_data = scrub_payload(snippet_data, self.log)
        uuid_to_check = snippet_data['uuid']
        self.log.info(f"Attempting to create or retrieve snippet: {uuid_to_check}")
        try:
            with self.session_scope() as session:
                existing_snippet = session.query(CodeSnippet).filter(CodeSnippet.uuid == uuid_to_check).one_or_none()

                if existing_snippet:
                    self.log.info(f"Snippet {uuid_to_check} already exists. Skipping creation.")
                    return existing_snippet

                self.log.info(f"Creating new snippet: {uuid_to_check}")

                cwe_objects = []
                if 'cwes' in snippet_data and snippet_data['cwes'] and isinstance(snippet_data['cwes'], str) : # Ensure cwes is a string
                    cwes_str = snippet_data['cwes']
                    cwe_id_list = [c_id.strip() for c_id in cwes_str.split(',') if c_id.strip()]
                    for cwe_id_str in cwe_id_list:
                        cwe_instance = session.query(CWE).filter_by(id=cwe_id_str).first()
                        if not cwe_instance:
                            self.log.info(f"CWE with id '{cwe_id_str}' not found. Creating new CWE entry.")
                            cwe_instance = CWE(id=cwe_id_str, name=cwe_id_str, description=f"Description for {cwe_id_str} (auto-created)")
                            session.add(cwe_instance)
                        cwe_objects.append(cwe_instance)
                
                info = snippet_data.get('info', "")
                project = snippet_data.get('project', "")
                commit_message = snippet_data.get('commit_message', "")
                metrics = snippet_data.get('metrics', {})
                install_command = snippet_data.get('install_command', "# No command found")
                slice_code = snippet_data.get('slice_code', None)
                dataset = snippet_data.get('dataset', None)
                repo_url = snippet_data.get('repo_url', None)
                commit_hash = snippet_data.get('commit_hash', None)
                cve = snippet_data.get('cve', None)

                new_snippet = CodeSnippet(
                    uuid=uuid_to_check,
                    seed_uuid=snippet_data['seed_uuid'],
                    parent_uuid=snippet_data.get('parent_uuid'),
                    generation_model=snippet_data['generation_model'],
                    code=snippet_data['code'],
                    code_hash=snippet_data.get('code_hash') or _sha256_code(snippet_data['code']),
                    slice_code=slice_code,
                    status=Status[snippet_data['status'].upper()].value,
                    label=Label[snippet_data['label'].upper()].value,
                    type=Type[snippet_data['snippet_type'].upper()].value,
                    language=snippet_data['language'],
                    info=info,
                    project=project,
                    cwes=cwe_objects,
                    commit_message=commit_message,
                    commit_hash=commit_hash,
                    metrics=metrics,
                    install_command=install_command,
                    dataset=dataset,
                    repo_url=repo_url,
                    cve=cve,
                    reproduce_attempts=int(snippet_data.get('reproduce_attempts') or 0),
                )
                session.add(new_snippet)
                session.flush()  # Materialise server_defaults (created_at) without committing yet
                session.refresh(new_snippet)
                # No stats mutation here on purpose — see the aggregate-statistics
                # note above.  session_scope commits everything atomically.

                self.log.info(f"Created snippet with UUID: {new_snippet.uuid}")
                # Expunge the object after creation to detach it from the session
                session.expunge(new_snippet) 
                return new_snippet
        except Exception as e:
            self.log.error(f"Failed to create or retrieve snippet {uuid_to_check}: {str(e)}", exc_info=True)
            raise

    def increment_pair_attempts(self, uuid: str) -> int:
        """Atomically add one counterpart attempt to *uuid*; returns the new count."""
        def _do(session):
            row = session.query(CodeSnippet).filter(CodeSnippet.uuid == uuid).with_for_update().first()
            if not row:
                return 0
            row.pair_attempts = (row.pair_attempts or 0) + 1
            return row.pair_attempts
        return self._execute_with_retry(_do)

    def increment_attempt_count(self, uuid: str) -> int:
        try:
            with self.session_scope() as session:
                snippet = session.query(CodeSnippet).filter(CodeSnippet.uuid == uuid).first()
                if snippet:
                    snippet.attempt_count = (snippet.attempt_count or 0) + 1 # Ensure not None
                    self.log.info(f"Incremented attempt count for {uuid} to {snippet.attempt_count}")
                    return snippet.attempt_count
                self.log.warning(f"Attempted to increment attempt count for non-existent snippet {uuid}")
                return 0
        except Exception as e:
            self.log.error(f"Failed to increment attempt count for {uuid}: {str(e)}", exc_info=True)
            return 0
    
    def update_snippet(self, uuid: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Apply *metadata* to a snippet.

        Returns True on success and False only when the snippet does not exist.
        Every other failure **raises** — a write that silently reports failure is
        how a snippet ends up frozen in a stage with nothing in the logs tying it
        to the cause.  Transient connection/pool errors are retried first by
        _execute_with_retry.
        """
        metadata = scrub_payload(metadata, self.log)

        def _do(session):
            snippet = session.query(CodeSnippet).filter(CodeSnippet.uuid == uuid).first()
            if not snippet:
                self.log.warning(f"Attempted to update non-existent snippet {uuid}")
                return False

            if metadata:
                field_config = {
                    'esbmc_log': {'type': 'regular'},
                    'witness':   {'type': 'regular'},
                    'language': {'type': 'regular'},
                    'compilation_log': {'type': 'regular'},
                    'info': {'type': 'regular'},
                    'attempt_count': {'type': 'regular'},
                    'cwes': {'type': 'relationship', 'model': CWE, 'key_field': 'id'},
                    'commit_message': {'type': 'regular'},
                    'install_command': {'type': 'regular'},
                    'code': {'type': 'regular'},
                    'metrics': {'type': 'regular'},
                    'parent_uuid': {'type': 'regular'},
                    'verification_meta': {'type': 'regular'},
                    'esbmc_cwes': {'type': 'regular'},
                    'verified_code_hash': {'type': 'regular'},
                    'pair_attempts': {'type': 'regular'},
                    # 'regular', not 'enum': None (no reproduction for this label) must be settable
                    'reproduced': {'type': 'regular'},
                    'sanitizer_log': {'type': 'regular'},
                    'poc_input': {'type': 'regular'},
                    'sanitizer_cwes': {'type': 'regular'},
                    'reproduce_attempts': {'type': 'regular'},
                    'label': {'type': 'enum', 'enum_class': Label},
                    'status': {'type': 'enum', 'enum_class': Status},
                    'type': {'type': 'enum', 'enum_class': Type}
                }

                # code change without a fresh verdict invalidates the stored verdict
                if 'code' in metadata and metadata['code'] is not None \
                        and metadata['code'] != snippet.code:
                    snippet.code_hash = _sha256_code(metadata['code'])
                    carries_verdict = 'verified_code_hash' in metadata
                    if not carries_verdict and (
                            snippet.label in (Label.SAFE.value, Label.VULNERABLE.value)
                            or snippet.esbmc_log or snippet.verified_code_hash):
                        self.log.info(f"Code of {uuid} changed after verification; clearing its verdict")
                        snippet.label = Label.UNKNOWN.value
                        snippet.esbmc_log = None
                        snippet.witness = None
                        snippet.verification_meta = None
                        snippet.esbmc_cwes = None
                        snippet.verified_code_hash = None
                        snippet.reproduced = None
                        snippet.sanitizer_log = None
                        snippet.poc_input = None
                        snippet.sanitizer_cwes = None
                        if snippet.type != Type.SEED.value:
                            snippet.cwes = []
                        if 'status' not in metadata:
                            snippet.status = Status.GENERATION_SUCCESS.value

                for field, config in field_config.items():
                    if field in metadata:
                        value_from_metadata = metadata[field]

                        if config['type'] == 'regular':
                            setattr(snippet, field, value_from_metadata)
                        elif config['type'] == 'enum':
                            enum_class = config['enum_class']
                            resolved_enum_member = None
                            if isinstance(value_from_metadata, enum_class):
                                resolved_enum_member = value_from_metadata
                            elif isinstance(value_from_metadata, str):
                                try:
                                    resolved_enum_member = enum_class[value_from_metadata.upper()]
                                except KeyError:
                                    try:
                                        resolved_enum_member = enum_class(value_from_metadata)
                                    except ValueError:
                                        self.log.warning(
                                            f"String value '{value_from_metadata}' is not a valid name or value for enum {enum_class.__name__} for field '{field}'.")
                            else:
                                try:
                                    resolved_enum_member = enum_class(value_from_metadata)
                                except ValueError:
                                    self.log.warning(
                                        f"Value '{value_from_metadata}' (type: {type(value_from_metadata)}) "
                                        f"could not be converted to enum {enum_class.__name__} for field '{field}'.")

                            if resolved_enum_member is not None:
                                setattr(snippet, field, resolved_enum_member.value)
                            else:
                                self.log.warning(f"Failed to set enum field '{field}' with value '{value_from_metadata}'. Invalid or unresolvable enum value.")
                        elif config['type'] == 'relationship' and field == 'cwes':
                            if isinstance(value_from_metadata, str) and value_from_metadata:
                                cwe_id_list = [c_id.strip() for c_id in value_from_metadata.split(',') if c_id.strip()]
                                cwe_objects = []
                                for cwe_id_str in cwe_id_list:
                                    cwe_instance = session.query(CWE).filter_by(id=cwe_id_str).first()
                                    if not cwe_instance:
                                        self.log.info(f"CWE with id '{cwe_id_str}' not found during update. Creating new CWE entry.")
                                        cwe_instance = CWE(id=cwe_id_str, name=cwe_id_str, description=f"Description for {cwe_id_str} (auto-created during update)")
                                        session.add(cwe_instance)
                                    cwe_objects.append(cwe_instance)
                                snippet.cwes = cwe_objects
                            elif isinstance(value_from_metadata, list) and all(isinstance(item, CWE) for item in value_from_metadata):
                                snippet.cwes = value_from_metadata
                            elif value_from_metadata is None:
                                snippet.cwes = []
                            else:
                                self.log.warning(f"Invalid CWEs data type for update: {type(value_from_metadata)}")

            self.log.info(f"Successfully updated snippet {uuid} with metadata: {list(metadata.keys()) if metadata else 'No metadata'}")
            return True

        try:
            return self._execute_with_retry(_do)
        except Exception as e:
            # Logged here for context, then re-raised so the caller can decide
            # between re-queuing the message and recording the snippet as needing
            # a resume — silently returning False hid real write failures.
            self.log.error(f"Failed to update snippet {uuid}: {str(e)}", exc_info=True)
            raise

    def delete_snippet(self, uuid: str) -> bool:
        """Delete a derived snippet that did not form a valid pair.

        Refuses to delete if the snippet has children (FK constraint) — in that
        case the caller should leave it in the DB; the pairs API already filters
        it out.  CWE association rows are removed automatically by SQLAlchemy
        before the snippet row itself is deleted.
        """
        try:
            with self.session_scope() as session:
                snippet = session.query(CodeSnippet).filter(CodeSnippet.uuid == uuid).first()
                if not snippet:
                    return False
                children_count = session.query(func.count(CodeSnippet.uuid)).filter(
                    CodeSnippet.parent_uuid == uuid
                ).scalar()
                if children_count:
                    self.log.warning(
                        f"Cannot delete snippet {uuid}: has {children_count} child(ren). "
                        f"Leaving in DB — pairs API will filter it out."
                    )
                    return False
                session.delete(snippet)
                self.log.info(f"Deleted non-conclusive derived snippet {uuid}")
                return True
        except Exception as e:
            self.log.error(f"Failed to delete snippet {uuid}: {str(e)}", exc_info=True)
            return False

    def get_snippet(self, uuid: str):
        def _query(session):
            snippet = (
                session.query(CodeSnippet)
                .options(joinedload(CodeSnippet.cwes))
                .filter(CodeSnippet.uuid == uuid)
                .first()
            )
            if snippet:
                for cwe in snippet.cwes:
                    session.expunge(cwe)
                session.expunge(snippet)
            return snippet

        return self._execute_with_retry(_query)

    def get_snippets_by_seed(self, seed_uuid: str) -> List[CodeSnippet]:
        self.log.debug(f"Fetching snippets for seed hash: {seed_uuid}")
        try:
            with self.session_scope() as session:
                snippets = session.query(CodeSnippet).filter_by(seed_uuid=seed_uuid).all()
                # FIX: Expunge each snippet from the session before returning
                expunged_snippets = []
                for snippet in snippets:
                    session.expunge(snippet)
                    expunged_snippets.append(snippet)
                self.log.debug(f"Found {len(expunged_snippets)} snippets for seed hash: {seed_uuid}")
                return expunged_snippets
        except Exception as e:
            self.log.error(f"Error fetching snippets for seed {seed_uuid}: {str(e)}", exc_info=True)
            raise

    def get_vulnerable_snippets(self) -> List[CodeSnippet]:
        self.log.info("Fetching vulnerable snippets")
        try:
            with self.session_scope() as session:
                snippets = session.query(CodeSnippet).filter_by(
                    label=Label.VULNERABLE.value,
                    status=Status.VERIFICATION_SUCCESS.value
                ).all()
                expunged_snippets = []
                for snippet in snippets:
                    session.expunge(snippet)
                    expunged_snippets.append(snippet)
                self.log.info(f"Found {len(expunged_snippets)} vulnerable snippets")
                return expunged_snippets
        except Exception as e:
            self.log.error(f"Error fetching vulnerable snippets: {str(e)}", exc_info=True)
            raise

    def get_child_snippets(self, parent_uuid: str) -> List[CodeSnippet]:
        self.log.debug(f"Fetching child snippets for parent: {parent_uuid}")
        try:
            with self.session_scope() as session:
                snippets = session.query(CodeSnippet).filter_by(parent_uuid=parent_uuid).all()
                expunged_snippets = []
                for snippet in snippets:
                    session.expunge(snippet)
                    expunged_snippets.append(snippet)
                self.log.debug(f"Found {len(expunged_snippets)} child snippets")
                return expunged_snippets
        except Exception as e:
            self.log.error(f"Error fetching child snippets for {parent_uuid}: {str(e)}", exc_info=True)
            raise

    def export_to_jsonl(self, filepath: str):
        self.log.info(f"Exporting database to JSONL: {filepath}")
        import json
        try:
            with self.session_scope() as session:
                snippets = session.query(CodeSnippet).all()
                self.log.info(f"Exporting {len(snippets)} snippets")
                with open(filepath, 'w') as f:
                    for i, snippet in enumerate(snippets, 1):
                        # Prepare CWEs for JSON export (list of IDs)
                        cwe_ids = [cwe.id for cwe in snippet.cwes] if snippet.cwes else []
                        json_data = {
                            'uuid': snippet.uuid,
                            'seed_uuid': snippet.seed_uuid,
                            'generation_model': snippet.generation_model,
                            'code': snippet.code,
                            'label': snippet.label,
                            'status': snippet.status,
                            'type': snippet.type,
                            'compilation_log': snippet.compilation_log,
                            'esbmc_log': snippet.esbmc_log,
                            'parent_uuid': snippet.parent_uuid,
                            'attempt_count': snippet.attempt_count,
                            'metrics': snippet.metrics,
                            'created_at': snippet.created_at.isoformat() if snippet.created_at else None,
                            'updated_at': snippet.updated_at.isoformat() if snippet.updated_at else None,
                            'cwes': cwe_ids,
                            'project': snippet.project,
                            'language': snippet.language,
                            'info': snippet.info,
                            'commit_message': snippet.commit_message,
                            'install_command': snippet.install_command
                        }
                        json.dump(json_data, f)
                        f.write('\n')
                        if i % 1000 == 0:
                            self.log.debug(f"Exported {i} snippets...")
                self.log.info(f"Successfully exported {len(snippets)} snippets to {filepath}")
        except Exception as e:
            self.log.error(f"Failed to export database: {str(e)}", exc_info=True)
            raise