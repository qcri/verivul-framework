from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional, Dict, Any, Callable, TypeVar
from sqlalchemy import desc, func
from sqlalchemy.exc import OperationalError, TimeoutError as SATimeoutError
import asyncio
import os
import sys
import json
import docker as docker_sdk
from starlette.concurrency import run_in_threadpool

_T = TypeVar("_T")

# Add the project root to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from sqlalchemy.orm import joinedload
from src.db.database import DatabaseManager
from src.db.models import Status, Label, CodeSnippet, Stats, CWE, code_snippet_cwe_association
from src.web.api.schemas import (
    CodeSnippetResponse,
    StatsResponse,
    StatusCountResponse,
    ModelsResponse,
    CodeSnippetConciseResponse,
    ExtendedStatsResponse,
    MetricStats,
    PairResponse,
    PairSnippet,
)
from src.utils.docker_cleanup import OWNER_LABEL, OWNER_VALUE, ROLE_LABEL, _label_sets
from src.utils.logger import logger
from config.settings import settings

log = logger.get_logger("api_routes")

router = APIRouter(tags=["snippets"])

# Initialize database manager
db_manager = DatabaseManager(caller="APIAgent")


# ---------------------------------------------------------------------------
# Response cache for the polled aggregate endpoints
#
# The dashboard polls /stats and /extended-stats every 30 s and /resources every
# 5 s.  The aggregate endpoints each run several full-table scans (the metrics
# aggregate alone is ~130 ms), and every open browser tab multiplied that load.
# A short TTL keeps the numbers live while collapsing concurrent pollers onto one
# query: the lock means N simultaneous requests compute the result once.
# ---------------------------------------------------------------------------

AGGREGATE_CACHE_TTL_SECONDS = 20


class _TTLCache:
    def __init__(self):
        self.value = None
        self.stamp = 0.0
        self.lock = asyncio.Lock()


_EXTENDED_STATS_CACHE = _TTLCache()
_STATS_CACHE = _TTLCache()


async def _cached(cache: _TTLCache, produce: Callable, ttl: float = AGGREGATE_CACHE_TTL_SECONDS):
    """Return a cached value, recomputing it at most once per *ttl* seconds."""
    now = asyncio.get_event_loop().time()
    if cache.value is not None and (now - cache.stamp) < ttl:
        return cache.value
    async with cache.lock:
        # Another request may have refreshed it while this one waited for the lock.
        now = asyncio.get_event_loop().time()
        if cache.value is not None and (now - cache.stamp) < ttl:
            return cache.value
        cache.value = await produce()
        cache.stamp = now
        return cache.value


async def _db_execute(fn: Callable, retries: int = 3, backoff: float = 1.0) -> _T:
    """Run *fn(session)* with async-friendly retry on connection/pool errors.

    Mirrors DatabaseManager._execute_with_retry but uses asyncio.sleep so the
    event loop stays unblocked during the backoff delay.
    """
    def _run():
        with db_manager.session_scope() as session:
            return fn(session)

    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            # SQLAlchemy here is synchronous: calling it inline would block the
            # event loop for the whole query, stalling every other request.
            # session_scope() hands out an independent session, so running it on
            # a worker thread is safe.
            return await run_in_threadpool(_run)
        except (OperationalError, SATimeoutError) as e:
            last_exc = e
            db_manager.Session.remove()
            if attempt < retries - 1:
                delay = backoff * (2 ** attempt)
                log.warning(
                    f"DB transient error (attempt {attempt + 1}/{retries}), "
                    f"retrying in {delay:.1f}s: {e}"
                )
                await asyncio.sleep(delay)
            else:
                log.error(f"DB error after {retries} attempts: {e}", exc_info=True)
    raise last_exc

@router.get("/snippets", response_model=List[CodeSnippetConciseResponse])
async def get_snippets(
    skip: int = 0,
    limit: int = 20,
    type: Optional[str] = None,
    seed_uuid: Optional[str] = None,
    status: Optional[str] = None,
    label: Optional[str] = None,
    model: Optional[str] = None,
    language: Optional[str] = None,
    dataset: Optional[str] = None,
    cve: Optional[str] = None,
    reproduced: Optional[str] = None,
    sort_by: str = "updated_at",
    sort_desc: bool = True
):
    """Get code snippets with optional filtering."""
    def _query(session):
        query = session.query(
            CodeSnippet.uuid,
            CodeSnippet.seed_uuid,
            CodeSnippet.generation_model,
            CodeSnippet.label,
            CodeSnippet.type,
            CodeSnippet.status,
            CodeSnippet.attempt_count,
            CodeSnippet.esbmc_cwes,
            CodeSnippet.reproduced,
            CodeSnippet.language,
            CodeSnippet.project,
            CodeSnippet.dataset,
            CodeSnippet.cve,
            CodeSnippet.commit_hash,
            CodeSnippet.repo_url,
            CodeSnippet.created_at,
            CodeSnippet.updated_at,
        )

        if type:
            query = query.filter(CodeSnippet.type == type)
        if seed_uuid:
            query = query.filter(CodeSnippet.seed_uuid == seed_uuid)
        if status:
            query = query.filter(CodeSnippet.status == status)
        if label:
            query = query.filter(CodeSnippet.label == label)
        if model:
            query = query.filter(CodeSnippet.generation_model == model)
        if language:
            query = query.filter(CodeSnippet.language == language)
        if dataset:
            query = query.filter(CodeSnippet.dataset == dataset)
        if cve:
            query = query.filter(CodeSnippet.cve.ilike(f"%{cve}%"))
        if reproduced:
            query = query.filter(CodeSnippet.reproduced == reproduced)

        sort_col = getattr(CodeSnippet, sort_by, None)
        if sort_col is not None:
            query = query.order_by(desc(sort_col) if sort_desc else sort_col)
        else:
            query = query.order_by(desc(CodeSnippet.updated_at))

        snippets = query.offset(skip).limit(limit).all()

        result = []
        for row in snippets:
            result.append({
                "uuid": row.uuid,
                "seed_uuid": row.seed_uuid,
                "generation_model": row.generation_model,
                "label": row.label,
                "type": row.type,
                "status": row.status,
                "attempt_count": row.attempt_count,
                "cwes": [],
                "esbmc_cwes": row.esbmc_cwes,
                "reproduced": row.reproduced,
                "language": row.language,
                "project": row.project,
                "dataset": row.dataset,
                "cve": row.cve,
                "commit_hash": row.commit_hash,
                "repo_url": row.repo_url,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            })

        if result:
            uuids = [r["uuid"] for r in result]
            cwe_rows = session.query(
                code_snippet_cwe_association.c.code_snippet_uuid,
                code_snippet_cwe_association.c.cwe_id
            ).filter(code_snippet_cwe_association.c.code_snippet_uuid.in_(uuids)).all()
            cwe_map: dict = {}
            for snippet_uuid, cwe_id in cwe_rows:
                cwe_map.setdefault(snippet_uuid, []).append(cwe_id)
            for r in result:
                r["cwes"] = cwe_map.get(r["uuid"], [])

        return result

    try:
        result = await _db_execute(_query)
        log.info(f"Found {len(result)} valid snippets")
        return result
    except Exception as e:
        log.error(f"Error fetching snippets: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/snippets/{uuid}", response_model=CodeSnippetResponse)
async def get_snippet(uuid: str):
    """Get a specific code snippet by UUID."""
    log.info(f"Fetching snippet with UUID: {uuid}")

    def _query(session):
        snippet = (
            session.query(CodeSnippet)
            .options(joinedload(CodeSnippet.cwes))
            .filter(CodeSnippet.uuid == uuid)
            .first()
        )
        if not snippet:
            return None
        result = {c.name: getattr(snippet, c.name) for c in snippet.__table__.columns}
        result["cwes"] = [cwe.id for cwe in snippet.cwes]
        return result

    try:
        result = await _db_execute(_query)
        if result is None:
            log.warning(f"Snippet with UUID {uuid} not found")
            raise HTTPException(status_code=404, detail=f"Snippet with UUID {uuid} not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error fetching snippet {uuid}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/snippets/{uuid}/children", response_model=List[CodeSnippetResponse])
async def get_children(uuid: str):
    """Get all child snippets for a given parent UUID."""
    log.info(f"Fetching children for parent UUID: {uuid}")

    def _query(session):
        children = session.query(CodeSnippet).filter(CodeSnippet.parent_uuid == uuid).all()
        result = []
        for child in children:
            try:
                result.append({c.name: getattr(child, c.name) for c in child.__table__.columns})
            except Exception as exc:
                log.error(f"Error processing child snippet: {exc}", exc_info=True)
        return result

    try:
        result = await _db_execute(_query)
        log.info(f"Found {len(result)} children for parent {uuid}")
        return result
    except Exception as e:
        log.error(f"Error fetching children for {uuid}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Get overall statistics about the database."""
    log.info("Fetching overall statistics")

    def _query(session):
        # Derived from the snippets table (cached for a few seconds), not
        # maintained incrementally on the write path — see
        # DatabaseManager.refresh_stats for why.
        return db_manager.refresh_stats(session)

    try:
        # Cached: without it every poll from every open tab re-ran the aggregate
        # scans *and* rewrote the Stats row.
        data = await _cached(_STATS_CACHE, lambda: _db_execute(_query))
        if not data:
            return StatsResponse(
                total_snippets=0,
                status_counts=[],
                label_counts={},
                model_counts={},
                vulnerable_count=0,
                safe_count=0,
                cwe_distribution={},
            )
        status_data = [
            StatusCountResponse(status=s, count=c)
            for s, c in (data["status_counts"] or {}).items()
        ]
        return StatsResponse(
            total_snippets=data["total_snippets"],
            status_counts=status_data,
            label_counts=data["label_counts"] or {},
            model_counts=data["model_counts"] or {},
            vulnerable_count=data["vulnerable_count"],
            safe_count=data["safe_count"],
            cwe_distribution=data["cwe_distribution"] or {},
        )
    except Exception as e:
        log.error(f"Error fetching stats: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/languages")
async def get_languages():
    """Return all distinct non-null languages present in the database."""
    def _query(session):
        rows = (
            session.query(CodeSnippet.language)
            .filter(CodeSnippet.language.isnot(None))
            .distinct()
            .all()
        )
        return sorted(r[0] for r in rows if r[0])

    try:
        return {"languages": await _db_execute(_query)}
    except Exception as e:
        log.error(f"Error fetching languages: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/models", response_model=ModelsResponse)
async def get_models():
    """Get list of all unique model names."""
    log.info("Fetching unique model names")

    def _query(session):
        rows = (
            session.query(CodeSnippet.generation_model)
            .filter(CodeSnippet.type == "GENERATED", CodeSnippet.generation_model.isnot(None))
            .distinct()
            .all()
        )
        return [r[0] for r in rows if r[0] is not None]

    try:
        model_names = await _db_execute(_query)
        log.info(f"Found {len(model_names)} unique models")
        return ModelsResponse(models=model_names)
    except Exception as e:
        log.error(f"Error fetching models: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/extended-stats", response_model=ExtendedStatsResponse)
async def get_extended_stats():
    """Aggregate metrics stats, CWE distribution, and language distribution for SAFE+VULNERABLE snippets."""
    from sqlalchemy import cast, Float, text, case

    def _query(session):
        LABELS = ["SAFE", "VULNERABLE"]
        base = (CodeSnippet.type == "GENERATED", CodeSnippet.label.in_(LABELS))

        counts = session.query(
            func.count(case((CodeSnippet.label == "SAFE", 1))),
            func.count(case((CodeSnippet.label == "VULNERABLE", 1))),
        ).filter(*base).one()
        total_safe, total_vulnerable = int(counts[0]), int(counts[1])

        agg = session.execute(text("""
            SELECT
                MIN((metrics->>'loc')::float), MAX((metrics->>'loc')::float), AVG((metrics->>'loc')::float),
                MIN((metrics->>'cc')::float),  MAX((metrics->>'cc')::float),  AVG((metrics->>'cc')::float),
                MIN((metrics->>'nd')::float),  MAX((metrics->>'nd')::float),  AVG((metrics->>'nd')::float)
            FROM code_snippets
            WHERE type = 'GENERATED'
              AND label IN ('SAFE', 'VULNERABLE')
              AND metrics IS NOT NULL
        """)).one()

        def _round(v):
            return round(float(v), 1) if v is not None else None

        cwe_rows = (
            session.query(
                code_snippet_cwe_association.c.cwe_id,
                func.count(code_snippet_cwe_association.c.cwe_id)
            )
            .join(CodeSnippet, CodeSnippet.uuid == code_snippet_cwe_association.c.code_snippet_uuid)
            .filter(
                CodeSnippet.label == "VULNERABLE",
                CodeSnippet.type == "GENERATED",
                CodeSnippet.status == "VERIFICATION_SUCCESS",
            )
            .group_by(code_snippet_cwe_association.c.cwe_id)
            .order_by(func.count(code_snippet_cwe_association.c.cwe_id).desc())
            .all()
        )

        lang_rows = (
            session.query(CodeSnippet.language, func.count(CodeSnippet.uuid))
            .filter(*base)
            .group_by(CodeSnippet.language)
            .order_by(func.count(CodeSnippet.uuid).desc())
            .all()
        )

        comp_counts = session.execute(text("""
            SELECT
                SUM(CASE WHEN status IN (
                        'COMPILATION_SUCCESS','VERIFICATION_SUCCESS',
                        'VERIFICATION_ERROR','VERIFICATION_TIMEOUT'
                    ) THEN 1 ELSE 0 END) AS success,
                SUM(CASE WHEN status = 'COMPILATION_FAILED' THEN 1 ELSE 0 END) AS fail
            FROM code_snippets
            WHERE type = 'GENERATED'
        """)).one()

        compile_success = int(comp_counts[0] or 0)
        compile_fail    = int(comp_counts[1] or 0)
        compile_total   = compile_success + compile_fail

        return {
            "total_safe": total_safe,
            "total_vulnerable": total_vulnerable,
            "loc": (_round(agg[0]), _round(agg[1]), _round(agg[2])),
            "cc":  (_round(agg[3]), _round(agg[4]), _round(agg[5])),
            "nd":  (_round(agg[6]), _round(agg[7]), _round(agg[8])),
            "cwe_dist": {row[0]: row[1] for row in cwe_rows},
            "lang_dist": {(row[0] or "unknown"): row[1] for row in lang_rows},
            "compile_success": compile_success,
            "compile_fail": compile_fail,
            "compilation_rate": round(compile_success / compile_total, 4) if compile_total else None,
        }

    try:
        d = await _cached(_EXTENDED_STATS_CACHE, lambda: _db_execute(_query))
        return ExtendedStatsResponse(
            total_safe=d["total_safe"],
            total_vulnerable=d["total_vulnerable"],
            loc=MetricStats(min=d["loc"][0], max=d["loc"][1], mean=d["loc"][2]),
            cc=MetricStats(min=d["cc"][0],  max=d["cc"][1],  mean=d["cc"][2]),
            nd=MetricStats(min=d["nd"][0],  max=d["nd"][1],  mean=d["nd"][2]),
            cwe_distribution_vulnerable=d["cwe_dist"],
            language_distribution=d["lang_dist"],
            compile_success=d["compile_success"],
            compile_fail=d["compile_fail"],
            compilation_rate=d["compilation_rate"],
        )
    except Exception as e:
        log.error(f"Error fetching extended stats: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/pairs", response_model=List[PairResponse])
async def get_pairs(
    skip: int = 0,
    limit: int = 50,
    pair_type: Optional[str] = None,
    language: Optional[str] = None,
):
    """Return conclusive fix/injection pairs only.

    Included:  VULNERABLE → SAFE  (fix worked)
               SAFE → VULNERABLE  (injection worked)
    Excluded:  same label on both sides, or either side is UNKNOWN.
    """
    from sqlalchemy.orm import aliased

    def _query(session):
        Parent = aliased(CodeSnippet, flat=True)

        query = (
            session.query(CodeSnippet)
            .join(Parent, Parent.uuid == CodeSnippet.parent_uuid)
            .options(joinedload(CodeSnippet.cwes))
            .filter(
                CodeSnippet.parent_uuid.isnot(None),
                CodeSnippet.type == "GENERATED",
                CodeSnippet.label.in_(["SAFE", "VULNERABLE"]),
                Parent.label.in_(["SAFE", "VULNERABLE"]),
                CodeSnippet.label != Parent.label,
            )
        )
        if language:
            query = query.filter(CodeSnippet.language == language)
        if pair_type == "fix":
            query = query.filter(CodeSnippet.label == "SAFE", Parent.label == "VULNERABLE")
        elif pair_type == "injection":
            query = query.filter(CodeSnippet.label == "VULNERABLE", Parent.label == "SAFE")

        # Ordered by updated_at like every other listing: a pair's row changes
        # when it is re-verified, and the most recently touched pairs are the ones
        # worth looking at first.
        derived_snippets = (
            query.order_by(desc(CodeSnippet.updated_at)).offset(skip).limit(limit).all()
        )

        parent_uuids = [s.parent_uuid for s in derived_snippets]
        parents = {}
        if parent_uuids:
            parent_rows = (
                session.query(CodeSnippet)
                .options(joinedload(CodeSnippet.cwes))
                .filter(CodeSnippet.uuid.in_(parent_uuids))
                .all()
            )
            parents = {p.uuid: p for p in parent_rows}

        def _to_snippet_dict(s: CodeSnippet) -> dict:
            return {
                "uuid": s.uuid,
                "label": s.label,
                "status": s.status,
                "generation_model": s.generation_model,
                "cwes": [cwe.id for cwe in s.cwes],
                "esbmc_cwes": s.esbmc_cwes,
                "language": s.language,
                "created_at": s.created_at,
                "updated_at": s.updated_at,
            }

        result = []
        for derived in derived_snippets:
            parent = parents.get(derived.parent_uuid)
            if not parent:
                continue
            pt = "fix" if parent.label == "VULNERABLE" else "injection"
            result.append({
                "pair_type": pt,
                "seed_uuid": derived.seed_uuid,
                "original": _to_snippet_dict(parent),
                "derived": _to_snippet_dict(derived),
            })
        return result

    try:
        rows = await _db_execute(_query)
        result = [
            PairResponse(
                pair_type=r["pair_type"],
                seed_uuid=r["seed_uuid"],
                original=PairSnippet(**r["original"]),
                derived=PairSnippet(**r["derived"]),
            )
            for r in rows
        ]
        log.info(f"Returning {len(result)} pairs")
        return result
    except Exception as e:
        log.error(f"Error fetching pairs: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@router.get("/pairs/count")
async def get_pairs_count(
    pair_type: Optional[str] = None,
    language: Optional[str] = None,
):
    """Return the total number of conclusive pairs in the DB (no pagination)."""
    from sqlalchemy.orm import aliased

    def _query(session):
        Parent = aliased(CodeSnippet, flat=True)
        query = (
            session.query(func.count(CodeSnippet.uuid))
            .join(Parent, Parent.uuid == CodeSnippet.parent_uuid)
            .filter(
                CodeSnippet.parent_uuid.isnot(None),
                CodeSnippet.type == "GENERATED",
                CodeSnippet.label.in_(["SAFE", "VULNERABLE"]),
                Parent.label.in_(["SAFE", "VULNERABLE"]),
                CodeSnippet.label != Parent.label,
            )
        )
        if language:
            query = query.filter(CodeSnippet.language == language)
        if pair_type == "fix":
            query = query.filter(CodeSnippet.label == "SAFE", Parent.label == "VULNERABLE")
        elif pair_type == "injection":
            query = query.filter(CodeSnippet.label == "VULNERABLE", Parent.label == "SAFE")
        return query.scalar() or 0

    try:
        total = await _db_execute(_query)
        return {"total": total}
    except Exception as e:
        log.error(f"Error counting pairs: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

_docker_client = None


def _get_docker_client():
    """Return a shared Docker client.

    `/resources` is polled every 5 s; rebuilding the client per request re-read
    the environment and opened a fresh socket connection each time.
    """
    global _docker_client
    if _docker_client is None:
        _docker_client = docker_sdk.from_env()
    return _docker_client


@router.get("/resources")
async def get_resources():
    """Live resource utilisation — queries Docker for running verivul containers."""
    rm = settings.resource_management
    compilation_total  = rm.get('compilation_slots', 4)
    verification_total = rm.get('verification_slots', 4)

    try:
        # Filter by label on the daemon instead of listing every container on the
        # host and matching name prefixes in Python: ~164 ms -> ~7 ms per poll on
        # a box with 50 unrelated containers.
        client = _get_docker_client()
        containers = []
        seen = set()
        # Include the pre-rename labels so containers started by a process that
        # predates the rename still show up while the pipeline drains.
        for owner_label, owner_value, _pid, _role in _label_sets():
            for c in client.containers.list(filters={"label": f"{owner_label}={owner_value}"}):
                if c.id not in seen:
                    seen.add(c.id)
                    containers.append(c)
    except Exception as e:
        global _docker_client
        log.warning(f"Docker unavailable for resource query: {e}")
        _docker_client = None  # force a rebuild on the next poll
        return {
            "compilation":  {"total": compilation_total,  "active": 0, "free": compilation_total},
            "verification": {"total": verification_total, "active": 0, "free": verification_total},
            "docker_available": False,
        }

    def _by_role(*roles):
        return [
            {"name": c.name, "status": c.status}
            for c in containers
            if any((c.labels or {}).get(role_label) in roles
                   for *_ignored, role_label in _label_sets())
        ]

    # Roles cover both the agents and scripts/resume_stuck_snippets.py, which does
    # the same work out of band.
    compiler_containers = _by_role("compiler", "resume-compile")
    esbmc_containers = _by_role("esbmc", "resume-esbmc")

    return {
        "compilation": {
            "total":      compilation_total,
            "active":     len(compiler_containers),
            "free":       max(0, compilation_total - len(compiler_containers)),
            "containers": compiler_containers,
        },
        "verification": {
            "total":      verification_total,
            "active":     len(esbmc_containers),
            "free":       max(0, verification_total - len(esbmc_containers)),
            "containers": esbmc_containers,
        },
        "docker_available": True,
    }