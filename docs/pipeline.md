# Pipeline operation

## Running

```bash
# Populate from a dataset and start the agents
python main.py /path/to/dataset.jsonl

# Resume all stages (re-queues anything stuck mid-pipeline)
python main.py /path/to/dataset.jsonl --resume

# Genuine clean slate: also delete every pending task from RabbitMQ
python main.py /path/to/dataset.jsonl --purge-queues
```

Starting the pipeline no longer purges the queues implicitly. Purging deletes
pending tasks while the matching database rows keep their status, which strands
those snippets, so it now requires `--purge-queues` (which covers the queues of
disabled models too — those are unreachable otherwise).

At start-up the pipeline also reports queued work for models that are not enabled
in `config/config.yaml`. Agents are only started for enabled models, so such
messages would sit in their queues forever:

```
WARNING 13587 message(s) are queued for models that are not enabled in config.yaml
        and will never be consumed: llm__qwen3_6_35b_a3b=9113, llm__seed_coder_8b=2980, …
```

Shutdown is cooperative: agents get SIGTERM and 30 s to finish in-flight
containers and settle their messages before being killed, and any containers left
behind by a hard kill are removed on the next start.

## Resuming specific stages

Use `--stages` with `--resume` to re-queue only the pipeline steps you need.
No dataset file is required when the `generate` stage is omitted.

| Stage | What it re-queues |
|---|---|
| `generate` | Seeds without a generated snippet → LLM |
| `compile` | `GENERATION_SUCCESS` snippets → compiler |
| `compile_fix` | `COMPILATION_FAILED` snippets (under retry limit) → LLM |
| `verify` | `COMPILATION_SUCCESS` snippets → ESBMC |
| `inject_fix` | Verified `SAFE`/`VULNERABLE` originals with no paired child → LLM |

```bash
# Re-queue only inject/fix tasks (no dataset needed)
python main.py --resume --stages inject_fix

# Re-queue compile + verify together
python main.py /path/to/dataset.jsonl --resume --stages compile,verify

# Re-queue everything except initial generation
python main.py --resume --stages compile,compile_fix,verify,inject_fix
```

> `--resume` only **re-publishes messages**. It advances nothing unless the agent
> processes are running and consuming those queues. To do the work without agents,
> use the resume script below.

## Recovering stuck snippets without agents

`scripts/resume_stuck_snippets.py` finds snippets stranded mid-pipeline and, for
the compile and verify stages, does the work itself in a local multiprocessing
pool, writing results straight to the database. Reach for it when the pipeline was
stopped mid-run, when a queue was purged (a non-`--resume` start purges every
queue), or when a next-stage task was lost.

| Stage | Picks up | How it advances the snippet |
|---|---|---|
| `compile` | `GENERATION_SUCCESS` | Compiles locally in Docker |
| `compile_fix` | `COMPILATION_FAILED` under the retry limit | Publishes `compilation_fix` — **needs a live LLM agent** |
| `verify` | `COMPILATION_SUCCESS` | Runs ESBMC locally in Docker |
| `inject_fix` | Verified `SAFE`/`VULNERABLE` originals with no paired child | Publishes `vulnerability_fix` / `inject_vulnerability` — **needs a live LLM agent** |

Stages always run in the order above, so `--stages compile,verify` verifies what
it just compiled, and `--stages verify,inject_fix` queues fix/injection tasks for
snippets verified in the same run.

Compilation and verification reuse the agents' own command builders and verdict
mapping, so a snippet resumed here gets identical compiler flags, identical ESBMC
flags, a witness, and inferred CWEs — labels stay comparable with the pipeline's.

```bash
# Verify everything that has been sitting in COMPILATION_SUCCESS
python scripts/resume_stuck_snippets.py --stages verify

# See what each stage would do, changing nothing
python scripts/resume_stuck_snippets.py --dry-run

# Compile then verify, one model, capped at 500 snippets per stage
python scripts/resume_stuck_snippets.py \
    --stages compile,verify --models gemma-4-31b-it --limit 500

# Also retry snippets that dead-ended in VERIFICATION_ERROR
python scripts/resume_stuck_snippets.py --stages verify --include-errors

# Trade coverage for throughput on a big backlog
python scripts/resume_stuck_snippets.py \
    --stages verify --workers 48 --esbmc-timeout 60
```

| Flag | Default | Notes |
|---|---|---|
| `--stages` | all four | Comma-separated; always executed in pipeline order |
| `--esbmc-timeout` | `esbmc.timeout` from config | Second throughput dial. Lowering it trades coverage for speed |
| `--include-timeouts` | off | Retry `VERIFICATION_TIMEOUT` too. Kept separate from `--include-errors` because timeouts reproduce under the same budget |
| `--stuck-minutes` | `45` | Only touches rows untouched this long. Keep it above the pipeline's worst-case in-flight time (`esbmc_batch_timeout` + `esbmc_batch_size` × `esbmc.timeout`) or you will re-run work an agent is still doing |
| `--workers` | `resource_management.verification_slots` | Pool size for compile/verify, so a resume run stays inside the same Docker resource envelope as the pipeline |
| `--models` | all | Restrict to given `generation_model` values |
| `--limit` | none | Cap snippets handled per stage |
| `--include-errors` | off | Adds `VERIFICATION_ERROR` to the verify stage — no other stage ever revisits those |
| `--max-fix-attempts` | `3` | `compile_fix` retry budget per snippet |
| `--dry-run` | off | Report only; no compiling, verifying, or publishing |

## Concurrency model

Each of the three agent types runs one process per enabled model, and each process
runs `*_concurrency` worker threads (config `queues.*_concurrency`). A few
invariants keep that safe; breaking them is what previously lost snippets silently.

| Component | Rule |
|---|---|
| `QueueProducer` | One shared pika connection, every operation under a lock. pika's `BlockingConnection` is **not** thread-safe: 16 threads publishing on one unlocked connection corrupts the frame stream and drops messages while reporting success. Publisher confirms are on, so a `True` return means the broker accepted and persisted the message |
| Publish results | Never ignored. Agents log a greppable `STRANDED snippet <uuid> … --stages <stage>` line naming the resume stage that recovers it, rather than re-running an expensive LLM call or ESBMC run |
| `QueueConsumer` | Callbacks return one `Outcome` per message, so a transient failure re-delivers that message alone instead of its whole batch |
| `DatabaseManager` | `session_scope()` hands out an independent session per call (a thread-local one is shared by every coroutine on that thread). Pool size comes from `database.pool_size` and must cover the largest `*_concurrency` |
| Write failures | `update_snippet` raises; only a missing snippet returns `False`. NUL bytes in ESBMC logs and witnesses — which Postgres rejects — are scrubbed centrally |
| Statistics | Derived from grouped queries and cached, never mutated on the write path. The old `SELECT … FOR UPDATE` on a single `Stats` row serialised every write in the entire pipeline |
| Back-pressure | Running out of compilation/verification slots raises `SlotUnavailableError` (a `RetryableError`), so the message is re-queued instead of the snippet being recorded as a failure it never had |
| Containers | Every container carries `verivul.owner` / `verivul.creator_pid` labels so leftovers from a killed agent can be identified and removed |
| Bind mounts | Containers run as root. Mount the source **read-only as a single file** where possible (ESBMC), and where a writable directory is unavoidable (compilation) emit `reclaim_trap()` so the container chowns the mount back to the host user on exit — otherwise a root-owned subdirectory such as mypy's `.mypy_cache` makes host-side cleanup impossible |


## Requeue helpers

`scripts/requeue.py` re-publishes work that ended without a usable result, with subcommands `compile`, `frontend`, `resource` and `generation` (see `--help`). Other maintenance scripts:

| Script | Purpose |
|---|---|
| `scripts/resume_stuck_snippets.py` | recover snippets stranded mid-pipeline (above) |
| `scripts/clear_queues.py` | purge the RabbitMQ queues |
| `scripts/prune_db.py` | delete rows that are no longer needed |
| `scripts/export_verified.py` | export verified snippets with CWEs, ESBMC logs and confirmation results |
| `scripts/export_pairs.py` | export confirmed fix and injection pairs |
| `scripts/confirm_labels.py` | run the sanitizer confirmation on stored snippets |
| `scripts/afl_reproduce.py` | AFL++ campaign for programs the input search could not crash |
| `src/utils/cleaner.py` | strip comments and label-revealing words from program text (`python -m src.utils.cleaner --help`) |
