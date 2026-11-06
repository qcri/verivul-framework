"""Pure verification primitives: the ESBMC flag list and the CWE mapping.

These live apart from esbmc_agent so that everything which has to agree on what a
label *means* can import them without pulling in Docker, the database or the
queue: the agent, scripts/resume_stuck_snippets.py, and the tests that pin these
decisions.  A label in this corpus is only meaningful relative to the flags that
produced it, so divergence here silently produces labels that are not comparable
with the ones already recorded.
"""
import hashlib
import io
import json
import re
import shlex
import tarfile
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from config.settings import settings


# ---------------------------------------------------------------------------
# Violated property → CWE mapping
#
# ESBMC >= 8.4 annotates every violated property with the matching CWE ids
# itself, against CWE 4.20, and prints them as a "CWE: CWE-416, CWE-825" line
# inside the violation block (the same ids it writes to --sarif-output taxa).
# That annotation is upstream-maintained and is preferred whenever present.
#
# The regex catalogue below is only a fallback, for logs without a CWE line
# and for frontends that do not annotate.  It is
# intentionally allowed to yield more than one id per property: several ESBMC
# checks genuinely cannot distinguish between related weaknesses, and guessing
# one is how "array bounds violated" used to be recorded as an out-of-bounds
# *read* (CWE-125) even when the counterexample was a write.
# ---------------------------------------------------------------------------
_ESBMC_CWE_LINE = re.compile(r'^[ \t]*CWE:[ \t]*(CWE-\d+(?:[ \t]*,[ \t]*CWE-\d+)*)[ \t]*$',
                             re.M)
_CWE_ID = re.compile(r'CWE-\d+')

_ESBMC_CWE_PATTERNS: List[Tuple[re.Pattern, Tuple[str, ...]]] = [
    # NULL pointer dereference
    (re.compile(r'null pointer|source pointer is null|destination pointer is null', re.I),
     ('CWE-476',)),
    # Use-after-free / expired pointer dereference
    (re.compile(r'use.after.free|invalidated dynamic object|access.*after.*free|'
                r'use of.*freed pointer', re.I), ('CWE-416', 'CWE-825')),
    # Double-free
    (re.compile(r'double.free|freed.*twice', re.I), ('CWE-415',)),
    # Freeing memory that is not a valid heap allocation
    (re.compile(r'invalid pointer freed|free\(\) of non-dynamic memory', re.I), ('CWE-590',)),
    # Use-after-return
    (re.compile(r'accessed expired variable pointer', re.I), ('CWE-562',)),
    # Classic buffer overflow via unsafe libc → CWE-120 (plus the write)
    (re.compile(r'buffer overflow on (scanf|sscanf|sprintf|gets|strcpy|strcat|memcpy)', re.I),
     ('CWE-120', 'CWE-787')),
    # Bounds violation: ESBMC does not report direction, so record both the
    # read and the write, matching how 8.4 annotates the same property.
    (re.compile(r'array bounds violated|dereference failure: array bounds|'
                r'out.of.bound|buffer.*over.read', re.I),
     ('CWE-125', 'CWE-787', 'CWE-129')),
    # General out-of-bounds write / overflowing a buffer
    (re.compile(r'buffer overflow|stack.*overflow|heap.*overflow', re.I),
     ('CWE-787', 'CWE-121')),
    # Arithmetic underflow, kept ahead of the general overflow rule
    (re.compile(r'arithmetic overflow on sub', re.I), ('CWE-191',)),
    # Arithmetic overflow (signed; unsigned wraparound is not checked)
    (re.compile(r'arithmetic overflow|integer overflow|overflow on (add|mul|shl|shr|neg|div)', re.I),
     ('CWE-190',)),
    # Division by zero
    (re.compile(r'division by zero', re.I), ('CWE-369',)),
    # NaN / IEEE arithmetic
    (re.compile(r'NaN on ieee_', re.I), ('CWE-682',)),
    # Memory leak ("forgotten memory" is ESBMC's term for a lost allocation)
    (re.compile(r'forgotten memory|memory leak', re.I), ('CWE-401',)),
    # Invalid pointer / improper memory access (catch-all)
    (re.compile(r'invalid pointer|incorrect alignment|improper.*memory', re.I), ('CWE-119',)),
]


def cwes_from_esbmc_annotation(log: str) -> List[str]:
    """Return the CWE ids ESBMC annotated the violations with, in first-seen order.

    Empty if the log carries no annotation (ESBMC < 8.4).
    """
    found: List[str] = []
    seen = set()
    for block in _ESBMC_CWE_LINE.finditer(log or ''):
        for cwe in _CWE_ID.findall(block.group(1)):
            if cwe not in seen:
                seen.add(cwe)
                found.append(cwe)
    return found


def infer_cwes_from_esbmc_log(log: str) -> List[str]:
    """Return deduplicated CWE ids for the violations in an ESBMC log.

    Prefers ESBMC's own annotation; falls back to matching the violated-property
    text against the catalogue above.  Returns an empty list if neither yields
    anything (a successful or inconclusive run).
    """
    if not log:
        return []

    annotated = cwes_from_esbmc_annotation(log)
    if annotated:
        return annotated

    # Collect the description line of each violation (the first non-trivial line
    # after 'Violated property:' that is not the file/line header).
    violation_lines: List[str] = []
    lines = log.split('\n')
    for i, line in enumerate(lines):
        if 'Violated property' in line:
            for j in range(1, 5):
                if i + j < len(lines):
                    candidate = lines[i + j].strip()
                    if candidate and not candidate.startswith('file ') and candidate != '0':
                        violation_lines.append(candidate)
                        break

    # Fall back to scanning the full log if no violation block was found
    if not violation_lines:
        violation_lines = lines

    found: List[str] = []
    seen: set = set()
    for text in violation_lines:
        for pattern, cwes in _ESBMC_CWE_PATTERNS:
            if pattern.search(text):
                for cwe in cwes:
                    if cwe not in seen:
                        seen.add(cwe)
                        found.append(cwe)
                break  # first matching pattern wins for this property
    return found


# ---------------------------------------------------------------------------
# Verification primitives
#
# These are module-level (not ESBMCAgent methods) so that out-of-band tooling —
# scripts/resume_stuck_snippets.py in particular — verifies snippets with
# *exactly* the same ESBMC flags and the same log→verdict mapping as the agent.
# Any divergence here silently produces labels that are not comparable with the
# ones the pipeline wrote.  ESBMCAgent keeps thin delegating wrappers.
# ---------------------------------------------------------------------------

WITNESS_STEM = "/work/witness"
WITNESS_GRAPHML = WITNESS_STEM + ".graphml"
WITNESS_YAML = WITNESS_STEM + ".yml"
SARIF_PATH = "/work/out.sarif"


def code_hash(code: str) -> str:
    """SHA-256 of the program text; the identity a verdict is attached to."""
    return hashlib.sha256((code or "").encode("utf-8", errors="replace")).hexdigest()


class VerificationResult(NamedTuple):
    """One ESBMC run; ``meta`` is the provenance stored with the label."""
    status: Any
    label: Any
    log: str
    witness: Optional[str]
    meta: Dict[str, Any]


FRONTEND_CHECK_LANGUAGES = ("c", "cpp", "python")


_CLANG_ERROR_LINE = re.compile(r"\.(?:c|cc|cpp|h|hpp):\d+:\d+: error")
PYTHON_SUPPORTED_MODULES = ("collections", "dataclasses", "datetime", "decimal", "enum", "heapq", "math",
                            "os", "queue", "random", "re", "string", "time", "typing")


def frontend_failure_message(logs: str) -> Optional[str]:
    """The message sent back to the LLM when ESBMC's front end rejected a program, or None
    when *logs* hold no front-end error (a timeout, out-of-memory, or a verdict).

    C/C++: the clang error lines.  Python: ESBMC's own `ERROR:` lines only.  The mypy
    `error: ... [no-untyped-def]` lines that precede them are not what stops ESBMC, and
    listing them sent the model off annotating functions instead of removing the import.
    """
    logs = logs or ""
    if not re.search(r"\berror\b", logs, re.I):
        return None
    if re.search(r"^ERROR: (Timed out|Out of memory)", logs, re.M) and not _CLANG_ERROR_LINE.search(logs):
        return None  # a resource limit, not something the program can be rewritten around
    lines = logs.splitlines()
    clang = [l for l in lines if _CLANG_ERROR_LINE.search(l)]
    hard = [l for l in lines if l.startswith("ERROR:")]
    hint = ""
    if clang:
        detail = clang[:25]
    elif hard:
        detail = hard[:10]
        modules = re.findall(r"Cannot open file: \S*?/([A-Za-z0-9_]+)\.json", logs) + \
                  re.findall(r'Object "([A-Za-z0-9_]+)" not found', logs)
        modules = [m for m in dict.fromkeys(modules) if m not in PYTHON_SUPPORTED_MODULES]
        if modules and "module-file-not-found" in logs or modules and "Cannot open file" in logs:
            hint = ("\nESBMC's Python front end cannot import: " + ", ".join(modules)
                    + ". Remove those imports and every use of them. Only these modules are supported: "
                    + ", ".join(PYTHON_SUPPORTED_MODULES) + ".")
    else:
        detail = [l for l in lines if re.search(r"\berror\b", l, re.I)][:25] or [logs[-1500:]]
    return ("ESBMC front end rejected this program. It compiles with the regular compiler, "
            "but the verifier cannot read it:\n" + "\n".join(detail)[:3000] + hint)


def build_frontend_check_command(language: str, source_path: str) -> Optional[str]:
    """ESBMC command that only runs the front end and GOTO conversion (about a second).

    It reports what verification would reject at parse time -- C++ library features ESBMC's
    model lacks, unsupported Python imports -- so the compile stage can send those programs
    back for repair instead of spending a verification slot on them.  The flags that decide
    what the front end accepts match build_verification_command.  None if the language has
    no such check.
    """
    if language in ("c", "cpp"):
        args = ["esbmc", "--goto-functions-only", "--64", "--function", "main",
                "-Wno-int-conversion", "-D_GNU_SOURCE", "--input-file", source_path]
    elif language == "python":
        args = ["esbmc", "--goto-functions-only", "--input-file", source_path]
    else:
        return None
    return " ".join(shlex.quote(a) for a in args)


def esbmc_budget(container_timeout: Optional[int] = None) -> Tuple[str, str]:
    """Return the ``--timeout`` / ``--memlimit`` values ESBMC should be given.

    Both used to be hard-coded (10m, 4g) while the container that runs ESBMC is
    killed after ``esbmc.timeout`` seconds and capped at ``esbmc_mem_limit``.
    With ESBMC believing it had 10 minutes, it never self-terminated inside our
    window: every long snippet was killed by the Docker wait instead, which
    discards its output (we keep only the last 50 log lines) and costs the full
    wait.  Giving ESBMC a slightly *shorter* budget than the container means it
    stops on its own terms and reports what it established.

    Likewise the memory limit: ESBMC aiming at 4 GB inside a 2 GB container gets
    OOM-killed rather than reporting that it ran out of memory.
    """
    if container_timeout is None:
        container_timeout = int(settings.esbmc.get('timeout', 300))
    # Leave ESBMC room to print its result before the container wait fires.
    internal = max(30, container_timeout - 10)
    mem_limit = str(settings.resource_management.get('esbmc_mem_limit', '4096m')).lower()
    # Docker accepts "2048m"; ESBMC wants a bare number of MB or a g/m suffix.
    return f"{internal}s", mem_limit


def build_verification_command(
    language: str, source_path: str, container_timeout: Optional[int] = None,
    extra_flags: Optional[List[str]] = None,
) -> str:
    """Return the full shell command (possibly multi-step) to verify source_path with ESBMC.

    ``extra_flags`` is for second-tier passes (e.g. the strictness tag) and never
    for the label pass."""
    timeout_value, mem_value = esbmc_budget(container_timeout)
    base = ["--timeout", timeout_value, "--memlimit", mem_value]

    # Flags shared by all k-induction targets (C, C++, CUDA)
    k_induction_flags = [
        "--k-induction",
        "--interval-analysis",
        "--unlimited-k-steps",
        "--state-hashing",
        "--add-symex-value-sets",
    ]
    # Checks shared by the C-family targets.
    #
    # --unsigned-overflow-check is deliberately NOT enabled here.  Unsigned
    # wraparound is defined behaviour in C, so on its own it is not a defect,
    # and ESBMC's overflow encoding picks the *signed* interpretation whenever
    # either operand of a shift is a plain int (smt_overflow.cpp chooses
    # is_signed = is_signedbv_type(side1) || is_signedbv_type(side2)), which
    # makes `1u << k` report "arithmetic overflow on shl" for k >= 31.  It also
    # fires inside ESBMC's own fread model, where the byte count is computed as
    # `nread * size` *before* `__ESBMC_assume(nread <= nitems)` constrains
    # nread, so the multiply is unconstrained.  Neither report is a property of
    # the program under test.  Dropping the flag loses no detection power: a
    # wrapped length that is actually used still fails, but as the memory-safety
    # violation it causes (e.g. "array bounds violated" at the memcpy), which is
    # the more useful root cause to record.  Genuine *signed* overflow, which is
    # UB, is still checked by --overflow-check.
    #
    # --no-align-check: this is a scoping decision, not purely artefact removal,
    # and it cuts both ways.  Sampling the "Incorrect alignment when accessing
    # data object" reports in the corpus, the majority land on ordinary `p->field`
    # access through a malloc'd or list-walked pointer, where the report reflects
    # how precisely ESBMC tracks heap alignment rather than a defect in the
    # program; a minority land on genuine unaligned casts such as
    # `*(uint32_t *)&buf[2]`, which really are undefined behaviour. Those genuine
    # cases are given up deliberately: they are benign on the x86-64 target this
    # corpus declares, they map to CWE-704 rather than to a memory-safety
    # weakness, and leaving the check on admits the much larger imprecise group.
    #
    # --no-unlimited-scanf-check is deliberately NOT enabled.  It was a candidate
    # because it would report "buffer overflow on scanf" for a *numeric*
    # conversion such as scanf("%u", &x), where the report is about the value the
    # environment supplies rather than the program.  ESBMC 8.4 does not report
    # that case, so the flag buys nothing, and it is actively harmful:
    # measured on 8.4, it turns scanf("%s", buf8) and sscanf(line, "%s", buf8)
    # from FAILED into SUCCESSFUL.  Those are genuine unbounded-write defects
    # (CWE-120), and a bounded scanf("%7s", buf8) is correctly SUCCESSFUL with
    # the check left on, so the check produces no false report on 8.4.
    # realloc failure is a separate switch; leak flags match LeakSanitizer semantics
    # (still-reachable at exit and live-at-abort are not leaks). See tests/esbmc_cases/REPORT.md.
    common_checks = [
        "--force-malloc-success",
        "--force-realloc-success",
        "--memory-leak-check",
        "--no-reachable-memory-leak",
        "--no-abnormal-memory-leak",
        "--overflow-check",
        "--nan-check",
        "--ub-shift-check",
        "--floatbv",
        "--no-align-check",
        "--no-unwinding-assertions",
    ]

    # ESBMC models argv[i] as NULL for every i that it does not explicitly back
    # with a nondet string.  Any program that reads argument *content* therefore
    # fails on the entry-point model rather than on its own logic, and
    # __ESBMC_assume(argv[i] != NULL) does not repair it: the assumption
    # contradicts the model, so every proof made under it is vacuous.
    #
    # --argv-max-args backs that many entries (argv[0] included) with nondet
    # strings.  6 covers 99.6% of the argv-reading programs measured in the
    # current corpus (highest index referenced: argv[1] 50.7%, argv[2] 14.6%,
    # argv[3] 4.7%, argv[4] 1.9%, remainder in a thin tail).
    #
    # --argv-max-strlen is the cost knob and it is steep: on a 9-line program,
    # 8 bytes solves in ~4 s, 16 in ~19 s, 32 in ~111 s and 64 exceeds a 170 s
    # budget.  16 is the largest width that leaves headroom inside the
    # per-container budget.  It bounds the argument model, so a SAFE verdict
    # means "no violation reachable with arguments up to this width", which is
    # why generation now prefers stdin over argv.
    #
    # Both options need ESBMC >= 8.4.
    argv_model = ["--argv-max-args", "6", "--argv-max-strlen", "16"]
    # ESBMC appends .graphml/.yml to the witness stem itself
    witness = ["--witness-output", WITNESS_STEM]
    sarif = ["--sarif-output", SARIF_PATH]

    # Clang frontend flags (verified against --help on ESBMC 8.4):
    #   -Wno-int-conversion  suppress int↔pointer warnings that ESBMC's
    #                        clang treats as hard errors (not suppressible
    #                        via -Wno-error — must target the specific diag).
    #   -D_GNU_SOURCE        expose POSIX/GNU macros (ENOMEM, ENOENT, …)
    #                        that generated code uses without #include.
    # NOTE: --clang-fe-arg does not exist in ESBMC 8.4; -W/-D are the
    #       correct top-level flags.
    clang_fe = ["-Wno-int-conversion", "-D_GNU_SOURCE"]

    # Run ESBMC with an unlimited stack so complex CFGs do not abort().
    ulimit_prefix = "ulimit -s unlimited && "

    if language in ("c", "cpp"):
        args = (["esbmc"] + k_induction_flags + base +
                ["--64", "--function", "main"] +
                common_checks + argv_model + (extra_flags or []) + clang_fe + witness + sarif +
                ["--input-file", source_path])
        return ulimit_prefix + " ".join(shlex.quote(a) for a in args)

    elif language == "cuda":
        # CUDA: same as C/C++ plus data-races-check for GPU concurrency
        args = (["esbmc"] + k_induction_flags + base +
                ["--64", "--function", "main"] +
                common_checks + ["--data-races-check"] + argv_model +
                clang_fe + witness + sarif +
                ["--input-file", source_path])
        return ulimit_prefix + " ".join(shlex.quote(a) for a in args)

    elif language == "python":
        # Python frontend requires mypy (installed in esbmc image) and
        # ast2json.  Uses incremental BMC; no --64/--function/k-induction.
        args = (["esbmc", "--incremental-bmc"] + base +
                ["--overflow-check", "--memory-leak-check",
                 "--no-unwinding-assertions",
                 "--input-file", source_path])
        return " ".join(shlex.quote(a) for a in args)

    elif language == "solidity":
        # solc generates a JSON AST that ESBMC's Solidity frontend reads.
        # --unwind 3 + --no-unwinding-assertions prevents ESBMC's internal
        # address-generation loop from running forever (verified fix).
        solast_path = source_path.replace(".sol", ".solast")
        solc_step = (f"solc --ast-compact-json {shlex.quote(source_path)} "
                     f"> {shlex.quote(solast_path)}")
        esbmc_args = (["esbmc", solast_path, "--sol", source_path] + base +
                      ["--overflow-check", "--unsigned-overflow-check",
                       "--no-unwinding-assertions", "--unwind", "3"] +
                      witness)
        esbmc_step = " ".join(shlex.quote(a) for a in esbmc_args)
        return f"{solc_step} && {esbmc_step}"

    elif language == "kt":
        jar_path = "/work/source.jar"
        jimple_dir = "/work/jimple_out"
        # Search both the official release path (/opt/kotlinc) and the older
        # apt-installed path (/usr/share/kotlin) so the image keeps working
        # after the Dockerfile is rebuilt with the new Kotlin version.
        kotlin_stdlib = "$(find /opt/kotlinc /usr/share/kotlin -name 'kotlin-stdlib*.jar' 2>/dev/null | head -1)"
        # --allow-phantom-refs: treats classes that Soot cannot resolve
        # (e.g. kotlin.Metadata, which lives in the Kotlin compiler but is
        # not always on Soot's classpath) as placeholders rather than hard
        # errors.  Without this flag Soot aborts and produces no Jimple,
        # leaving ESBMC with no input ("Please provide a program to verify").
        # ESBMC's Jimple frontend reads a JSON form of Jimple (textual Jimple fails with
        # "json.exception.parse_error ... last read: 'p'"), produced by jimple2json from Soot's
        # textual output.  The Soot flags are the ones jimple2json documents: Soot >= 4.4 quotes
        # type names ('void') which ESBMC then cannot resolve, hence Soot 4.3.0 in the image
        # (/opt/soot.jar), original local names, and annotations for the parser.
        # jimple2json writes <file>.json next to its input; ESBMC picks its frontend from the
        # extension, so the JSON is copied to a .jimple name.
        soot_step = (f"java -cp /opt/soot.jar soot.Main -pp "
                     f"-soot-classpath \"{jar_path}:{kotlin_stdlib}\" "
                     f"--allow-phantom-refs "
                     f"-src-prec class -f jimple SourceKt -write-local-annotations "
                     f"-p jb use-original-names:true -keep-line-number -print-tags-in-output "
                     f"-d {jimple_dir}")
        text_jimple = f"{jimple_dir}/SourceKt.jimple"
        json_jimple = f"{jimple_dir}/SourceKt_ir.jimple"
        convert_step = f"jimple2json {text_jimple} && cp {text_jimple}.json {json_jimple}"
        # --force-malloc-success: `newarray` allocates through malloc, and without it every
        # array use is a NULL dereference.  No --memory-leak-check: the JVM is garbage
        # collected, so "forgotten memory" is a false positive for every array.
        esbmc_args = (["esbmc"] + k_induction_flags + base +
                      ["--force-malloc-success", "--overflow-check"])
        esbmc_step = " ".join(shlex.quote(a) for a in esbmc_args) + f" {json_jimple}"
        return (f"kotlinc {shlex.quote(source_path)} -include-runtime -jvm-target 1.8 -d {shlex.quote(jar_path)} && "
                f"mkdir -p {shlex.quote(jimple_dir)} && "
                f"{soot_step} && "
                f"{convert_step} && "
                f"{esbmc_step}")

    else:
        # Fallback: treat unknown language like C
        args = (["esbmc"] + k_induction_flags + base +
                ["--64", "--function", "main"] +
                common_checks + clang_fe + witness + sarif +
                ["--input-file", source_path])
        return ulimit_prefix + " ".join(shlex.quote(a) for a in args)


def pair_rejection_reason(parent, child_label: str, child_code: str, child_meta: Optional[Dict]) -> Optional[str]:
    """Reason a derived program is not a valid pair with *parent*, or None."""
    definitive = {'SAFE', 'VULNERABLE'}
    if parent is None:
        return "parent no longer exists"
    if child_label not in definitive:
        return f"derived verdict is {child_label}"
    if parent.label not in definitive:
        return f"parent label is {parent.label}"
    if child_label == parent.label:
        return f"derived label {child_label} equals parent label"
    if code_hash(child_code) == (parent.code_hash or code_hash(parent.code or "")):
        return "derived code is byte-identical to the parent"
    pmeta, cmeta = parent.verification_meta or {}, child_meta or {}
    for key in ('command', 'esbmc_version'):
        if pmeta.get(key) and cmeta.get(key) and pmeta[key] != cmeta[key]:
            return f"parent and child differ in {key}"
    return None


def extract_file(container, path: str) -> Optional[str]:
    """Read one file out of a finished container, or None if it does not exist."""
    if container is None:
        return None
    try:
        stream, _ = container.get_archive(path)
        buf = io.BytesIO()
        for chunk in stream:
            buf.write(chunk)
        buf.seek(0)
        with tarfile.open(fileobj=buf) as tar:
            member = tar.getmembers()[0]
            f = tar.extractfile(member)
            if f:
                return f.read().decode('utf-8', errors='replace')
    except Exception:
        pass  # absent file (timeout / frontend error / older version) is not an error
    return None


def extract_witness(container) -> Optional[str]:
    """GraphML witness of a finished run (violation or correctness), or None."""
    return extract_file(container, WITNESS_GRAPHML)


def extract_artifacts(container) -> Dict[str, Optional[str]]:
    """All machine-readable outputs of a run: GraphML and YAML witness, SARIF."""
    return {
        'witness_graphml': extract_file(container, WITNESS_GRAPHML),
        'witness_yaml': extract_file(container, WITNESS_YAML),
        'sarif': extract_file(container, SARIF_PATH),
    }


_VERSION_RE = re.compile(r'ESBMC version (\S+)')
_VIOLATED_RE = re.compile(
    r'Violated property:\s*\n'
    r'\s*file (?P<file>\S+) line (?P<line>\d+)(?: column (?P<column>\d+))? function (?P<function>\S+)\s*\n'
    r'\s*(?P<description>[^\n]+)')
_VERDICT_RE = re.compile(r'VERIFICATION (SUCCESSFUL|FAILED|UNKNOWN)')
_KSTEP_RE = re.compile(r'\(k = (\d+)\)')
_SOLUTION_RE = re.compile(r'Solution found by the (forward condition|inductive step)')
PROGRAM_SOURCE_PREFIX = '/work/source.'


def esbmc_version_from_log(log: str) -> Optional[str]:
    m = _VERSION_RE.search(log or '')
    return m.group(1) if m else None


def parse_violated_properties(log: str) -> List[Dict[str, Any]]:
    """Every 'Violated property' block, in order; in_program is False inside library models."""
    out: List[Dict[str, Any]] = []
    for m in _VIOLATED_RE.finditer(log or ''):
        desc = m.group('description').strip()
        # 8.4 prints a "CWE: ..." line right after the description of a violation
        block_end = m.end()
        nxt = (log[block_end:block_end + 200].split('\n') + [''])[1].strip()
        cwes = _CWE_ID.findall(nxt) if nxt.startswith('CWE:') else []
        out.append({
            'description': desc,
            'file': m.group('file'),
            'line': int(m.group('line')),
            'column': int(m.group('column')) if m.group('column') else None,
            'function': m.group('function'),
            'in_program': m.group('file').startswith(PROGRAM_SOURCE_PREFIX),
            'cwes': cwes,
        })
    return out


def parse_sarif(text: Optional[str]) -> List[Dict[str, Any]]:
    """Results of an ESBMC SARIF report as [{rule, message, line, cwes}]."""
    if not text:
        return []
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    results: List[Dict[str, Any]] = []
    for run in doc.get('runs', []):
        for r in run.get('results', []):
            loc = ((r.get('locations') or [{}])[0].get('physicalLocation') or {})
            results.append({
                'rule': r.get('ruleId'),
                'message': (r.get('message') or {}).get('text'),
                'file': (loc.get('artifactLocation') or {}).get('uri'),
                'line': (loc.get('region') or {}).get('startLine'),
                'cwes': ['CWE-' + t['id'] for t in r.get('taxa', [])
                         if (t.get('toolComponent') or {}).get('name') == 'CWE' and t.get('id')],
            })
    return results


def build_verification_meta(
    log: str, command: str, image: str, image_digest: Optional[str],
    duration_s: Optional[float], path: str,
    artifacts: Optional[Dict[str, Optional[str]]] = None,
) -> Dict[str, Any]:
    """Provenance stored with every verdict: command, version, image, parsed properties."""
    artifacts = artifacts or {}
    log = log or ''
    props = parse_violated_properties(log)
    verdict = _VERDICT_RE.search(log)
    solution = _SOLUTION_RE.search(log)
    ks = _KSTEP_RE.findall(log)
    annotated = cwes_from_esbmc_annotation(log)
    sarif = parse_sarif(artifacts.get('sarif'))
    return {
        'esbmc_version': esbmc_version_from_log(log),
        'command': command,
        'image': image,
        'image_digest': image_digest,
        'path': path,
        'duration_s': round(duration_s, 2) if duration_s is not None else None,
        'verdict': verdict.group(1) if verdict else None,
        'proof': solution.group(1) if solution else None,
        'k': int(ks[-1]) if ks else None,
        'violated_properties': props,
        'cwe_source': 'esbmc' if annotated else ('rules' if infer_cwes_from_esbmc_log(log) else 'none'),
        'sarif_results': sarif,
        'witness_yaml': artifacts.get('witness_yaml'),
        'has_witness_graphml': bool(artifacts.get('witness_graphml')),
    }
