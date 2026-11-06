"""
Backward program slice engine with heuristic inter-procedural support.

Entry point: slice_function()
"""
from __future__ import annotations
from dataclasses import dataclass, field

from .usedef import Stmt, CallSite, extract_statements, get_function_params
from .summaries import STDLIB_SUMMARIES, apply_summary

# ── Configuration ─────────────────────────────────────────────────────────────

MAX_DEPTH: int = 3          # maximum callee recursion depth
MAX_SLICE_STMTS: int = 200  # cap output statement count
MAX_ITERATIONS: int = 50    # safety limit on worklist iterations


# ── Result type ───────────────────────────────────────────────────────────────


@dataclass
class SliceResult:
    """Outcome of slice_function()."""
    sliced_code: str               # reconstructed slice (ordered lines)
    sliced_lines: list[int]        # original 1-based line numbers included
    criterion_lines: list[int]     # lines used as criterion
    num_stmts_before: int          # total statements parsed in entry function
    num_stmts_after: int           # statements in the slice
    inter_proc_calls: list[str]    # callee names resolved inter-procedurally
    criterion_source: str = "diff"


# ── Call DB ───────────────────────────────────────────────────────────────────


def build_call_db(neighbor_functions: list[dict]) -> dict[str, str]:
    """
    Build a {function_name -> source_code} lookup from same-commit functions.

    `neighbor_functions` is a list of dicts with at least 'name' and 'code'.
    When multiple functions share a name, the first one wins.
    """
    db: dict[str, str] = {}
    for fn in neighbor_functions:
        name = fn.get("name", "").strip()
        code = fn.get("code", "").strip()
        if name and code and name not in db:
            db[name] = code
    return db


# ── Dependency resolution for call sites ─────────────────────────────────────


def _resolve_call(
    site: CallSite,
    call_db: dict[str, str],
    language: str,
    depth: int,
    visited: frozenset[str],
) -> tuple[set[str], set[str], list[str]]:
    """
    Determine data dependencies introduced by a call site.

    Returns:
        (result_deps, side_effect_vars, resolved_callees)
        result_deps       – vars at call site that site.result_var depends on
        side_effect_vars  – arg vars that may be modified (pointer writes)
        resolved_callees  – callee names that were resolved inter-procedurally
    """
    callee = site.callee
    arg_vars = site.arg_vars

    # 1. Stdlib summary
    if callee in STDLIB_SUMMARIES:
        rd, se = apply_summary(callee, arg_vars, site.result_var)
        return rd, se, []

    # 2. Same-commit callee (inter-procedural inline)
    if callee in call_db and depth < MAX_DEPTH and callee not in visited:
        callee_src = call_db[callee]
        callee_params = get_function_params(callee_src, language)
        callee_stmts = extract_statements(callee_src, language)
        if not callee_stmts:
            return set(arg_vars), set(), []

        # Criterion: return statements & all defs (conservative)
        return_idxs = [s.idx for s in callee_stmts if "return" in s.text]
        if not return_idxs:
            return_idxs = [callee_stmts[-1].idx]

        sub_result = _backward_slice_inner(
            callee_stmts,
            set(return_idxs),
            worklist=set(),   # will be seeded from return stmts uses inside
            call_db=call_db,
            language=language,
            depth=depth + 1,
            visited=visited | {callee},
        )

        # Which formal parameters appear in the callee slice?
        sliced_uses: set[str] = set()
        for idx in sub_result.sliced_idxs:
            sliced_uses |= callee_stmts[idx].uses

        used_params = sliced_uses & set(callee_params)
        # Map formal → actual
        result_deps: set[str] = set()
        for i, param in enumerate(callee_params):
            if param in used_params and i < len(arg_vars):
                result_deps.add(arg_vars[i])
        if not result_deps:
            result_deps = set(arg_vars)  # conservative fallback

        return result_deps, set(), [callee]

    # 3. Unknown: conservative identity (return val depends on all args;
    #    pointer args may be written)
    side_effects: set[str] = set()
    for var in arg_vars:
        # Heuristic: if arg starts with '&', wrapped in address-of → out param
        # (tree-sitter already strips '&'; arg_vars holds identifiers only)
        pass  # covered conservatively below

    return set(arg_vars), side_effects, []


# ── Core backward slice ───────────────────────────────────────────────────────


@dataclass
class _SliceState:
    sliced_idxs: set[int] = field(default_factory=set)
    inter_proc_calls: list[str] = field(default_factory=list)


def _backward_slice_inner(
    stmts: list[Stmt],
    criterion_idxs: set[int],
    worklist: set[str],
    call_db: dict[str, str],
    language: str,
    depth: int,
    visited: frozenset[str],
) -> _SliceState:
    state = _SliceState()
    sliced = state.sliced_idxs

    # Seed worklist from criterion
    for idx in criterion_idxs:
        sliced.add(idx)
        worklist |= stmts[idx].uses | stmts[idx].defs

    # Build var → last defining stmt index (in forward order)
    # We iterate multiple times for completeness (fixed-point)
    iteration = 0
    changed = True
    while changed and iteration < MAX_ITERATIONS:
        changed = False
        iteration += 1
        for stmt in stmts:
            if stmt.idx in sliced:
                continue
            # Does this stmt define something we need, or is it a ctrl dep
            # of a sliced stmt and uses something we need?
            touches_worklist = bool(stmt.defs & worklist)
            if not touches_worklist:
                continue

            sliced.add(stmt.idx)
            changed = True

            # Add all uses of this statement to the worklist
            worklist |= stmt.uses

            # Resolve call sites in this statement
            for site in stmt.calls:
                rd, se, resolved = _resolve_call(
                    site, call_db, language, depth, visited
                )
                # result_var is now the definition; it depends on rd
                if site.result_var and site.result_var in worklist:
                    worklist |= rd
                    worklist.discard(site.result_var)  # resolved its def
                else:
                    worklist |= rd
                # side-effect vars are "written" by the call → treat as defs
                worklist |= se
                state.inter_proc_calls.extend(resolved)

            if len(sliced) >= MAX_SLICE_STMTS:
                return state

    # Control dependencies: always include the condition of any
    # control-flow statement that gates a sliced statement
    ctrl_to_add: set[int] = set()
    for idx in list(sliced):
        for ctrl_idx in stmts[idx].ctrl_deps:
            ctrl_to_add.add(ctrl_idx)
    sliced |= ctrl_to_add

    return state


# ── Criterion helpers ─────────────────────────────────────────────────────────


def _criterion_from_diff(
    before_src: str, after_src: str, stmts: list[Stmt]
) -> set[int]:
    """
    Compute criterion statement indices from a before/after diff.
    Returns the stmts whose source lines were modified.
    """
    import difflib

    before_lines = before_src.splitlines()
    after_lines = after_src.splitlines()
    matcher = difflib.SequenceMatcher(None, before_lines, after_lines)

    import re

    changed_before: set[int] = set()
    inserted: list[tuple[int, set[str]]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "delete"):
            for lineno in range(i1 + 1, i2 + 1):  # 1-based
                changed_before.add(lineno)
        elif tag == "insert":
            idents = set(re.findall(r"[A-Za-z_]\w*", "\n".join(after_lines[j1:j2])))
            inserted.append((i1, idents))

    criterion: set[int] = set()
    for stmt in stmts:
        start, end = _stmt_rows(stmt)
        if any(start + 1 <= ln <= end + 1 for ln in changed_before):
            criterion.add(stmt.idx)
    # an inserted guard has no line of its own in the vulnerable version: the
    # statements after the insertion point that use what the guard checks are the sink
    for row, idents in inserted:
        hits = [s.idx for s in stmts if not s.is_ctrl_cond and s.node.start_point[0] >= row
                and (s.uses | s.defs) & idents]
        if not hits:
            hits = [s.idx for s in stmts if not s.is_ctrl_cond and s.node.start_point[0] >= row][:1]
        if not hits:
            hits = [s.idx for s in stmts if not s.is_ctrl_cond and s.node.start_point[0] < row][-1:]
        criterion.update(hits)

    return criterion


def _criterion_from_cwe(cwe: str, stmts: list[Stmt]) -> set[int]:
    """
    Identify likely vulnerable statement indices from CWE heuristics.
    Returns statements whose text contains known dangerous patterns.
    """
    cwe_upper = (cwe or "").upper()

    # Map CWE families → dangerous keywords/patterns
    patterns: list[str] = []

    if any(x in cwe_upper for x in ("119", "120", "121", "122", "125", "787", "788")):
        patterns += ["memcpy", "memmove", "strcpy", "strncpy", "strcat", "gets", "sprintf",
                     "snprintf", "read(", "recv(", "fread", "copy_from_user", "copy_to_user"]
    if "416" in cwe_upper or "415" in cwe_upper or "401" in cwe_upper:
        patterns += ["free(", "kfree(", "put(", "release(", "destroy("]
    if "476" in cwe_upper:
        patterns += ["malloc", "kmalloc", "kzalloc", "calloc", "lookup", "find", "get("]
    if "190" in cwe_upper or "191" in cwe_upper:
        patterns += ["malloc", "kmalloc", "calloc", "alloc(", "sizeof", "<<", "memcpy"]
    if "22" in cwe_upper:   # Path traversal
        patterns += ["open(", "fopen(", "strcat", "strcpy", "/", ".."]
    if "78" in cwe_upper:   # OS command injection
        patterns += ["system(", "popen(", "execl", "execv", "sprintf"]
    if "134" in cwe_upper:  # Format string
        patterns += ["printf(", "sprintf(", "fprintf(", "syslog("]
    if "362" in cwe_upper:  # Race condition
        patterns += ["lock", "mutex", "spin", "atomic"]

    criterion: set[int] = set()
    if patterns:
        for stmt in stmts:
            if not stmt.is_ctrl_cond and any(p in stmt.text for p in patterns):
                criterion.add(stmt.idx)
    if not criterion:
        criterion = {s.idx for s in stmts if not s.is_ctrl_cond and s.text.lstrip().startswith("return")}
    return criterion


# ── Public entry point ────────────────────────────────────────────────────────


def slice_function(
    vulnerable_src: str,
    *,
    fixed_src: str | None = None,
    cwe: str = "",
    language: str = "c",
    neighbor_functions: list[dict] | None = None,
) -> SliceResult:
    """
    Compute a backward program slice of `vulnerable_src`.

    Parameters
    ----------
    vulnerable_src:
        Source code of the vulnerable function (before the fix).
    fixed_src:
        Source code of the fixed function (after the fix).  When provided,
        a diff-based criterion is used (most precise).
    cwe:
        CWE identifier (e.g. "CWE-119") used as fallback criterion when
        `fixed_src` is not available.
    language:
        "c" or "cpp".
    neighbor_functions:
        List of dicts {"name": str, "code": str} — functions changed in the
        same commit.  Used for inter-procedural inlining.

    Returns
    -------
    SliceResult
    """
    stmts = extract_statements(vulnerable_src, language)
    if not stmts:
        return SliceResult(
            sliced_code=vulnerable_src,
            sliced_lines=[],
            criterion_lines=[],
            num_stmts_before=0,
            num_stmts_after=0,
            inter_proc_calls=[],
        )

    criterion: set[int] = set()
    criterion_source = "diff"
    if fixed_src:
        criterion = _criterion_from_diff(vulnerable_src, fixed_src, stmts)
    if not criterion:
        criterion = _criterion_from_cwe(cwe, stmts)
        criterion_source = "cwe"
    if not criterion:
        criterion = {s.idx for s in stmts}
        criterion_source = "all"

    # ── Build call DB from neighbor functions ─────────────────────────────────
    call_db: dict[str, str] = {}
    if neighbor_functions:
        call_db = build_call_db(neighbor_functions)

    # ── Run the slice ─────────────────────────────────────────────────────────
    state = _backward_slice_inner(
        stmts=stmts,
        criterion_idxs=criterion,
        worklist=set(),
        call_db=call_db,
        language=language,
        depth=0,
        visited=frozenset(),
    )

    sliced_idxs = sorted(state.sliced_idxs)
    sliced_stmts = [stmts[i] for i in sliced_idxs]

    src_lines = vulnerable_src.splitlines()
    included_lines: set[int] = set()
    for stmt in sliced_stmts:
        start, end = _stmt_rows(stmt)
        included_lines.update(range(start, end + 1))
        included_lines.update(_enclosing_rows(stmt.node))
        if stmt.is_ctrl_cond:
            included_lines.update(_ctrl_closing_rows(stmt.node))
    _close_blocks(stmts[0].node, included_lines)
    sliced_code = "\n".join(src_lines[i] for i in sorted(included_lines) if i < len(src_lines))

    return SliceResult(
        sliced_code=sliced_code,
        sliced_lines=sorted(ln + 1 for ln in included_lines),  # 1-based
        criterion_lines=sorted(
            stmts[i].src_line for i in criterion if i < len(stmts)
        ),
        num_stmts_before=len(stmts),
        num_stmts_after=len(sliced_stmts),
        inter_proc_calls=list(set(state.inter_proc_calls)),
        criterion_source=criterion_source,
    )


_CONTROL_TYPES = {"if_statement", "for_statement", "while_statement", "do_statement",
                  "switch_statement", "else_clause", "case_statement", "labeled_statement"}


def _header_end_row(node) -> int:
    """Last row of a control statement's header: up to where its body starts."""
    for child in node.children:
        if child.type in ("compound_statement",) or child.type in _CONTROL_TYPES \
                or child.type.endswith("_statement") and child.type != "else_clause":
            if child.start_point[0] > node.start_point[0] or child.type == "compound_statement":
                return child.start_point[0]
    return node.start_point[0]


def _stmt_rows(stmt) -> tuple[int, int]:
    """0-based row span of a statement; control statements contribute only their header."""
    node = stmt.node
    if stmt.is_ctrl_cond:
        return node.start_point[0], _header_end_row(node)
    return node.start_point[0], node.end_point[0]


def _ctrl_closing_rows(node) -> set[int]:
    body = next((c for c in node.children if c.type == "compound_statement"), None)
    rows = {body.end_point[0]} if body else set()
    if node.type == "do_statement":
        rows.add(node.end_point[0])
    return rows


def _close_blocks(any_node, rows: set[int]) -> None:
    """Every block opened on an included row is closed: add the end row of each
    compound statement starting there (a `} else {` row opens the else block)."""
    top = any_node
    while top.parent is not None:
        top = top.parent
    opens: dict[int, set[int]] = {}
    stack = [top]
    while stack:
        n = stack.pop()
        if n.type == "compound_statement":
            opens.setdefault(n.start_point[0], set()).add(n.end_point[0])
        stack.extend(n.children)
    changed = True
    while changed:
        changed = False
        for row in list(rows):
            for end in opens.get(row, ()):
                if end not in rows:
                    rows.add(end)
                    changed = True


def _enclosing_rows(node) -> set[int]:
    """Rows that keep a retained statement syntactically closed: the header and
    braces of every enclosing block and the function signature."""
    rows: set[int] = set()
    cur = node.parent
    while cur is not None:
        t = cur.type
        if t == "compound_statement":
            rows.add(cur.start_point[0]); rows.add(cur.end_point[0])
        elif t in _CONTROL_TYPES:
            rows.update(range(cur.start_point[0], _header_end_row(cur) + 1))
            if t == "do_statement":
                rows.add(cur.end_point[0])
        elif t == "function_definition":
            body = next((c for c in cur.children if c.type == "compound_statement"), None)
            rows.update(range(cur.start_point[0], (body.start_point[0] if body else cur.start_point[0]) + 1))
            if body:
                rows.add(body.end_point[0])
            break
        cur = cur.parent
    return rows
