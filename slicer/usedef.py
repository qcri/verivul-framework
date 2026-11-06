"""
Use-def extractor for C/C++ functions using tree-sitter.

Produces a flattened list of Stmt objects from a function body, each carrying:
  - defs:      variables defined (written) by this statement
  - uses:      variables used (read) by this statement
  - calls:     list of (callee_name, [arg_var_names], result_var | None)
  - ctrl_deps: indices of ancestor control-condition statements
"""
from __future__ import annotations
from dataclasses import dataclass, field
from tree_sitter import Node
from .parsers import get_parser

# ── Node type constants ────────────────────────────────────────────────────────

# Statement-level node types we "flatten" (descend into their bodies)
CONTROL_NODES = {
    "if_statement",
    "while_statement",
    "for_statement",
    "do_statement",
    "switch_statement",
}

# Statement-level leaf nodes (do not recurse into their children for new stmts)
STMT_NODES = {
    "declaration",
    "expression_statement",
    "return_statement",
    "break_statement",
    "continue_statement",
    "goto_statement",
}


# ── Data model ────────────────────────────────────────────────────────────────


@dataclass
class CallSite:
    callee: str
    arg_vars: list[str]
    result_var: str | None = None    # variable receiving return value, if any


@dataclass
class Stmt:
    idx: int
    src_line: int           # 1-based line in (possibly prepended) source
    text: str               # raw source text of this statement
    node: object            # tree-sitter Node (not used in serialisation)
    defs: set[str] = field(default_factory=set)
    uses: set[str] = field(default_factory=set)
    calls: list[CallSite] = field(default_factory=list)
    ctrl_deps: list[int] = field(default_factory=list)   # Stmt indices
    is_ctrl_cond: bool = False   # True → this is an if/while/for condition stmt


# ── Variable name extraction ───────────────────────────────────────────────────


def _collect_identifiers(node: Node) -> set[str]:
    """Recursively collect all identifier names under `node`."""
    names: set[str] = set()
    if node.type == "identifier":
        names.add(node.text.decode("utf-8", errors="replace"))
    for child in node.children:
        names |= _collect_identifiers(child)
    return names


def _lhs_def(node: Node) -> str | None:
    """Extract the variable name being defined by an LHS node (best-effort)."""
    if node.type == "identifier":
        return node.text.decode("utf-8", errors="replace")
    # pointer / array declarators: *x, x[]
    if node.type in ("pointer_declarator", "array_declarator", "reference_declarator"):
        for child in node.children:
            result = _lhs_def(child)
            if result:
                return result
    # field access: a->b or a.b → defining 'a' (conservative)
    if node.type in ("field_expression",):
        return _lhs_def(node.children[0])
    # subscript: a[i] → defining 'a'
    if node.type == "subscript_expression":
        return _lhs_def(node.children[0])
    # parenthesised
    if node.type == "parenthesized_expression":
        inner = next((c for c in node.children if c.type != "(" and c.type != ")"), None)
        if inner:
            return _lhs_def(inner)
    return None


def _extract_call_sites(node: Node, result_var: str | None) -> list[CallSite]:
    """Find all call_expression nodes under `node` and build CallSite objects."""
    sites: list[CallSite] = []
    if node.type == "call_expression":
        # callee name
        fn_node = node.child_by_field_name("function") or node.children[0]
        callee = fn_node.text.decode("utf-8", errors="replace").strip()
        # strip qualifiers: ns::f → f,  obj->f → f,  obj.f → f
        callee = callee.rsplit("::", 1)[-1]
        callee = callee.rsplit("->", 1)[-1]
        callee = callee.rsplit(".", 1)[-1]
        # argument variable names
        args_node = node.child_by_field_name("arguments") or (
            node.children[1] if len(node.children) > 1 else None
        )
        arg_vars: list[str] = []
        if args_node:
            for child in args_node.children:
                if child.type in ("(", ")", ","):
                    continue
                # Extract the "root" variable from an expression
                ids = _collect_identifiers(child)
                arg_vars.extend(sorted(ids))
        sites.append(CallSite(callee=callee, arg_vars=arg_vars, result_var=result_var))
    else:
        for child in node.children:
            sites.extend(_extract_call_sites(child, result_var))
    return sites


# ── Statement use/def analysis ─────────────────────────────────────────────────


def _analyse_declaration(node: Node) -> tuple[set[str], set[str], list[CallSite]]:
    defs: set[str] = set()
    uses: set[str] = set()
    calls: list[CallSite] = []

    for child in node.children:
        if child.type == "init_declarator":
            # int x = <rhs>
            decl_id = child.child_by_field_name("declarator") or child.children[0]
            var = _lhs_def(decl_id)
            if var:
                defs.add(var)
            rhs = child.child_by_field_name("value")
            if rhs is None:
                # fallback: last child after '='
                children = [c for c in child.children if c.type not in ("=",)]
                rhs = children[-1] if len(children) > 1 else None
            if rhs:
                uses |= _collect_identifiers(rhs)
                calls.extend(_extract_call_sites(rhs, var))
        elif child.type in (
            "pointer_declarator",
            "array_declarator",
            "identifier",
        ):
            var = _lhs_def(child)
            if var:
                defs.add(var)

    return defs, uses, calls


def _analyse_expression_stmt(
    node: Node,
) -> tuple[set[str], set[str], list[CallSite]]:
    defs: set[str] = set()
    uses: set[str] = set()
    calls: list[CallSite] = []

    inner = next(
        (c for c in node.children if c.type not in (";",)), None
    )
    if inner is None:
        return defs, uses, calls

    if inner.type == "assignment_expression":
        lhs = inner.child_by_field_name("left") or inner.children[0]
        rhs = inner.child_by_field_name("right")
        var = _lhs_def(lhs)
        if var:
            defs.add(var)
        # LHS may also use vars (e.g. buf[i] uses buf and i on write)
        if lhs.type in ("subscript_expression", "field_expression",
                        "pointer_expression", "dereference_expression"):
            uses |= _collect_identifiers(lhs)
        if rhs:
            uses |= _collect_identifiers(rhs)
            calls.extend(_extract_call_sites(rhs, var))
        # compound assignment (+=, -=, …): LHS is also used
        op = inner.child_by_field_name("operator")
        if op and op.text not in (b"=",):
            if var:
                uses.add(var)
    elif inner.type == "update_expression":  # i++, ++i
        child = next((c for c in inner.children if c.type == "identifier"), None)
        if child:
            var = child.text.decode("utf-8", errors="replace")
            defs.add(var)
            uses.add(var)
    else:
        # function call or other expression
        uses |= _collect_identifiers(inner)
        calls.extend(_extract_call_sites(inner, None))

    return defs, uses, calls


def _analyse_return(node: Node) -> tuple[set[str], set[str], list[CallSite]]:
    uses: set[str] = set()
    calls: list[CallSite] = []
    for child in node.children:
        if child.type in ("return", ";"):
            continue
        uses |= _collect_identifiers(child)
        calls.extend(_extract_call_sites(child, None))
    return set(), uses, calls


# ── Flattening ────────────────────────────────────────────────────────────────


def _flatten(
    node: Node,
    src_bytes: bytes,
    stmts: list[Stmt],
    ctrl_stack: list[int],
) -> None:
    """Recursively flatten a compound or control-flow node into `stmts`."""

    if node.type == "compound_statement":
        for child in node.children:
            if child.type not in ("{", "}"):
                _flatten(child, src_bytes, stmts, ctrl_stack)
        return

    if node.type in STMT_NODES:
        idx = len(stmts)
        text = src_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
        line = node.start_point[0] + 1  # tree-sitter rows are 0-based

        defs: set[str] = set()
        uses: set[str] = set()
        calls: list[CallSite] = []

        if node.type == "declaration":
            defs, uses, calls = _analyse_declaration(node)
        elif node.type == "expression_statement":
            defs, uses, calls = _analyse_expression_stmt(node)
        elif node.type == "return_statement":
            defs, uses, calls = _analyse_return(node)
        # break/continue/goto: no defs/uses

        stmts.append(
            Stmt(
                idx=idx,
                src_line=line,
                text=text,
                node=node,
                defs=defs,
                uses=uses,
                calls=calls,
                ctrl_deps=list(ctrl_stack),
            )
        )
        return

    if node.type in CONTROL_NODES:
        # ── Build a synthetic "condition" statement ────────────────────────────
        cond_node = _get_condition(node)
        cond_uses: set[str] = set()
        cond_calls: list[CallSite] = []
        if cond_node:
            cond_uses = _collect_identifiers(cond_node)
            cond_calls = _extract_call_sites(cond_node, None)

        cond_idx = len(stmts)
        cond_text = src_bytes[node.start_byte : node.start_byte + 80].decode(
            "utf-8", errors="replace"
        ).split("\n")[0]
        stmts.append(
            Stmt(
                idx=cond_idx,
                src_line=node.start_point[0] + 1,
                text=cond_text,
                node=node,
                defs=set(),
                uses=cond_uses,
                calls=cond_calls,
                ctrl_deps=list(ctrl_stack),
                is_ctrl_cond=True,
            )
        )

        # for_statement init may define variables (e.g. int i = 0)
        if node.type == "for_statement":
            init = node.child_by_field_name("initializer")
            if init and init.type not in (";",):
                _flatten(init, src_bytes, stmts, ctrl_stack + [cond_idx])

        # Recurse into bodies with this condition on the stack
        for child in node.children:
            if child.type == "compound_statement":
                _flatten(child, src_bytes, stmts, ctrl_stack + [cond_idx])
            elif child.type in STMT_NODES | CONTROL_NODES:
                _flatten(child, src_bytes, stmts, ctrl_stack + [cond_idx])
            # else_clause
            elif child.type == "else_clause":
                for grandchild in child.children:
                    if grandchild.type in {"compound_statement"} | CONTROL_NODES:
                        _flatten(grandchild, src_bytes, stmts, ctrl_stack + [cond_idx])
        return

    # case_statement, labeled_statement, etc.
    for child in node.children:
        _flatten(child, src_bytes, stmts, ctrl_stack)


def _get_condition(node: Node) -> Node | None:
    """Extract the condition sub-node from an if/while/for/do node."""
    if node.type in ("if_statement", "while_statement", "do_statement"):
        cond = node.child_by_field_name("condition")
        if cond:
            # strip enclosing parentheses
            inner = next(
                (c for c in cond.children if c.type not in ("(", ")")), cond
            )
            return inner
    if node.type == "for_statement":
        cond = node.child_by_field_name("condition")
        return cond
    return None


# ── Public API ────────────────────────────────────────────────────────────────


def get_function_params(src: str, language: str = "c") -> list[str]:
    """Return the parameter names of the first function defined in `src`."""
    parser = get_parser(language)
    tree = parser.parse(src.encode("utf-8"))
    params: list[str] = []

    def find_params(node: Node) -> bool:
        if node.type == "parameter_declaration":
            for child in node.children:
                name = _lhs_def(child)
                if name:
                    params.append(name)
                    return False
            # fallback: last identifier
            ids = _collect_identifiers(node)
            params.extend(sorted(ids))
            return False
        for child in node.children:
            find_params(child)
        return True

    find_params(tree.root_node)
    return params


def extract_statements(src: str, language: str = "c") -> list[Stmt]:
    """
    Parse `src` (a single C/C++ function) and return a flattened list of Stmt.

    The function body may or may not include the outer function signature —
    if a function_definition is found, we use it; otherwise we try
    compound_statement directly.
    """
    parser = get_parser(language)
    src_bytes = src.encode("utf-8")
    tree = parser.parse(src_bytes)

    root = tree.root_node
    body: Node | None = None

    # Find first function_definition → grab its compound_statement body
    def find_body(n: Node) -> Node | None:
        if n.type == "function_definition":
            for child in n.children:
                if child.type == "compound_statement":
                    return child
        if n.type == "compound_statement" and body is None:
            return n
        for child in n.children:
            result = find_body(child)
            if result:
                return result
        return None

    body = find_body(root)
    if body is None:
        return []

    stmts: list[Stmt] = []
    _flatten(body, src_bytes, stmts, ctrl_stack=[])
    # Re-index (in case anything shifted)
    for i, s in enumerate(stmts):
        s.idx = i
    return stmts
