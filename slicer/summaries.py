"""
Stdlib / POSIX function summaries for inter-procedural slicing.

Each entry describes which parameter positions contribute to the return value
and which pointer parameters are written (side-effect outputs).

Format:
    FUNCTION_NAME: {
        "result_deps": [param_idx, ...],   # which args the return value depends on
        "writes":      [param_idx, ...],   # which pointer args may be modified
    }

Param indices are 0-based.  Use -1 as sentinel meaning "all args".
"""

STDLIB_SUMMARIES: dict[str, dict] = {
    # ── Memory operations ──────────────────────────────────────────────────────
    "memcpy":    {"result_deps": [0],       "writes": [0]},      # dst <- src,n
    "memmove":   {"result_deps": [0],       "writes": [0]},
    "memset":    {"result_deps": [0],       "writes": [0]},
    "memcmp":    {"result_deps": [-1],      "writes": []},
    "memchr":    {"result_deps": [0, 2],    "writes": []},
    # ── String operations ──────────────────────────────────────────────────────
    "strcpy":    {"result_deps": [0],       "writes": [0]},
    "strncpy":   {"result_deps": [0],       "writes": [0]},
    "strcat":    {"result_deps": [0],       "writes": [0]},
    "strncat":   {"result_deps": [0],       "writes": [0]},
    "strcmp":    {"result_deps": [-1],      "writes": []},
    "strncmp":   {"result_deps": [-1],      "writes": []},
    "strcasecmp":{"result_deps": [-1],      "writes": []},
    "strlen":    {"result_deps": [0],       "writes": []},
    "strnlen":   {"result_deps": [0, 1],    "writes": []},
    "strstr":    {"result_deps": [0, 1],    "writes": []},
    "strchr":    {"result_deps": [0, 1],    "writes": []},
    "strrchr":   {"result_deps": [0, 1],    "writes": []},
    "strtok":    {"result_deps": [0, 1],    "writes": [0]},
    "strtok_r":  {"result_deps": [0, 1],    "writes": [0, 2]},
    "strtol":    {"result_deps": [0, 2],    "writes": [1]},
    "strtoul":   {"result_deps": [0, 2],    "writes": [1]},
    "strtoll":   {"result_deps": [0, 2],    "writes": [1]},
    "strtoull":  {"result_deps": [0, 2],    "writes": [1]},
    "atoi":      {"result_deps": [0],       "writes": []},
    "atol":      {"result_deps": [0],       "writes": []},
    "atof":      {"result_deps": [0],       "writes": []},
    # ── Formatting ────────────────────────────────────────────────────────────
    "sprintf":   {"result_deps": [1],       "writes": [0]},
    "snprintf":  {"result_deps": [2],       "writes": [0]},
    "sscanf":    {"result_deps": [0, 1],    "writes": [-1]},
    "printf":    {"result_deps": [0],       "writes": []},
    "fprintf":   {"result_deps": [1],       "writes": []},
    "vsnprintf": {"result_deps": [2],       "writes": [0]},
    "vsprintf":  {"result_deps": [1],       "writes": [0]},
    # ── Heap allocation ──────────────────────────────────────────────────────
    "malloc":    {"result_deps": [0],       "writes": []},
    "calloc":    {"result_deps": [0, 1],    "writes": []},
    "realloc":   {"result_deps": [0, 1],    "writes": []},
    "alloca":    {"result_deps": [0],       "writes": []},
    "free":      {"result_deps": [],        "writes": [0]},
    # ── I/O ──────────────────────────────────────────────────────────────────
    "read":      {"result_deps": [0, 2],    "writes": [1]},
    "write":     {"result_deps": [0, 2],    "writes": []},
    "recv":      {"result_deps": [0, 3],    "writes": [1]},
    "send":      {"result_deps": [0, 2, 3], "writes": []},
    "fread":     {"result_deps": [3, 2],    "writes": [0]},
    "fwrite":    {"result_deps": [3, 2],    "writes": []},
    "fgets":     {"result_deps": [2, 1],    "writes": [0]},
    "fputs":     {"result_deps": [0, 1],    "writes": []},
    "getc":      {"result_deps": [0],       "writes": []},
    "fgetc":     {"result_deps": [0],       "writes": []},
    "getchar":   {"result_deps": [],        "writes": []},
    # ── String/char classification ────────────────────────────────────────────
    "isdigit":   {"result_deps": [0],       "writes": []},
    "isalpha":   {"result_deps": [0],       "writes": []},
    "isspace":   {"result_deps": [0],       "writes": []},
    "tolower":   {"result_deps": [0],       "writes": []},
    "toupper":   {"result_deps": [0],       "writes": []},
    # ── Math ─────────────────────────────────────────────────────────────────
    "abs":       {"result_deps": [0],       "writes": []},
    "labs":      {"result_deps": [0],       "writes": []},
    "min":       {"result_deps": [-1],      "writes": []},
    "max":       {"result_deps": [-1],      "writes": []},
    # ── Network / socket ─────────────────────────────────────────────────────
    "htons":     {"result_deps": [0],       "writes": []},
    "ntohs":     {"result_deps": [0],       "writes": []},
    "htonl":     {"result_deps": [0],       "writes": []},
    "ntohl":     {"result_deps": [0],       "writes": []},
    # ── Misc ─────────────────────────────────────────────────────────────────
    "copy_from_user":   {"result_deps": [2],    "writes": [0]},
    "copy_to_user":     {"result_deps": [2],    "writes": [1]},
    "__copy_from_user": {"result_deps": [2],    "writes": [0]},
}


def apply_summary(
    callee: str,
    arg_vars: list[str],
    result_var: str | None,
) -> tuple[set[str], set[str]]:
    """
    Apply a stdlib summary.

    Returns:
        (result_deps, side_effect_vars)
        result_deps       – vars at call-site that result_var depends on
        side_effect_vars  – arg vars that may be modified (pointer writes)
    """
    summary = STDLIB_SUMMARIES.get(callee)
    if summary is None:
        # Unknown: conservative identity
        return set(arg_vars), set()

    rd_indices = summary["result_deps"]
    wr_indices = summary["writes"]

    if -1 in rd_indices:
        result_deps = set(arg_vars)
    else:
        result_deps = {arg_vars[i] for i in rd_indices if i < len(arg_vars)}

    if -1 in wr_indices:
        side_effects = set(arg_vars)
    else:
        side_effects = {arg_vars[i] for i in wr_indices if i < len(arg_vars)}

    return result_deps, side_effects
