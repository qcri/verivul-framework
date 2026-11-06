# slicer

Heuristic inter-procedural backward program slicer for C/C++ vulnerability code.
It works on source text via [tree-sitter](https://tree-sitter.github.io/) and needs no compilation or repository cloning.

## Install

```bash
pip install tree-sitter tree-sitter-c tree-sitter-cpp
```

## Python API

```python
from slicer import slice_function

code = """
int process(int *buf, int len, int offset) {
    int total = 0;
    log_debug("enter");
    if (offset < 0) return -1;
    int idx = offset + len;
    total = buf[idx];
    return total;
}
"""

fixed = """
int process(int *buf, int len, int offset) {
    int total = 0;
    log_debug("enter");
    if (offset < 0) return -1;
    int idx = offset + len;
    if (idx >= MAX_BUF) return -1;
    total = buf[idx];
    return total;
}
"""

result = slice_function(code, fixed_src=fixed, language="c")
print(result.sliced_code)
# int process(int *buf, int len, int offset) {
#     int idx = offset + len;
#     total = buf[idx];
#     return total;
# }

print(result.num_stmts_before, "→", result.num_stmts_after)  # 6 → 3
```

### With CWE fallback (no patch available)

```python
result = slice_function(code, cwe="CWE-119", language="c")
```

### With neighbor functions (inter-procedural)

```python
result = slice_function(
    code,
    fixed_src=fixed,
    language="c",
    neighbor_functions=[
        {"name": "compute_offset", "code": "int compute_offset(int a, int b) { return a + b; }"}
    ],
)
print(result.inter_proc_calls)  # ["compute_offset"] if resolved
```

## CLI (batch JSONL)

Input format, one JSON object per line:

```json
{"uuid": "1", "code": "int f(int x) { return x+1; }", "language": "c"}
```

Optional fields: `fixed_code`, `cwes` (list), `neighbor_functions` (list of `{name, code}`).

```bash
python -m slicer.run --input data.jsonl --output sliced.jsonl --workers 4
```

Output adds: `slice_code`, `slice_lines`, `criterion_lines`, `slice_stmts_before`, `slice_stmts_after`, `inter_proc_calls`.

## Dataset adapters

Convert raw datasets to the universal input format:

```bash
# ICVul
python -m slicer.adapters.icvul --output icvul_input.jsonl

# ReposVul
python -m slicer.adapters.reposvul --output reposvul_input.jsonl
```

Then slice:

```bash
python -m slicer.run --input icvul_input.jsonl --output icvul_sliced.jsonl --workers 6
```

## How it works

1. **Parse**: tree-sitter CST to a linearized statement sequence with def, use and call sets
2. **Criterion**: changed lines from `difflib` (if `fixed_code` given), else CWE-pattern heuristic
3. **Backward slice**: fixed-point worklist: include statements whose defs intersect the working set
4. **Call resolution**: three tiers, stdlib summaries (about 60 functions), co-commit callee inlining (depth up to 3), conservative identity
5. **Control deps**: add enclosing `if`/`for`/`while`/`switch` for every included statement
