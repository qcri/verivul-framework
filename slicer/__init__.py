"""
Standalone heuristic inter-procedural program slicer for C/C++ code.

Usage:
    # Generic CLI — reads universal JSONL, outputs sliced JSONL
    python -m slicer.run --input input.jsonl --output sliced.jsonl

    # Dataset adapters — convert raw dataset → universal format → sliced
    python -m slicer.adapters.icvul   --output icvul_slicer_input.jsonl
    python -m slicer.adapters.reposvul --output reposvul_slicer_input.jsonl

    # API
    from slicer import slice_function
    result = slice_function(code, fixed_src=fixed, cwe="CWE-119", language="c")
"""
from .engine import slice_function, SliceResult
from .usedef import extract_statements, Stmt
from .parsers import get_parser

__all__ = ["slice_function", "SliceResult", "extract_statements", "Stmt", "get_parser"]
