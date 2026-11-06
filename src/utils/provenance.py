"""Derived per-record fields: trigger line and provenance category of a verdict."""
import re
from typing import Any, Dict, List, Optional, Tuple

from src.agents.esbmc_verification import parse_violated_properties

_STATE_SRC = re.compile(r'State \d+ file /work/source\.\w+ line (\d+) column \d+ function (\w+)')
LIB_PREFIX = ('/home/runner/', '/usr/include', '/tmp/esbmc')


def trigger_line(log: str) -> Optional[int]:
    """1-based line in the verified program that the violation is attributed to."""
    props = parse_violated_properties(log or '')
    for p in props:
        if p['in_program']:
            return p['line']
    states = _STATE_SRC.findall(log or '')
    return int(states[-1][0]) if states else None


def violation_context(code: str, log: str, meta: Optional[Dict[str, Any]] = None, radius: int = 4) -> str:
    """Plain-language location of an ESBMC violation, for a model asked to fix it.

    ESBMC often reports the violated property inside its own C library model (fread, memcpy:
    "array bounds violated" at string.c:286), which says nothing about where the *program*
    is at fault.  The counterexample's last state in the program names the call that leads
    there; this returns that function, line and the surrounding source.
    """
    props = (meta or {}).get('violated_properties') or parse_violated_properties(log or '')
    p = props[0] if props else None
    states = _STATE_SRC.findall(log or '')
    if p and p.get('in_program'):
        line, func = p['line'], p.get('function')
    elif states:
        line, func = int(states[-1][0]), states[-1][1]
    else:
        line, func = (p or {}).get('line'), (p or {}).get('function')
    if not p and not line:
        return ''
    parts = []
    if p:
        where = 'in the program' if p.get('in_program') else f"inside the C library model ({p.get('function')})"
        cwes = ', '.join(p.get('cwes') or [])
        parts.append(f"ESBMC violated: {p['description']}{' [' + cwes + ']' if cwes else ''}, raised {where}.")
    lines = (code or '').splitlines()
    if line and 1 <= line <= len(lines):
        lo, hi = max(1, line - radius), min(len(lines), line + radius)
        snippet = '\n'.join(f"{'>>' if n == line else '  '} {n}: {lines[n - 1]}" for n in range(lo, hi + 1))
        parts.append(f"The last program statement the counterexample executes before the violation is line {line}"
                     + (f" in {func}()" if func else '')
                     + f" (marked >>); the faulty call or value is at or after it:\n{snippet}")
    return '\n'.join(parts)


def category(label: str, log: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Classify what produced a label by the class of the violated property."""
    if label != 'VULNERABLE':
        return {'category': 'safe' if label == 'SAFE' else 'inconclusive', 'in_program': None}
    props = (meta or {}).get('violated_properties') or parse_violated_properties(log or '')
    if not props:
        return {'category': 'unparsed', 'in_program': None}
    desc = props[0]['description'].lower()
    in_program = bool(props[0]['in_program'])
    if 'forgotten memory' in desc or 'memory leak' in desc:
        cat = 'resource-leak'
    elif 'invalidated dynamic object' in desc or 'freed' in desc or 'non-dynamic memory' in desc:
        cat = 'memory-safety:lifetime'
    elif 'null pointer' in desc or 'pointer is null' in desc:
        cat = 'memory-safety:null'
    elif 'bounds' in desc or 'buffer overflow' in desc or 'out of bounds' in desc or 'invalid pointer' in desc \
            or 'dereference failure' in desc:
        cat = 'memory-safety:bounds'
    elif 'shl' in desc or 'shift' in desc:  # "arithmetic overflow on shl" is reported by UBSan as a shift
        cat = 'ub:shift'
    elif 'arithmetic overflow' in desc or 'integer overflow' in desc:
        cat = 'ub:signed-overflow'
    elif 'division by zero' in desc or 'nan' in desc:
        cat = 'ub:arithmetic'
    elif 'vla' in desc:
        cat = 'ub:vla'
    elif 'alignment' in desc:
        cat = 'ub:alignment'
    elif 'unwinding assertion' in desc:
        cat = 'environment:unwinding'
    elif 'assertion' in desc:
        cat = 'assertion'
    else:
        cat = 'other'
    return {'category': cat, 'in_program': in_program, 'property': props[0]['description'],
            'property_function': props[0]['function'], 'property_line': props[0]['line']}


def lexically_obvious(code: str, line_no: Optional[int]) -> bool:
    """Whether the violating line uses an API a grep-based scanner would flag."""
    if not line_no:
        return False
    lines = code.split('\n')
    if not 0 < line_no <= len(lines):
        return False
    return bool(re.search(r'\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(|scanf\s*\([^)]*"[^"]*%s', lines[line_no - 1]))
