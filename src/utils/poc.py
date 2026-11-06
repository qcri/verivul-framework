"""LLM-written proof-of-concept inputs for ESBMC violations the sanitizer search did not reach.

The model answers with candidate inputs in a small chunk language (text, hex, packed
integers, repeat) rather than raw bytes or code, so a 70 KB input costs a few tokens and
nothing the model writes is ever executed.  Candidates go to the runner as seeds.
"""
import json
import re
import struct
from typing import Any, Dict, List, Optional

from .provenance import violation_context

MAX_INPUT = 1 << 20
PACK = {"u8": "<B", "u16le": "<H", "u16be": ">H", "u32le": "<I", "u32be": ">I", "u64le": "<Q", "u64be": ">Q",
        "i32le": "<i", "i32be": ">i"}


def build_prompt(instruction: str, code: str, esbmc_log: str, meta: Optional[Dict[str, Any]] = None,
                 tried: Optional[List[str]] = None) -> str:
    log = esbmc_log or ""
    k = log.find("[Counterexample]")
    trace = log[k:] if k >= 0 else log[-6000:]
    if len(trace) > 12000:  # long traces are mostly repeated array dumps; keep both ends
        trace = trace[:6000] + "\n...\n" + trace[-6000:]
    where = violation_context(code, log, meta)
    feedback = ("\n\n# Earlier candidates that did not trigger a sanitizer report:\n" + "\n".join(tried)) if tried else ""
    return (f"# Instruction:\n{instruction}\n\n# Program:\n```\n{code}\n```\n\n"
            f"# Where the violation happens:\n{where}\n\n# ESBMC counterexample:\n```\n{trace}\n```{feedback}")


def _chunk(c: Dict[str, Any]) -> bytes:
    if "text" in c:
        return str(c["text"]).encode("latin-1", "replace")
    if "hex" in c:
        return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", str(c["hex"])))
    if "repeat" in c:
        r = c["repeat"]
        unit = _chunk({k: v for k, v in r.items() if k in ("text", "hex")})
        n = int(r.get("count", 0))
        if not unit or n < 0 or len(unit) * n > MAX_INPUT:
            raise ValueError("repeat out of range")
        return unit * n
    for kind, fmt in PACK.items():
        if kind in c:
            v = int(c[kind], 0) if isinstance(c[kind], str) else int(c[kind])
            bits = struct.calcsize(fmt) * 8
            return struct.pack(fmt, v if fmt[1].islower() else v % (1 << bits))
    raise ValueError(f"unknown chunk {sorted(c)}")


def parse_candidates(response: str) -> List[bytes]:
    """Candidate inputs from a model answer; malformed candidates are skipped."""
    text = re.sub(r"<think>.*?</think>", "", response or "", flags=re.DOTALL)
    m = re.search(r"<poc>(.*?)</poc>", text, re.DOTALL)
    body = (m.group(1) if m else text).strip()
    body = re.sub(r"^```\w*|```$", "", body.strip()).strip()
    try:
        data = json.loads(body)
    except ValueError:
        return []
    out = []
    for cand in (data.get("candidates") if isinstance(data, dict) else data) or []:
        try:
            b = b"".join(_chunk(c) for c in cand)
        except (ValueError, TypeError, KeyError, struct.error, AttributeError):
            continue
        if b and len(b) <= MAX_INPUT:
            out.append(b)
    return out[:3]


def describe(b: bytes, limit: int = 160) -> str:
    """Short printable form of a tried candidate, for the retry prompt."""
    s = repr(b[:limit])[2:-1]
    return s + (f"... ({len(b)} bytes)" if len(b) > limit else "")
