"""Independent dynamic check of an ESBMC verdict.

The program is compiled with AddressSanitizer and UBSan in the verification
image and driven with boundary-value and mutated inputs on stdin, files named in
the source and environment variables read by the source.  A sanitizer report is
compared with the property ESBMC violated.

VULNERABLE:  confirmed_exact (same kind and line) > confirmed_function > confirmed_class
             (compatible kind) > other_defect (a different real defect) > not_reproduced
SAFE:        counterexample_found (a sanitizer fired: possible false SAFE) or
             no_crash_found

A search that finds nothing proves nothing, so `not_reproduced` is not evidence
that a VULNERABLE label is wrong, only that this campaign did not reach it.
`env_apis` lists environment calls (stat, open, localtime_r, ...) in the source:
ESBMC treats their results as unconstrained, a real run sees one environment, so
a program that calls them can be VULNERABLE under the model and still not
reproduce.  `env_dependent` records that, and the export keeps both facts.

Only the sanitizer classes ESBMC also checks are enabled (address errors, signed
overflow, shifts, division by zero, null, bounds); other UBSan findings such as
nonnull-attribute are out of scope and never counted.
"""
import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "confirm_runner.py")

COMPATIBLE = {
    "memory-safety:null": {"null-deref", "segv"},
    "memory-safety:lifetime": {"heap-use-after-free", "attempting double-free", "attempting free on address which was not malloc()-ed",
                               "stack-use-after-return", "stack-use-after-scope", "bad-free", "null-deref", "segv"},
    "memory-safety:bounds": {"heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow", "stack-buffer-underflow",
                             "heap-buffer-underflow", "segv", "null-deref", "dynamic-stack-buffer-overflow", "memcpy-param-overlap", "array-bounds", "pointer-overflow",
                             "negative-size-param", "strcpy-param-overlap", "bad-free"},
    "resource-leak": {"leak"},
    "ub:signed-overflow": {"signed-overflow"},
    "ub:arithmetic": {"division-by-zero"},
    "ub:shift": {"shift"},
    "ub:vla": {"vla-bound"},
}


def compare(label: str, category: Optional[str], prop_function: Optional[str], prop_line: Optional[int],
            run: Dict[str, Any]) -> str:
    if not run.get("compiled"):
        return "compile_error"
    f = run.get("finding")
    if label == "SAFE":
        return "counterexample_found" if f else "no_crash_found"
    if not f:
        return "not_reproduced"
    kind = f["kind"]
    ok = kind in COMPATIBLE.get(category or "", set())
    if ok and prop_line and f.get("line") == prop_line:
        return "confirmed_exact"
    if ok and prop_function and f.get("function") == prop_function:
        return "confirmed_function"
    return "confirmed_class" if ok else "other_defect"


def runner_args(ext: str, seed: int, budget: float, root: str = "/work", runs: Optional[int] = None) -> list:
    """argv of confirm_runner.py for a source file named source.<ext> under *root*."""
    return ["python3", f"{root}/confirm_runner.py", "--source", f"{root}/source.{ext}",
            "--language", "cpp" if ext == "cpp" else "c", "--seed", str(seed), "--budget", str(budget),
            "--hints", f"{root}/hints.json"] + (["--runs", str(runs)] if runs else [])


_CE_INT = re.compile(r"[=,]\s*(-?\d+)\b(?!\.)")
_CE_ARRAY = re.compile(r"=\s*\{\s*(\d+(?:\s*,\s*\d+){1,})\s*\}")


def counterexample_hints(esbmc_log: str, meta: Optional[Dict[str, Any]] = None,
                         seeds: Optional[List[bytes]] = None) -> Dict[str, Any]:
    """Values ESBMC chose on the violating path, for the sanitizer search to try first.

    The trace shows variables after the program decoded them (a magic as a uint32, a
    command as a char array), not the raw input, so these are fed to the runner as
    integers for header fields and as byte tokens to splice in, not replayed verbatim.
    `meta['testcase']` (the --generate-testcase values, in order) adds a seed made of its
    byte-sized values.  *seeds* are explicit inputs (an LLM-written proof of concept).
    """
    log = esbmc_log or ""
    k = log.find("[Counterexample]")
    trace = log[k:] if k >= 0 else ""
    ints, tokens = set(), []
    for m in _CE_ARRAY.finditer(trace):
        vals = [int(x) for x in m.group(1).split(",")]
        raw = bytes(v for v in vals if 0 <= v < 256)
        raw = raw.split(b"\x00")[0] if raw[:1] != b"\x00" else raw.rstrip(b"\x00")
        if len(raw) >= 2:
            tokens.append(raw)
    for m in _CE_INT.finditer(trace):
        v = int(m.group(1))
        if abs(v) >= 2 and -2 ** 63 <= v < 2 ** 64:
            ints.add(v)
            if v >= 2 ** 29:  # ESBMC assumes malloc succeeds; the real allocator caps at 512 MB,
                ints.add((v & 0xFFFF) | 0x10000)  # so also try a size that still truncates but fits
    all_seeds = list(seeds or [])
    tc = (meta or {}).get("testcase") or []
    if tc:
        all_seeds.append(bytes(int(v) % 256 for v in tc if -128 <= int(v) < 256))
        ints.update(int(v) for v in tc if abs(int(v)) >= 2)
    return {"seeds": [base64.b64encode(x).decode() for x in all_seeds if x],
            "tokens": [base64.b64encode(t).decode() for t in tokens[:64]],
            "ints": sorted(ints, key=abs)[:256]}


def write_job(td: str, code: str, ext: str, hints: Optional[Dict[str, Any]] = None) -> None:
    """Lay out source, runner and hints in *td*, which is mounted read-only at /work."""
    with open(os.path.join(td, f"source.{ext}"), "w", encoding="utf-8") as f:
        f.write(code)
    shutil.copy(RUNNER, os.path.join(td, "confirm_runner.py"))
    with open(os.path.join(td, "hints.json"), "w") as f:
        json.dump(hints or {}, f)


def parse_runner_output(stdout: str) -> Dict[str, Any]:
    """The runner prints one JSON object; it is the last line of its output."""
    return json.loads(stdout.strip().splitlines()[-1])


def finalize(run: Dict[str, Any], label: str, category: Optional[str], prop_function: Optional[str],
             prop_line: Optional[int]) -> Dict[str, Any]:
    run["result"] = compare(label, category, prop_function, prop_line, run)
    run["env_dependent"] = bool(run.get("env_apis"))
    return run


def target_property(label: str, esbmc_log: str, meta: Optional[Dict[str, Any]]):
    """-> (category, function, line) of the property ESBMC violated, for compare()."""
    from .provenance import category as _category, trigger_line
    from ..agents.esbmc_verification import parse_violated_properties
    meta = meta or {}
    props = meta.get('violated_properties') or parse_violated_properties(esbmc_log or '')
    pr = props[0] if props else {}
    cat = _category(label, esbmc_log or '', meta).get('category') if label == 'VULNERABLE' else None
    line = pr.get('line') if pr.get('in_program') else trigger_line(esbmc_log or '')
    return cat, (pr.get('function') if pr.get('in_program') else None), line


def summary(res: Dict[str, Any]) -> Dict[str, Any]:
    """The part of a confirmation stored in verification_meta['confirmation']."""
    return {k: res.get(k) for k in ('result', 'runs', 'channels', 'env_apis', 'env_dependent', 'finding',
                                    'elapsed_s', 'timeouts', 'error', 'sanitizer_flags', 'sanitizer_env',
                                    'seeds', 'tokens')}


def confirm(code: str, language: str, label: str, category: Optional[str] = None,
            prop_function: Optional[str] = None, prop_line: Optional[int] = None,
            image: str = "esbmc:8.4", seed: int = 1, budget: float = 40, mem: str = "2g",
            hints: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ext = "cpp" if language in ("cpp", "c++") else "c"
    with tempfile.TemporaryDirectory() as td:
        # Mount only the temp dir, with the runner copied in: the Docker daemon cannot
        # always read the repository path (network home directories), but it can
        # always read the system temp dir.
        write_job(td, code, ext, hints)
        os.chmod(td, 0o755)
        cmd = ["docker", "run", "--rm", "--network", "none", "--memory", mem, "--cpus", "2",
               "-v", f"{td}:/work:ro", "-w", "/work", "--entrypoint", "python3", image,
               *runner_args(ext, seed, budget)[1:]]
        p = None
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=budget + 180)
            run = parse_runner_output(p.stdout)
        except Exception as e:
            detail = (p.stderr or p.stdout or "").strip()[-300:] if p is not None else ""
            return {"result": "runner_error", "error": f"{e}: {detail}"[:400]}
    run["result"] = compare(label, category, prop_function, prop_line, run)
    run["env_dependent"] = bool(run.get("env_apis"))
    return run


_OVERFLOW_REGION = {"heap-buffer-overflow": "CWE-122", "stack-buffer-overflow": "CWE-121",
                    "dynamic-stack-buffer-overflow": "CWE-121", "stack-buffer-underflow": "CWE-124",
                    "heap-buffer-underflow": "CWE-124", "global-buffer-overflow": "CWE-788"}
_KIND_CWES = {"heap-use-after-free": ["CWE-416"], "attempting double-free": ["CWE-415"],
              "stack-use-after-return": ["CWE-562"], "stack-use-after-scope": ["CWE-825"],
              "null-deref": ["CWE-476"], "segv": ["CWE-119"], "leak": ["CWE-401"],
              "signed-overflow": ["CWE-190"], "shift": ["CWE-1335"], "division-by-zero": ["CWE-369"],
              "array-bounds": ["CWE-129"], "pointer-overflow": ["CWE-823"], "vla-bound": ["CWE-129"],
              "memcpy-param-overlap": ["CWE-119"], "strcpy-param-overlap": ["CWE-119"],
              "negative-size-param": ["CWE-195"], "bad-free": ["CWE-590"]}


def sanitizer_cwes(finding: Optional[Dict[str, Any]]) -> List[str]:
    """CWE ids a sanitizer report pins down.  ASan names the region and the access, so a
    heap write past the end is CWE-122 + CWE-787 where ESBMC can only say 'bounds'."""
    if not finding:
        return []
    kind, report = finding.get("kind") or "", finding.get("report") or ""
    if kind in _OVERFLOW_REGION:
        access = "CWE-787" if re.search(r"\bWRITE of size", report) else "CWE-125" if re.search(r"\bREAD of size", report) else None
        return [_OVERFLOW_REGION[kind]] + ([access] if access else [])
    if kind == "attempting free on address which was not malloc()-ed":
        return ["CWE-761"] if re.search(r"is located \d+ bytes inside of", report) else ["CWE-590"]
    return list(_KIND_CWES.get(kind, []))


def reproduction_fields(conf: Dict[str, Any], label: str) -> Dict[str, Any]:
    """DB columns for a confirmation record.  Any sanitizer report on a VULNERABLE program
    counts as REPRODUCED, also when it is a different defect than the one ESBMC named
    (result 'other_defect'): the label is backed by a crash either way, and the match level
    stays in verification_meta['confirmation']['result'].  None for SAFE (the field
    describes VULNERABLE labels; a SAFE crash is recorded as counterexample_found)."""
    f = conf.get("finding")
    if label != "VULNERABLE":
        return {"reproduced": None}
    if not f:
        return {"reproduced": "NOT_REPRODUCED", "sanitizer_log": None, "poc_input": None, "sanitizer_cwes": None}
    return {"reproduced": "REPRODUCED", "sanitizer_log": f.get("report"), "poc_input": f.get("input_b64"),
            "sanitizer_cwes": sanitizer_cwes(f)}
