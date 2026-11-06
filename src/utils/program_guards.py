"""Static rejections applied to generated C/C++ before compilation.

Each rule names a way a program would receive a label that is not about its own
logic (argv model, verifier intrinsics, unchecked threads) or would leak the
label through its text.  See tests/esbmc_cases/REPORT.md for the evidence.
"""
import re
from typing import Dict, List, Optional

ARGV_RE = re.compile(r'\b(argv|argc)\b|\bmain\s*\(\s*int\b')
INTRINSIC_RE = re.compile(r'__ESBMC_\w+|__VERIFIER_\w+|__CPROVER_\w+|\bnondet_\w+\s*\(|\bassert\s*\(\s*(0|false)\s*\)')
# Input other than stdin: the sanitizer search feeds stdin, so a defect behind a file or an
# environment variable is one it cannot reach to confirm.  Writing output files is fine.
FILE_INPUT_RE = re.compile(r'\bfopen\s*\([^;]*?,\s*"r|\b(?:std::)?(?:ifstream|fstream)\b|\bgetenv\s*\('
                           r'|\bopen\s*\([^;]*O_RDONLY|\bfreopen\s*\(')
THREAD_RE = re.compile(r'#\s*include\s*<(pthread|threads|omp)\.h>|\b(pthread_create|thrd_create|fork)\s*\(')
LEAKAGE_WORDS = (
    'vulnerable', 'vulnerability', 'vulnerabilities', 'vuln', 'exploit', 'exploitable', 'attack',
    'attacker', 'malicious', 'threat', 'flaw', 'danger', 'dangerous', 'safe', 'unsafe', 'secure',
    'insecure', 'benign', 'overflow', 'underflow', 'uaf', 'use_after_free', 'use-after-free',
    'double_free', 'double-free', 'dangling', 'remediate', 'remediation', 'sanitize', 'sanitized',
    'unsanitized', 'simulate', 'inject', 'injected', 'injection', 'cwe', 'cve', 'pwn', 'backdoor',
)
LEAKAGE_RE = re.compile(r'(?<![A-Za-z0-9])(' + '|'.join(re.escape(w) for w in LEAKAGE_WORDS) + r')(?![A-Za-z0-9])', re.I)
COMMENT_RE = re.compile(r'/\*.*?\*/|//[^\n]*', re.S)
STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')
IDENT_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
C_LANGS = ('c', 'cpp', 'c++', 'cuda')


def _identifier_words(code_no_comments: str) -> List[str]:
    words: List[str] = []
    for ident in IDENT_RE.findall(STRING_RE.sub('""', code_no_comments)):
        for part in re.split(r'_+|(?<=[a-z0-9])(?=[A-Z])', ident):
            if part:
                words.append(part.lower())
    return words


def leakage_hits(code: str) -> List[str]:
    """Weakness-signalling words in comments, string literals or identifiers."""
    hits = set()
    for m in COMMENT_RE.finditer(code):
        hits.update(w.lower() for w in LEAKAGE_RE.findall(m.group(0)))
    stripped = COMMENT_RE.sub('', code)
    for m in STRING_RE.finditer(stripped):
        hits.update(w.lower() for w in LEAKAGE_RE.findall(m.group(0)))
    leak_words = {w.replace('-', '_') for w in LEAKAGE_WORDS}
    hits.update(w for w in _identifier_words(stripped) if w in leak_words)
    return sorted(hits)


def check_program(code: str, language: str, cfg: Optional[Dict] = None) -> List[str]:
    """Reasons to reject *code* before compilation; empty means accepted."""
    if (language or '').lower() not in C_LANGS or not code:
        return []
    cfg = cfg or {}
    reasons: List[str] = []
    stripped = COMMENT_RE.sub('', code)
    if cfg.get('reject_argv', True) and ARGV_RE.search(stripped):
        reasons.append('reads argc/argv')
    if cfg.get('reject_intrinsics', True) and INTRINSIC_RE.search(stripped):
        reasons.append('uses verifier intrinsics')
    if cfg.get('reject_threads', True) and THREAD_RE.search(stripped):
        reasons.append('uses threads or fork')
    if cfg.get('reject_non_stdin_input', True) and FILE_INPUT_RE.search(stripped):
        reasons.append('reads input from a file or the environment instead of stdin')
    if cfg.get('reject_leakage', True):
        hits = leakage_hits(code)
        if hits:
            reasons.append('label leakage: ' + ', '.join(hits[:6]))
    return reasons
