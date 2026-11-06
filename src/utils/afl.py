"""
AFL++ input search for VULNERABLE programs the sanitizer search did not crash.

AFL++ only finds inputs: every crashing input and the newest corpus entries are replayed with
the pipeline's own runner (dynamic_confirm.confirm), so a program reproduced this way carries
the same evidence as one reproduced by the seeded search.
"""
import base64
import os
import random
import re
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from . import confirm_runner as R

AFL_IMAGE = 'aflplusplus/aflplusplus:v4.21c'
AFL_SAN = ("-g -O1 -fno-omit-frame-pointer -fsanitize=address,signed-integer-overflow,shift,integer-divide-by-zero,null,"
           "bounds,object-size,pointer-overflow,float-divide-by-zero,vla-bound -fno-sanitize-recover=all")


def likely_false_positive(code: str, language: str, prop: Dict[str, Any]) -> Optional[str]:
    """Why ESBMC's violation is one no input can trigger (a known ESBMC model gap), or None.
    These classes were never reproduced in the reproduction study, so fuzzing them is wasted."""
    d = prop.get('description', '')
    if 'forgotten' in d:
        if language == 'cpp' and (re.search(r'~\w+\s*\(\s*\)\s*(noexcept\s*)?\{[^}]*\b(delete|free)\b', code, re.S)
                                  or re.search(r'unique_ptr|shared_ptr|std::vector|std::string|\bvector<|\bstring\b', code)):
            return 'C++ leak through a destructor or STL (ESBMC does not model destructors)'
        m = re.search(r'forgotten memory: dynamic_(\d+)_value', d)
        if language == 'c' and m and int(m.group(1)) <= 3 and re.search(r'\bfopen\s*\(', code):
            return 'FILE not closed (no sanitizer reports it)'
        return None
    if language == 'cpp' and 'shl' in d:
        return 'C++ shift (ESBMC applies C rules)'
    if 'NaN' in d or 'ieee' in d:
        return 'NaN (no sanitizer reports it)'
    if re.search(r'_size|basic_string|out_of_range', d) or prop.get('function') == 'rdstate':
        return 'STL / iostream model assertion'
    return None


def _dictionary(tokens: List[bytes]) -> str:
    lines = []
    for i, t in enumerate(tokens[:200]):
        if 0 < len(t) <= 128:
            lines.append(f'k{i}="' + ''.join(chr(b) if 32 <= b < 127 and chr(b) not in '"\\' else f'\\x{b:02x}'
                                             for b in t) + '"')
    return '\n'.join(lines) + '\n'


def afl_inputs(code: str, language: str, hints: Dict[str, Any], seconds: int = 300) -> Tuple[List[bytes], Dict[str, Any]]:
    """AFL++ (cmplog + a dictionary of source and counterexample tokens) on *code* for *seconds*.
    -> (crashing inputs, then the newest corpus entries; stats)."""
    ext = 'cpp' if language == 'cpp' else 'c'
    rng = random.Random(1)
    tokens = [base64.b64decode(t) for t in hints.get('tokens', [])] + R.source_tokens(code)
    seeds = [base64.b64decode(x) for x in hints.get('seeds', [])]
    seeds += [R.structured(rng, tokens, sorted(set(R.INTS) | set(hints.get('ints', [])))) for _ in range(24)]
    seeds += [b'\n', b'0\n', b'A' * 64, b'\x00' * 16]
    cc = 'afl-clang-fast++ -std=c++17' if ext == 'cpp' else 'afl-clang-fast -std=gnu11'
    script = f"""
cd /w
{cc} {AFL_SAN} -w -o target source.{ext} {R.INCLUDES} -lm -lpthread -ldl 2> build.log || exit 3
AFL_LLVM_CMPLOG=1 {cc} -g -O1 -w -o cmplog source.{ext} {R.INCLUDES} -lm -lpthread -ldl 2>> build.log || exit 4
export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1 AFL_NO_AFFINITY=1 AFL_QUIET=1
export AFL_CMPLOG_ONLY_NEW=1 AFL_SKIP_CRASHES=1
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0:allocator_may_return_null=1:max_allocation_size_mb=512
export UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1
timeout {seconds + 60} afl-fuzz -i in -o out -x dict.txt -c ./cmplog -l 2AT -m none -t 1000 -V {seconds} -- ./target > fuzz.log 2>&1
chmod -R a+rwX /w
"""
    with tempfile.TemporaryDirectory(prefix='afl-') as td:
        os.chmod(td, 0o777)
        with open(f'{td}/source.{ext}', 'w') as f:
            f.write(code)
        os.makedirs(f'{td}/in')
        for i, x in enumerate(seeds):
            with open(f'{td}/in/s{i:03d}', 'wb') as f:
                f.write(x[:65536] or b'\n')
        with open(f'{td}/dict.txt', 'w') as f:
            f.write(_dictionary(tokens))
        p = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--memory', '3g', '--cpus', '1',
                            '-v', f'{td}:/w', '--entrypoint', 'bash', AFL_IMAGE, '-c', script],
                           capture_output=True, text=True, timeout=seconds + 300)
        if p.returncode in (3, 4):
            return [], {'error': 'afl build failed'}
        d = f'{td}/out/default'

        def listing(sub):
            return sorted(x for x in os.listdir(f'{d}/{sub}') if x.startswith('id:')) if os.path.isdir(f'{d}/{sub}') else []

        crashes, queue = listing('crashes'), listing('queue')
        found = [open(f'{d}/crashes/{x}', 'rb').read() for x in crashes[:100]]
        found += [open(f'{d}/queue/{x}', 'rb').read() for x in queue[::-1][:400]]
        return [x for x in found if x], {'afl_crashes': len(crashes), 'afl_queue': len(queue)}
