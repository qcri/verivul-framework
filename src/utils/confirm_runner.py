"""Runs inside the verification image: compile a program with ASan+UBSan and
search for an input that makes a sanitizer fire.  Prints one JSON object.

    python3 confirm_runner.py --source /work/source.c --language c --seed 1 --budget 40
"""
import argparse
import base64
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

INCLUDES = ("-include stdio.h -include stdlib.h -include string.h -include unistd.h "
            "-include sys/types.h -include sys/socket.h -include arpa/inet.h -include netinet/in.h "
            "-include time.h -include errno.h -include fcntl.h -include signal.h -include stdint.h "
            "-include stdbool.h -include stdarg.h -include limits.h")
SAN = ("-g -O0 -fno-omit-frame-pointer -fsanitize=address,signed-integer-overflow,shift,integer-divide-by-zero,null,bounds,object-size,"
       "pointer-overflow,float-divide-by-zero,vla-bound -fno-sanitize-recover=all")
ENV_APIS = ("stat fstat lstat open openat fopen opendir readdir readlink getcwd realpath getpwnam getpwuid gethostbyname "
            "getaddrinfo localtime localtime_r gmtime gmtime_r mktime strftime strptime time clock gettimeofday clock_gettime rand random "
            "getpid getuid socket connect accept recv recvfrom send select poll ioctl mmap fork popen system pipe dup dup2 "
            "fcntl signal sigaction getrlimit sysconf uname gethostname").split()
ENV = {"ASAN_OPTIONS": "detect_leaks=1:allocator_may_return_null=1:abort_on_error=0:exitcode=99:"
                       "detect_stack_use_after_return=1:max_allocation_size_mb=512",
       "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1:exitcode=98",
       "LSAN_OPTIONS": "exitcode=97"}
ARTEFACTS = ("allocation-size-too-big", "out of memory", "requested allocation size",
             "AddressSanitizer: failed to allocate", "AddressSanitizer failed to allocate", "unsupported")
INTS = [0, 1, -1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
        511, 512, 1023, 1024, 4095, 4096, 65535, 65536, 2**31 - 1, 2**31, 2**32 - 1, -2**31]
LENGTHS = [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 127, 128, 129, 255, 256, 257,
           511, 512, 513, 1000, 1023, 1024, 1025, 2048, 4095, 4096, 4097, 8192, 65536]


def compile_program(src, lang, out):
    cc = "g++ -std=c++17" if lang == "cpp" else "gcc -std=gnu11"
    cmd = f"{cc} {SAN} -w -o {out} {src} {INCLUDES} -lm -lpthread -lrt -ldl"
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
    return r.returncode == 0, (r.stderr or "")[-1500:]


def channels(code):
    lit = lambda pat: sorted(set(re.findall(pat, code)))
    called = sorted({f for f in ENV_APIS if re.search(r"\b" + f + r"\s*\(", code)})
    named = lit(r'"([\w./-]+\.(?:bin|dat|log|txt|img|raw|cfg|conf|ini|db|idx|pkg|arc|in|input|hdr|rec|json|csv|map|pak))"')
    return {
        "env_apis": called,
        "stdin": bool(re.search(r"\b(scanf|fgets|getchar|getc|fgetc|getline|gets|read\s*\(\s*0|fread\s*\([^;]*stdin|recv\s*\(|fscanf\s*\(\s*stdin|getdelim|cin\b|rdbuf)", code)),
        "env": lit(r'getenv\s*\(\s*"([^"]+)"'),
        "files": sorted(set(lit(r'fopen\s*\(\s*"([^"]+)"\s*,\s*"r[b+]*"') + lit(r'\bopen\s*\(\s*"([^"]+)"\s*,\s*O_RDONLY')
                            + lit(r'ifstream\s*\w*\s*[({]\s*"([^"]+)"') + named)),
        # A file opened through a variable: its name comes from stdin, getenv or a parameter.
        "indirect": bool(re.search(r'\bfopen\s*\(\s*[^"\s)]|ifstream\s*\w*\s*[({]\s*[^"\s)]|\.open\s*\(\s*[^"\s)]'
                                   r'|\bopen\s*\(\s*[^"\s)]', code)),
    }


def int_tokens(v):
    """Encodings of an integer a parser may compare against: LE/BE at the widths it fits, and decimal."""
    out = [str(v).encode()]
    for width in (2, 4, 8):
        if -(2 ** (8 * width - 1)) <= v < 2 ** (8 * width):
            u = v % (2 ** (8 * width))
            out += [u.to_bytes(width, "little"), u.to_bytes(width, "big")]
            if width > 2 or v >= 256:
                break
    return out


def source_tokens(code):
    """Magic numbers, keywords and sizes the program tests its input against."""
    toks = []
    for h in re.findall(r"\b0[xX]([0-9A-Fa-f]{3,16})[uUlL]*\b", code):
        toks += int_tokens(int(h, 16))[1:]
    for c in re.findall(r"'((?:[^'\\]|\\.){2,8})'", code):  # multi-char constants: 'MRBK'
        if "\\" not in c:
            toks.append(c.encode("latin-1", "replace"))
    for sl in re.findall(r'"((?:[^"\\\n]|\\.){1,40})"', code):
        if "%" not in sl and not sl.endswith((".h", ".hpp")):
            toks.append(sl.encode("latin-1", "replace").decode("unicode_escape").encode("latin-1", "replace"))
    for d in re.findall(r"(?:[<>=!]=?|case)\s*(-?\d{2,10})\b", code):
        toks += int_tokens(int(d))
    seen, out = set(), []
    for t in toks:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out[:300]


def classic_payloads():
    out = [b"", b"\n", b"\x00", b"0\n", b"-1\n", b"A", b"\xff" * 8]
    for L in LENGTHS:
        out.append(b"A" * L)
        out.append(b"A" * L + b"\n")
        out.append(b"1" * min(L, 40) + b"\n")
    for v in INTS:
        out.append(f"{v}\n".encode())
        out.append(f"{v} {v}\n".encode())
        out.append(f"{v} 1 {v}\n".encode())
        for width, order in ((1, "little"), (2, "little"), (2, "big"), (4, "little"), (4, "big")):
            if -(2 ** (8 * width - 1)) <= v < 2 ** (8 * width):
                head = (v % (2 ** (8 * width))).to_bytes(width, order)
                out.append(head + b"A" * 64)
                out.append(head + b"\x00" * 3 + b"B" * 300)
    return out


def structured(rng, tokens, ints):
    """A header-shaped binary record or a command line built from the program's own constants."""
    if tokens and rng.random() < 0.35:  # text protocol: KEYWORD arg arg\n, a few lines
        lines = []
        for _ in range(rng.randint(1, 4)):
            words = [rng.choice(tokens)] + [str(rng.choice(ints)).encode() for _ in range(rng.randint(0, 3))]
            if rng.random() < 0.3:
                words.append(b"A" * rng.choice(LENGTHS))
            lines.append(b" ".join(words))
        return b"\n".join(lines) + b"\n"
    order = rng.choice(("little", "big"))
    b = bytearray()
    if tokens and rng.random() < 0.85:
        b += rng.choice(tokens)
    for _ in range(rng.randint(1, 8)):
        width = rng.choice((1, 2, 2, 4, 4, 4, 8))
        v = rng.choice(ints) % (2 ** (8 * width))
        b += v.to_bytes(width, order)
    tail = rng.random()
    b += (b"" if tail < 0.15 else b"A" * rng.randint(1, 512) if tail < 0.55 else bytes(rng.randrange(256) for _ in range(rng.randint(1, 128)))
          if tail < 0.85 else b"\x00" * rng.randint(1, 64) if tail < 0.95 else b"A" * rng.choice((65536, 65537, 70000)))
    return bytes(b)


def mutate(rng, b, tokens):
    b = bytearray(b)
    for _ in range(rng.randint(1, 4)):
        op = rng.random()
        if op < 0.3 and b:
            b[rng.randrange(len(b))] = rng.choice([0, 1, 0x7f, 0x80, 0xff, 0x0a, 0x20, 0x41, 0x2d, 0x30])
        elif op < 0.5 and tokens:
            t = rng.choice(tokens)
            at = 0 if rng.random() < 0.5 else rng.randrange(len(b) + 1)
            b[at:at + (len(t) if rng.random() < 0.5 else 0)] = t
        elif op < 0.7:
            b[rng.randrange(len(b) + 1):0] = bytes(rng.choice([0x41, 0x0a, 0x00, 0xff]) for _ in range(rng.randint(1, 64)))
        elif op < 0.85 and b:
            del b[rng.randrange(len(b)):]
        else:
            b += rng.choice([b"\n", b" ", b"\x00", b"9" * rng.randint(1, 20)])
    return bytes(b)


def payloads(rng, n, tokens=(), ints=(), seeds=()):
    """Seeds (counterexample- or LLM-derived) first, then the classic boundary set
    interleaved with structured records and token-spliced mutants."""
    tokens, ints = list(tokens), sorted(set(INTS) | set(ints))
    base = classic_payloads()
    out = list(seeds) + base[:7]
    rest = base[7:]
    while len(out) < n:
        r = rng.random()
        if rest and r < 0.3:
            out.append(rest.pop(0))
        elif r < 0.7:
            out.append(structured(rng, tokens, ints))
        else:
            out.append(mutate(rng, rng.choice(out[:len(seeds) + 7] + base if rng.random() < 0.5 else out), tokens))
    return out[:n]


def run_one(exe, data, chans, timeout, as_path=False):
    """Run once.  With *as_path* the payload goes in a file and stdin and the environment
    variables carry that file's path (programs that read a file name, then open it)."""
    work = tempfile.mkdtemp(prefix="run_")
    env = dict(os.environ, **ENV)
    path = os.path.join(work, "input.bin")
    if as_path:
        with open(path, "wb") as f:
            f.write(data)
        stdin_data = path.encode() + b"\n" + data
        env_value = path
    else:
        stdin_data, env_value = data, data[:4096].decode("latin-1").replace("\x00", "")
    for name in chans["env"]:
        env[name] = env_value
    for p in chans["files"]:
        target = p if p.startswith("/") else os.path.join(work, p)
        try:
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            with open(target, "wb") as f:
                f.write(data)
        except OSError:
            pass
    # stdin is a regular file, not a pipe: programs that ftell/fseek/fstat stdin see a real size.
    stdin_path = os.path.join(work, ".stdin")
    with open(stdin_path, "wb") as f:
        f.write(stdin_data)
    try:
        with open(stdin_path, "rb") as stdin:
            p = subprocess.run([exe], stdin=stdin, capture_output=True, timeout=timeout, cwd=work, env=env)
        return p.returncode, (p.stderr or b"").decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return None, ""
    finally:
        shutil.rmtree(work, ignore_errors=True)


# Demangled C++ frames contain spaces ("parse(std::vector<int> const&) /work/source.cpp:94").
FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in (.+?) (?:/\S+/)?(source\.\w+):(\d+)(?::(\d+))?")


def frame_function(name):
    """ESBMC names functions without class or parameters: "A::~A()" -> "~A"."""
    return re.sub(r"\(.*$", "", name).split("::")[-1]
UB_LOC = re.compile(r"(?:^|\s)(?:/\S+/)?(source\.\w+):(\d+):(\d+): runtime error: (.+)")


def classify(rc, err):
    """-> (kind, function, line) of the first sanitizer report that is a program defect, else None."""
    if rc in (None, 0) or any(a in err for a in ARTEFACTS):
        return None
    m = re.search(r"ERROR: AddressSanitizer: (attempting double-free|attempting free on address which was not malloc\(\)-ed|[\w-]+)", err)
    if m:
        kind = m.group(1)
        if kind == "SEGV":
            kind = "null-deref" if re.search(r"address 0x0{1,4}[0-9a-f]{0,3}\b", err) or "unknown address 0x000000" in err else "segv"
        f = FRAME.search(err)
        return kind, (frame_function(f.group(1)) if f else None), (int(f.group(3)) if f else None)
    if "ERROR: LeakSanitizer" in err:
        f = FRAME.search(err)
        return "leak", (frame_function(f.group(1)) if f else None), (int(f.group(3)) if f else None)
    m = UB_LOC.search(err)
    if m:
        what = m.group(4)
        if "passed as argument" in what or "returned from" in what:
            return None
        kind = ("signed-overflow" if "signed integer overflow" in what else "division-by-zero" if "division by zero" in what
                else "shift" if "shift" in what else "null-deref" if "null pointer" in what
                else "array-bounds" if "out of bounds for type" in what
                else "pointer-overflow" if "pointer index expression" in what
                else "vla-bound" if "variable length array bound" in what else None)
        f = FRAME.search(err)
        return (kind, frame_function(f.group(1)) if f else None, int(m.group(2))) if kind else None
    if rc == 136 or rc == -8:
        return "division-by-zero", None, None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True)
    ap.add_argument("--language", default="c")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--budget", type=float, default=40)
    ap.add_argument("--runs", type=int, default=20000)
    ap.add_argument("--hints", help="JSON {seeds, tokens: [base64], ints: [int]} from the ESBMC counterexample or an LLM")
    ap.add_argument("--run-timeout", type=float, default=3)
    a = ap.parse_args()
    t0 = time.time()
    code = open(a.source, encoding="utf-8", errors="replace").read()
    exe = "/tmp/confirm_exe"
    ok, cerr = compile_program(a.source, a.language, exe)
    res = {"compiled": ok, "channels": None, "runs": 0, "finding": None, "timeouts": 0,
           "sanitizer_flags": SAN, "sanitizer_env": ENV}
    if not ok:
        res["compile_error"] = cerr
        print(json.dumps(res)); return
    chans = channels(code)
    res["channels"] = {"stdin": chans["stdin"], "env": chans["env"], "files": chans["files"], "indirect": chans["indirect"]}
    res["env_apis"] = chans["env_apis"]
    hints = {}
    if a.hints and os.path.exists(a.hints):
        with open(a.hints) as f:
            hints = json.load(f)
    seeds = [base64.b64decode(x) for x in hints.get("seeds", [])]
    tokens = [base64.b64decode(x) for x in hints.get("tokens", [])] + source_tokens(code)
    rng = random.Random(a.seed)
    data = payloads(rng, a.runs, tokens, hints.get("ints", []), seeds)
    # Programs that open a file through a variable alternate between the payload as data
    # and the payload as a file whose path is on stdin and in the environment; seeds get both.
    jobs = [(d, False) for d in data]
    if chans["indirect"]:
        jobs = [(d, m) for i, d in enumerate(data) for m in ((False, True) if i < len(seeds) else (i % 2 == 1,))]
    res["seeds"] = len(seeds)
    res["tokens"] = len(tokens)
    findings = []

    def work(job):
        if time.time() - t0 > a.budget or findings:
            return None
        d, as_path = job
        rc, err = run_one(exe, d, chans, a.run_timeout, as_path)
        return d, as_path, rc, err

    with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 4)) as ex:
        for r in ex.map(work, jobs):
            if r is None:
                continue
            res["runs"] += 1
            d, as_path, rc, err = r
            if rc is None:
                res["timeouts"] += 1
                continue
            c = classify(rc, err)
            if c and not findings:
                findings.append({"kind": c[0], "function": c[1], "line": c[2], "exit_code": rc, "input_len": len(d),
                                 "input_b64": base64.b64encode(d[:262144]).decode(), "input_as_path": as_path,
                                 "report": err[:12000]})
    res["finding"] = findings[0] if findings else None
    res["elapsed_s"] = round(time.time() - t0, 1)
    print(json.dumps(res))


if __name__ == "__main__":
    main()
