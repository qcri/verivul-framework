"""
Build vulnerable-only realism samples for KS / cluster analysis across six
datasets:  VeriVul, ICVul, TitanVul, mono (formerly monoVul), ARVO, FormAI.

Each output file contains up to N vulnerable function-level records:

    data/realism_samples/func_<dataset>.jsonl
        fields: id, code, dataset, language

Sampling targets N=6000 per dataset; for ARVO we take all vulnerable entries
(2917 — there are no more).

VeriVul samples are 5,000 vulnerable programs of the released dataset (data/verivul.jsonl), drawn with
the expansion-model mix of the original snapshot (gemma-4-31b-it 44.8%, seed-coder-8b 24.5%,
gpt-oss-120b 23.0%, qwen3.6-35b-a3b 7.7%). The ids of the sample used in the paper are in
data/realism/matched_sample.json and are used when present. The external datasets are read from
$EXTERNAL_DATASETS (default experiments/realism/data/external).

Run:
    python sample_realism.py
"""
import json
import glob
import os
import random
import re
import sys
from pathlib import Path

import pandas as pd
from tree_sitter import Language, Parser

try:
    from tree_sitter_cpp import language as cpp_language_id
except ImportError:
    print("tree_sitter_cpp not found"); sys.exit(1)

_lang = Language(cpp_language_id())
_parser = Parser()
_parser.language = _lang

SEED = 42
N = 6000                          # target vulnerable samples per dataset
C_EXTS = {'c', 'cc', 'cpp', 'cxx', 'h', 'hpp', 'C'}
ROOT = Path(__file__).parent
EXT = os.environ.get('EXTERNAL_DATASETS', str(ROOT / 'data' / 'external'))
OUT_DIR = Path(os.environ.get('REALISM_DIR', ROOT / 'data' / 'realism_samples'))
RELEASE = Path(os.environ.get('VERIVUL_RELEASE', ROOT / '..' / '..' / '..' / 'data' / 'verivul.jsonl'))
MATCHED = RELEASE.parent / 'realism' / 'matched_sample.json'
SHARE = {'gemma-4-31b-it': .448, 'seed-coder-8b': .245, 'gpt-oss-120b': .230, 'qwen3.6-35b-a3b': .077}
OUT_DIR.mkdir(parents=True, exist_ok=True)


# ── tree-sitter helpers (only needed for FormAI) ─────────────────────────────

def _collect_functions(node, results):
    if node.type == 'function_definition':
        name = _get_function_name(node)
        if name:
            results.append((name, node))
    for child in node.children:
        _collect_functions(child, results)


def _get_function_name(node):
    for child in node.children:
        if child.type in ('function_declarator', 'pointer_declarator',
                          'abstract_function_declarator', 'parenthesized_declarator'):
            n = _get_function_name(child)
            if n:
                return n
        if child.type == 'identifier':
            return child.text.decode('utf-8', errors='replace')
    return None


def _all_functions(code: str):
    tree = _parser.parse(bytes(code, 'utf-8'))
    funcs = []
    _collect_functions(tree.root_node, funcs)
    raw = code.encode('utf-8')
    return [(name, raw[node.start_byte:node.end_byte].decode('utf-8', errors='replace'),
             node.start_point[0], node.end_point[0]) for name, node in funcs]


def extract_function_by_name(code: str, func_name: str) -> str | None:
    for name, body, _, _ in _all_functions(code):
        if name == func_name:
            return body
    return None


def extract_function_by_line(code: str, line_no: int) -> str | None:
    target = line_no - 1
    best = None
    for name, body, sl, el in _all_functions(code):
        if sl <= target <= el:
            if best is None or (el - sl) < (best[3] - best[2]):
                best = (name, body, sl, el)
    return best[1] if best else None


def extract_largest_function(code: str, exclude_main: bool = False) -> str | None:
    funcs = [f for f in _all_functions(code) if len(f[1].splitlines()) >= 3]
    if exclude_main:
        non_main = [f for f in funcs if f[0] != 'main']
        if non_main:
            funcs = non_main
    if not funcs:
        return None
    funcs.sort(key=lambda x: len(x[1]), reverse=True)
    return funcs[0][1]


# ── FormAI violated_property parser ──────────────────────────────────────────
_VP_FUNC = re.compile(r'function (\w+)')
_VP_LINE = re.compile(r'line (\d+)')


def parse_formai_vp(vp: str):
    fm = _VP_FUNC.search(vp or '')
    lm = _VP_LINE.search(vp or '')
    return (fm.group(1) if fm else None), (int(lm.group(1)) if lm else None)


# ── output helper ─────────────────────────────────────────────────────────────

def save(records, name):
    path = OUT_DIR / f'func_{name}.jsonl'
    random.shuffle(records)
    with open(path, 'w') as f:
        for r in records:
            f.write(json.dumps(r) + '\n')
    locs = sorted(len(r['code'].splitlines()) for r in records)
    med = locs[len(locs) // 2] if locs else 0
    print(f'  {name}: {len(records)} records, LOC median={med} → {path}')


# ── VeriVul ──────────────────────────────────────────────────────────────────

def build_verivul():
    print('VeriVul...')
    pool = {}
    with open(RELEASE) as f:
        for line in f:
            r = json.loads(line)
            if r['label'] == 'VULNERABLE' and r['language'] == 'c' and r['loc'] >= 3:
                pool[r['id']] = r
    if MATCHED.exists():
        ids = json.load(open(MATCHED))['ids']
    else:
        rng = random.Random(SEED)
        ids = []
        for model, share in SHARE.items():
            ids += rng.sample(sorted(i for i, r in pool.items() if r['generation_model'] == model), round(5000 * share))
    records = [{'id': i, 'code': pool[i]['code'], 'dataset': 'VeriVul', 'language': 'c'} for i in ids if i in pool]
    print(f'  vuln pool (program-level): {len(pool)}, sampled {len(records)}')
    save(records, 'verivul')


# ── ICVul ─────────────────────────────────────────────────────────────────────

def build_icvul():
    random.seed(SEED)
    print('ICVul...')
    df = pd.read_csv(EXT + '/ICVul/ICVul-Dataset/function_info.csv')
    df['ext'] = df['filename'].apply(lambda x: str(x).split('.')[-1])
    pool = df[(df['before_change'] == True) & (df['ext'].isin(C_EXTS)) & df['code'].notna()]
    print(f'  vuln pool: {len(pool)}')
    n = min(N, len(pool))
    sampled = pool.sample(n=n, random_state=SEED)
    records = [
        {
            'id': f"icvul_{i}_{row['hash'][:8]}",
            'code': row['code'],
            'dataset': 'ICVul',
            'language': 'c' if row['ext'] in {'c', 'h'} else 'cpp',
        }
        for i, (_, row) in enumerate(sampled.iterrows())
    ]
    save(records, 'icvul')


# ── TitanVul ──────────────────────────────────────────────────────────────────

def build_titanvul():
    random.seed(SEED)
    print('TitanVul...')
    df = pd.read_csv(EXT + '/TitanVul/TitanVul.csv')
    pool = df[df['extension'].isin(C_EXTS) & df['func_before'].notna()]
    print(f'  vuln pool: {len(pool)}')
    n = min(N, len(pool))
    sampled = pool.sample(n=n, random_state=SEED)
    records = [
        {
            'id': f"titan_{i}_{str(row.get('cve_id',''))[:12]}",
            'code': row['func_before'],
            'dataset': 'TitanVul',
            'language': 'c' if row['extension'] in {'c', 'h'} else 'cpp',
        }
        for i, (_, row) in enumerate(sampled.iterrows())
    ]
    save(records, 'titanvul')


# ── monoVul (output name: mono) ──────────────────────────────────────────────

def build_mono():
    random.seed(SEED)
    print('mono (monoVul)...')
    files = [f for f in glob.glob(EXT + '/monoVul/*.json')
             if '_error' not in f]
    pool = []
    for fp in files:
        try:
            with open(fp) as f:
                d = json.load(f)
        except Exception:
            continue
        if 'C' not in d.get('language', ''):
            continue
        cve_id = d.get('cve_id', '')
        for h, c in d.get('commits', {}).items():
            for p in c.get('patches', []):
                if str(p.get('is_vul', '')).lower() != 'true':
                    continue
                fpath = p.get('file_path', '')
                ext = fpath.split('.')[-1] if '.' in fpath else 'c'
                if ext not in C_EXTS:
                    continue
                fb = p.get('func_before', '')
                if not fb or len(fb.strip()) < 20:
                    continue
                pool.append({
                    'id': f"mono_{cve_id}_{h[:8]}_{p.get('func_name','')}",
                    'code': fb,
                    'dataset': 'mono',
                    'language': 'c' if ext in {'c', 'h'} else 'cpp',
                })
    print(f'  vuln pool: {len(pool)}')
    n = min(N, len(pool))
    save(random.sample(pool, n), 'mono')


# ── ARVO ──────────────────────────────────────────────────────────────────────

def build_arvo():
    random.seed(SEED)
    print('ARVO...')
    # ARVO entries are file-level multi-function code chunks pulled by ARVO's
    # extraction tooling around each oss-fuzz crash. We use them as-is
    # (program/file granularity) — the chunk *is* the unit ARVO ships.
    with open(EXT + '/ARVO/extracted_arvo.json') as f:
        data = json.load(f)
    pool = []
    for d in data:
        if d.get('label') != 'Vulnerable':
            continue
        code = d.get('code', '')
        if not code or len(code.strip()) < 20:
            continue
        fn = d.get('file_name', '')
        ext = fn.split('.')[-1] if '.' in fn else ''
        if ext in {'c', 'h'}:
            lang = 'c'
        elif ext in {'cc', 'cpp', 'cxx', 'hh', 'hpp'}:
            lang = 'cpp'
        else:
            lang = 'other'
        pool.append({
            'id': f"arvo_{d.get('processed_index')}_{d.get('project','')}",
            'code': code,
            'dataset': 'ARVO',
            'language': lang,
        })
    print(f'  vuln pool (file-level): {len(pool)}')
    n = min(N, len(pool))           # ARVO max ≈ 2917
    if len(pool) <= n:
        save(pool, 'arvo')
    else:
        save(random.sample(pool, n), 'arvo')


# ── FormAI ────────────────────────────────────────────────────────────────────

def build_formai():
    random.seed(SEED)
    print('FormAI...')
    # Use FormAI source code at program level. Each entry already contains a
    # full self-contained C program; we keep it as the unit, paralleling the
    # program-level VeriVul handling.
    with open(EXT + '/FormAI-dataset/FormAI-v2.json') as f:
        formai = json.load(f)

    seen = set()
    pool = []
    for e in formai:
        fn = e.get('file_name', '')
        if not fn or fn in seen:
            continue
        src = e.get('source_code', '')
        if not src or len(src.strip()) < 20:
            continue
        et = str(e.get('error_type', '')).strip()
        vl = e.get('vulnerable_line')
        # vulnerable: has a real error_type and a numeric vulnerable_line
        if et in ('N/A', '') or vl in (None, '', 'NA', 'N/A'):
            continue
        seen.add(fn)
        pool.append({
            'id': f"formai_{fn}",
            'code': src,
            'dataset': 'FormAI',
            'language': 'c',
        })

    print(f'  vuln program pool: {len(pool)}')
    n = min(N, len(pool))
    save(random.sample(pool, n), 'formai')


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    build_verivul()
    build_icvul()
    build_titanvul()
    build_mono()
    build_arvo()
    build_formai()
    print(f'\nDone. Outputs in {OUT_DIR}')


if __name__ == '__main__':
    main()
