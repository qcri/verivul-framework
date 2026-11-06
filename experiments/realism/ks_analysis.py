"""
KS-test realism analysis: VeriVul / FormAI (synthetic) vs ICVul / TitanVul /
mono / ARVO (real). Compares distributions on a curated set of
vulnerability-relevant metrics (see VULN_METRICS below for the rationale).

Reads function-level samples from data/realism_samples/func_<dataset>.jsonl.

Outputs:
  data/realism_samples/metrics_func_<dataset>.jsonl   — per-sample metrics
  data/realism_samples/ks_results.json                — full KS table
  data/realism_samples/ks_summary.txt                 — human-readable summary
"""
import json
import sys
import os
import math
import re
from collections import Counter
from pathlib import Path
from scipy.stats import ks_2samp
import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
from code_metrics import CppCodeMetricsExtractor
from structural_metrics import StructuralMetricsExtractor

SAMPLES_DIR = Path(os.environ.get('REALISM_DIR', Path(__file__).parent / 'data' / 'realism_samples'))
DATASETS = ['verivul', 'icvul', 'titanvul', 'mono', 'arvo', 'formai']
REAL_WORLD = ['icvul', 'titanvul', 'mono', 'arvo']

stat_extractor = CppCodeMetricsExtractor()
struct_extractor = StructuralMetricsExtractor()


def compute_metrics(code: str) -> dict:
    stat = stat_extractor.extract_metrics(code)
    struct = struct_extractor.extract_metrics(code)

    # Size-normalize CST counts by total named nodes to remove LOC confound
    total_nodes = sum(v for k, v in struct.items()
                      if k.startswith('cst_') and k not in ('cst_max_depth', 'cst_has_error'))
    if total_nodes > 0:
        struct_norm = {
            f"{k}_norm": v / total_nodes
            for k, v in struct.items()
            if k.startswith('cst_') and k not in ('cst_max_depth', 'cst_has_error')
        }
    else:
        struct_norm = {}

    return {**stat, **struct, **struct_norm}


def load_or_compute(ds_name: str) -> list[dict]:
    cache_path = SAMPLES_DIR / f'metrics_func_{ds_name}.jsonl'
    if cache_path.exists():
        print(f'  loading cached metrics for {ds_name}')
        with open(cache_path) as f:
            return [json.loads(l) for l in f]

    print(f'  computing metrics for {ds_name}...', flush=True)
    src_path = SAMPLES_DIR / f'func_{ds_name}.jsonl'
    with open(src_path) as f:
        records = [json.loads(l) for l in f]

    results = []
    for i, r in enumerate(records):
        if i % 500 == 0:
            print(f'    {i}/{len(records)}', flush=True)
        m = compute_metrics(r['code'])
        m['id'] = r['id']
        m['dataset'] = r['dataset']
        results.append(m)

    with open(cache_path, 'w') as f:
        for m in results:
            f.write(json.dumps(m) + '\n')
    return results


# ── Load / compute metrics ────────────────────────────────────────────────────
all_metrics = {}
for ds in DATASETS:
    print(f'Processing {ds}...')
    all_metrics[ds] = load_or_compute(ds)

print('\nMetrics computed. Running KS tests...')


def get_values(records: list[dict], key: str) -> list[float]:
    vals = [r[key] for r in records if key in r and r[key] is not None]
    return [float(v) for v in vals if not (isinstance(v, float) and math.isnan(v))]


# ── Vulnerability-relevant metric subset ─────────────────────────────────────
# Rather than running KS over all ~120 metrics, we restrict to a curated set
# tied to canonical vulnerability-research signals. Each metric is included
# either because (a) prior software-engineering work links it to bug density
# (Shin & Williams 2008; Moshtari & Sami 2016; Chowdhury & Zulkernine 2011),
# or (b) it is a syntactic surface feature of a specific C/C++ memory-safety
# bug class (CWE-119/120/125/787 buffer overflows, CWE-476 NULL deref,
# CWE-704 type confusion, CWE-20 missing input validation, CWE-191 integer
# under-/overflow).
VULN_METRICS = {
    # ── Complexity & size — classic bug-proneness predictors ───────────────
    'complexity': [
        'loc',                     # function size — defect density
        'cyclomatic_complexity',   # branching complexity (McCabe)
        'max_nesting_depth',       # cognitive complexity
        'halstead_volume',         # operator/operand reasoning load
        'halstead_difficulty',     # error-prone-ness proxy
        'unique_tokens',           # vocabulary load
    ],
    # ── Memory safety surface — pointer / array / cast indicators ──────────
    'memory_safety': [
        'num_pointers',                    # raw pointer count
        'cst_pointer_declarator_norm',     # density of pointer declarations
        'cst_subscript_expression_norm',   # array indexing → CWE-119/125/787
        'cst_cast_expression_norm',        # type confusion → CWE-704
        'cst_call_expression_norm',        # taint sources / sinks
    ],
    # ── Control flow — where missing checks and bounds bugs live ───────────
    'control_flow': [
        'cst_if_statement_norm',     # conditional density (input validation)
        'cst_for_statement_norm',    # loop density (off-by-one, bounds)
        'cst_while_statement_norm',  # loop density
        'control_flow_density',      # overall branch density
    ],
    # ── Code-quality / naming — synthetic-vs-human signal ──────────────────
    'naming': [
        'naming_entropy',     # repetition vs variety in identifiers
        'naming_len_mean',    # identifier informativeness
    ],
}

# Flatten + de-duplicate while keeping order
all_keys = []
seen = set()
for cat_metrics in VULN_METRICS.values():
    for m in cat_metrics:
        if m not in seen:
            seen.add(m); all_keys.append(m)
print(f'\nUsing {len(all_keys)} vulnerability-relevant metrics across '
      f'{len(VULN_METRICS)} categories: {list(VULN_METRICS)}')

# ── KS tests ─────────────────────────────────────────────────────────────────
# For each real-world dataset: compare VeriVul vs real, FormAI vs real
ks_results = {}  # key -> {metric: {verivul_stat, formai_stat, verivul_pval, formai_pval}}

for real_ds in REAL_WORLD:
    ks_results[real_ds] = {}
    for key in sorted(all_keys):
        real_vals = get_values(all_metrics[real_ds], key)
        vv_vals   = get_values(all_metrics['verivul'], key)
        fa_vals   = get_values(all_metrics['formai'], key)

        if len(real_vals) < 30 or len(vv_vals) < 30 or len(fa_vals) < 30:
            continue

        vv_stat, vv_pval = ks_2samp(vv_vals, real_vals)
        fa_stat, fa_pval = ks_2samp(fa_vals, real_vals)

        ks_results[real_ds][key] = {
            'verivul_stat': round(vv_stat, 4),
            'verivul_pval': round(vv_pval, 4),
            'formai_stat':  round(fa_stat, 4),
            'formai_pval':  round(fa_pval, 4),
            'verivul_wins': int(vv_stat < fa_stat),  # 1 if VeriVul is closer
        }

# Save full results
out_path = SAMPLES_DIR / 'ks_results.json'
with open(out_path, 'w') as f:
    json.dump(ks_results, f, indent=2)
print(f'Full KS results → {out_path}')


# ── Summary ───────────────────────────────────────────────────────────────────
ALPHA = 0.05

lines = []
lines.append('=' * 72)
lines.append('KS REALISM ANALYSIS: VeriVul vs FormAI (lower stat = more similar)')
lines.append('=' * 72)

for real_ds in REAL_WORLD:
    res = ks_results[real_ds]
    sig = {k: v for k, v in res.items() if v['verivul_pval'] < ALPHA or v['formai_pval'] < ALPHA}

    vv_stats = [v['verivul_stat'] for v in sig.values()]
    fa_stats  = [v['formai_stat']  for v in sig.values()]
    vv_wins   = sum(v['verivul_wins'] for v in sig.values())
    fa_wins   = len(sig) - vv_wins

    lines.append(f'\nvs {real_ds.upper()}  ({len(sig)} significant metrics, alpha={ALPHA})')
    lines.append(f"  Avg KS stat  —  VeriVul: {np.mean(vv_stats):.3f}  |  FormAI: {np.mean(fa_stats):.3f}")
    lines.append(f"  Metric wins  —  VeriVul: {vv_wins}  |  FormAI: {fa_wins}")

    # Per-vulnerability-category breakdown
    for cat, cat_metrics in VULN_METRICS.items():
        cat_sig = {k: sig[k] for k in cat_metrics if k in sig}
        if not cat_sig:
            continue
        vv_s = [v['verivul_stat'] for v in cat_sig.values()]
        fa_s  = [v['formai_stat']  for v in cat_sig.values()]
        vv_w  = sum(v['verivul_wins'] for v in cat_sig.values())
        lines.append(f"    [{cat:<14}] n={len(cat_sig)}  "
                     f"VeriVul avg={np.mean(vv_s):.3f} wins={vv_w}  |  "
                     f"FormAI avg={np.mean(fa_s):.3f} wins={len(cat_sig)-vv_w}")

# Detail table covers every curated metric, grouped by category
KEY_METRICS = [m for cat in VULN_METRICS.values() for m in cat]

lines.append('\n' + '=' * 72)
lines.append('KEY METRICS DETAIL')
lines.append('=' * 72)
header = f"{'Metric':<35}" + ''.join(f" {'vs ' + r.upper():^22}" for r in REAL_WORLD)
lines.append(header)
lines.append(f"{'':35}" + (f" {'VV':>7} {'FA':>7} {'W':>4}  " * len(REAL_WORLD)))
lines.append('-' * (35 + 24 * len(REAL_WORLD)))

for m in KEY_METRICS:
    row = f"{m:<35}"
    for real_ds in REAL_WORLD:
        if m in ks_results[real_ds]:
            d = ks_results[real_ds][m]
            w = 'VV' if d['verivul_wins'] else 'FA'
            row += f"  {d['verivul_stat']:>7.3f} {d['formai_stat']:>7.3f} {w:>4}"
        else:
            row += f"  {'—':>7} {'—':>7} {'—':>4}"
    lines.append(row)

summary_text = '\n'.join(lines)
print('\n' + summary_text)

out_path2 = SAMPLES_DIR / 'ks_summary.txt'
with open(out_path2, 'w') as f:
    f.write(summary_text + '\n')
print(f'\nSummary → {out_path2}')
