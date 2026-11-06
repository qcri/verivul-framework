"""
evaluate_trigger.py — Evaluate how accurately models identify the vulnerability-
triggering line, using ESBMC-extracted ground truth from verified_samples.jsonl.

Only VeriVul (VeriVul) results are evaluated — it is the only dataset
for which ESBMC-verified trigger-line ground truth exists.

Ground truth fields (verified_samples.jsonl):
  trigger_line_number  — 1-based line number of the violating statement
  trigger_line         — verbatim source text of that line

Prediction fields (results/{model}/VeriVul_*.jsonl):
  trigger_line         — integer line number predicted by the model
  trigger_code         — source text of that line predicted by the model

Evaluation metrics (all computed over VULNERABLE ground-truth samples)
-----------------------------------------------------------------------
For each metric we report two denominators:
  (all)      all VULNERABLE samples with GT trigger info, even if the model
             returned no trigger prediction (null counts as wrong)
  (provided) only samples where the model actually provided a prediction

Metrics
  exact_line          — predicted line number == ground-truth line number
  exact_code          — predicted code string == ground-truth code string
  both                — both of the above
  stripped_code       — both strings stripped of leading/trailing whitespace match
  normalized_code     — lowercased + collapsed internal whitespace match
  code_in_gt          — stripped prediction is a substring of the GT line
  gt_in_code          — GT line is a substring of the stripped prediction
  either_contains     — either of the two containment checks above
  off_by_1            — abs(pred_line - gt_line) <= 1
  off_by_5            — abs(pred_line - gt_line) <= 5
  jaccard             — token Jaccard similarity >= 0.5 (rounded to bool for counts,
                        but mean similarity is also shown)

Scopes
  all_vulnerable      — every VULNERABLE GT sample with trigger info
  predicted_vulnerable — only samples the model predicted as VULNERABLE
  correctly_detected  — only samples the model correctly classified as VULNERABLE

Usage
-----
  python evaluate_trigger.py                     # all models
  python evaluate_trigger.py --model gpt-5.4     # single model
  python evaluate_trigger.py --output report.txt # save to file
"""

import argparse
import json
import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ROOT            = Path(__file__).parent
RESULTS_DIR     = (ROOT / ".." / ".." / ".." / "data" / "evaluation" / "predictions").resolve()
GROUND_TRUTH    = (ROOT / ".." / ".." / ".." / "data" / "evaluation" / "trigger_ground_truth.jsonl").resolve()
TARGET_DATASET  = "VeriVul"

JACCARD_THRESHOLD = 0.5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tokens(s: str) -> set[str]:
    return set(re.findall(r"\w+", s))


def _normalize(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def _jaccard(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta and not tb:
        return 1.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


def _pct(n: int, d: int) -> str:
    if d == 0:
        return "  N/A  "
    return f"{100 * n / d:6.1f}%"


def _fmt_mean(v: float | None) -> str:
    if v is None:
        return "  N/A  "
    return f"{100 * v:6.1f}%"


# ---------------------------------------------------------------------------
# Ground truth loading
# ---------------------------------------------------------------------------

def load_ground_truth() -> dict[str, dict]:
    """
    Returns {uuid: {line_number, line_code}} for every VULNERABLE record
    in verified_samples.jsonl that has both trigger fields populated.
    """
    gt: dict[str, dict] = {}
    total = missing = 0
    with open(GROUND_TRUTH, encoding="utf-8") as f:
        for raw in f:
            rec = json.loads(raw)
            if rec.get("label") != "VULNERABLE":
                continue
            total += 1
            ln  = rec.get("trigger_line_number")
            lc  = rec.get("trigger_line")
            if ln is None or lc is None:
                missing += 1
                continue
            gt[rec["uuid"]] = {"line_number": int(ln), "line_code": lc}
    print(f"Ground truth: {len(gt)} usable VULNERABLE records "
          f"({missing} of {total} missing trigger info, excluded)")
    return gt


# ---------------------------------------------------------------------------
# Results loading
# ---------------------------------------------------------------------------

def find_latest_approxvul(results_dir: Path) -> Path | None:
    files = sorted(
        results_dir.glob(f"{TARGET_DATASET}_*.jsonl"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return files[0] if files else None


def load_predictions(results_dir: Path) -> list[dict]:
    path = find_latest_approxvul(results_dir)
    if path is None:
        return []
    records = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if raw:
                try:
                    records.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass
    return records


# ---------------------------------------------------------------------------
# Per-sample metric computation
# ---------------------------------------------------------------------------

def eval_sample(
    pred_line: int | None,
    pred_code: str | None,
    gt_line: int,
    gt_code: str,
) -> dict:
    """Return a dict of bool/float metrics for one VULNERABLE sample."""
    has_pred = pred_line is not None or (pred_code is not None and pred_code.strip())

    pc_stripped = pred_code.strip() if pred_code else ""
    gc_stripped = gt_code.strip()
    pc_norm     = _normalize(pred_code) if pred_code else ""
    gc_norm     = _normalize(gt_code)
    jacc        = _jaccard(pred_code or "", gt_code)

    return {
        "has_prediction":  has_pred,
        # line-number metrics (require both numbers present)
        "exact_line":      (pred_line is not None and pred_line == gt_line),
        "off_by_1":        (pred_line is not None and abs(pred_line - gt_line) <= 1),
        "off_by_5":        (pred_line is not None and abs(pred_line - gt_line) <= 5),
        # code metrics (require code string present)
        "exact_code":      (bool(pc_stripped) and pc_stripped == gc_stripped),
        "stripped_code":   (bool(pc_stripped) and pc_stripped == gc_stripped),  # same as exact after strip
        "normalized_code": (bool(pc_norm)     and pc_norm == gc_norm),
        "code_in_gt":      (bool(pc_stripped) and pc_stripped in gc_stripped),
        "gt_in_code":      (bool(pc_stripped) and gc_stripped in pc_stripped),
        "either_contains": (bool(pc_stripped) and
                            (pc_stripped in gc_stripped or gc_stripped in pc_stripped)),
        # combined
        "both":            (pred_line is not None and pred_line == gt_line
                            and bool(pc_stripped) and pc_stripped == gc_stripped),
        # similarity
        "jaccard_ge50":    (jacc >= JACCARD_THRESHOLD),
        "jaccard_raw":     jacc,
    }


# ---------------------------------------------------------------------------
# Aggregation over a list of evaluated samples
# ---------------------------------------------------------------------------

BOOL_METRICS = [
    "exact_line", "off_by_1", "off_by_5",
    "exact_code", "normalized_code",
    "code_in_gt", "gt_in_code", "either_contains",
    "both", "jaccard_ge50",
]

METRIC_LABELS = {
    "exact_line":      "Exact line number",
    "off_by_1":        "Line number off-by-1",
    "off_by_5":        "Line number off-by-5",
    "exact_code":      "Exact code match",
    "normalized_code": "Normalised code match",
    "code_in_gt":      "Pred code ⊆ GT line",
    "gt_in_code":      "GT line ⊆ Pred code",
    "either_contains": "Either containment",
    "both":            "Exact line AND code",
    "jaccard_ge50":    f"Code Jaccard ≥ {int(JACCARD_THRESHOLD*100)}%",
}


def aggregate(samples: list[dict]) -> dict:
    """samples = list of eval_sample() results filtered to a given scope."""
    if not samples:
        return {}
    n = len(samples)
    provided = sum(1 for s in samples if s["has_prediction"])
    result = {"n_total": n, "n_provided": provided}
    for m in BOOL_METRICS:
        hits_all  = sum(1 for s in samples if s[m])
        hits_prov = sum(1 for s in samples if s["has_prediction"] and s[m])
        result[m] = {
            "hits_all":   hits_all,
            "hits_prov":  hits_prov,
            "pct_all":    hits_all  / n        if n        else None,
            "pct_prov":   hits_prov / provided if provided else None,
        }
    jacc_vals = [s["jaccard_raw"] for s in samples if s["has_prediction"]]
    result["mean_jaccard"] = sum(jacc_vals) / len(jacc_vals) if jacc_vals else None
    return result


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

W = 88

def section(title: str) -> str:
    return f"\n{'━' * W}\n  {title}\n{'━' * W}"


def render_scope_block(agg: dict, scope_label: str) -> list[str]:
    lines = []
    n   = agg.get("n_total", 0)
    np_ = agg.get("n_provided", 0)

    lines.append(f"\n  Scope: {scope_label}   (n={n}, with prediction={np_})")
    lines.append(f"  {'Metric':<32}  {'% (all GT)':<12}  {'% (provided)':<12}  {'Hits / All':>14}  {'Hits / Provided':>15}")
    lines.append("  " + "─" * 84)

    for m in BOOL_METRICS:
        if m not in agg:
            continue
        d   = agg[m]
        label = METRIC_LABELS[m]
        p_all  = _pct(d["hits_all"],  n)
        p_prov = _pct(d["hits_prov"], np_)
        lines.append(
            f"  {label:<32}  {p_all:<12}  {p_prov:<12}  "
            f"{d['hits_all']:>5} / {n:<6}  {d['hits_prov']:>5} / {np_:<6}"
        )

    mj = agg.get("mean_jaccard")
    lines.append(f"  {'Mean code Jaccard similarity':<32}  {'':12}  {_fmt_mean(mj):<12}")
    lines.append("  " + "─" * 84)
    return lines


def build_report(
    model_results: dict[str, list[dict]],   # model_name -> eval records per model
    gt: dict[str, dict],
) -> tuple[str, dict]:
    """
    model_results values: list of raw prediction dicts from results JSONL.
    Returns (text_report, json_report).
    """
    lines: list[str] = []
    report: dict = {"generated": datetime.now().isoformat(), "models": {}}

    lines += [
        "=" * W,
        f"  TRIGGER LINE LOCALISATION EVALUATION",
        f"  Dataset : {TARGET_DATASET}  (VeriVul)",
        f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "=" * W,
    ]

    for model_name, preds in sorted(model_results.items()):
        lines.append(section(f"MODEL: {model_name}"))

        # Separate vulnerable/safe records and index by pair_id
        vul_preds = {r["pair_id"]: r for r in preds if r.get("ground_truth") == "VULNERABLE"}

        # Only evaluate samples the model correctly classified as VULNERABLE
        corr_det_evals: list[dict] = []

        matched = not_in_gt = 0
        for pid, gt_rec in gt.items():
            pred = vul_preds.get(pid)
            if pred is None:
                not_in_gt += 1
                continue
            matched += 1

            if not (pred.get("correct") and pred.get("prediction") == "VULNERABLE"):
                continue

            pred_line = pred.get("trigger_line")
            pred_code = pred.get("trigger_code")
            ev = eval_sample(pred_line, pred_code,
                             gt_rec["line_number"], gt_rec["line_code"])
            corr_det_evals.append(ev)

        lines.append(f"\n  GT samples : {len(gt)}  matched : {matched}  "
                     f"unmatched (not in results) : {not_in_gt}")

        agg = aggregate(corr_det_evals)
        lines += render_scope_block(
            agg, "Correctly detected VULNERABLE samples"
        )
        report["models"][model_name] = agg

    lines += ["", "=" * W, ""]
    return "\n".join(lines), report


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate trigger-line localisation accuracy on VeriVul."
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--model",       default=None,
                     help="Model slug (subdirectory under results/).")
    src.add_argument("--results-dir", default=None, dest="results_dir",
                     help="Explicit results directory.")
    parser.add_argument("--output",   default=None,
                        help="Path for text report "
                             "(default: results/<model>/trigger_eval_report.txt). "
                             "Use '-' for stdout only.")
    parser.add_argument("--json",     default=None, dest="json_out",
                        help="Write JSON report to this path.")
    args = parser.parse_args()

    # Resolve model directories
    if args.results_dir:
        model_dirs = [Path(args.results_dir)]
    elif args.model:
        model_dirs = [RESULTS_DIR / args.model]
    else:
        model_dirs = sorted(p for p in RESULTS_DIR.iterdir() if p.is_dir())
        if not model_dirs:
            raise SystemExit(f"No result directories found under {RESULTS_DIR}")

    print(f"\nLoading ground truth from: {GROUND_TRUTH}")
    gt = load_ground_truth()

    model_results: dict[str, list[dict]] = {}
    for results_dir in model_dirs:
        if not results_dir.exists():
            print(f"[SKIP] {results_dir} — not found")
            continue
        preds = load_predictions(results_dir)
        if not preds:
            print(f"[SKIP] {results_dir.name} — no {TARGET_DATASET} results file")
            continue
        model_results[results_dir.name] = preds
        print(f"  Loaded {results_dir.name:<24} {len(preds):>5} records")

    if not model_results:
        raise SystemExit("No model results loaded.")

    print()
    text_report, json_report = build_report(model_results, gt)
    print(text_report)

    # Save text report
    if args.output != "-":
        if args.output:
            out_path = Path(args.output)
        elif len(model_dirs) == 1:
            out_path = model_dirs[0] / "trigger_eval_report.txt"
        else:
            out_path = RESULTS_DIR / "trigger_eval_report.txt"
        out_path.write_text(text_report, encoding="utf-8")
        print(f"Report saved → {out_path}")

    # Save JSON report
    if args.json_out:
        json_path = Path(args.json_out)
    elif len(model_dirs) == 1:
        json_path = model_dirs[0] / "trigger_eval_report.json"
    else:
        json_path = RESULTS_DIR / "trigger_eval_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_report, f, indent=2, ensure_ascii=False)
    print(f"JSON   saved → {json_path}")


if __name__ == "__main__":
    main()
