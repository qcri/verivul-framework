"""
evaluate.py — Pairwise evaluation of VeriVul inference results.

Anchors on VeriVul and compares it against every other dataset
that has results in the same run directory.

Two evaluation formats
----------------------
  1. Per dataset pair  — overall Acc / Precision / Recall / F1
  2. Per dataset pair, per CWE  — same metrics for each CWE shared between
                                   the two datasets in the pair

Usage
-----
  # All models in results/
  python evaluate.py

  # Specific model slug
  python evaluate.py --model gpt-5.4

  # Point at an arbitrary directory
  python evaluate.py --results-dir results/gpt-5.4

  # Save report to file (default: results/<model>/eval_report.txt)
  python evaluate.py --model gpt-5.4 --output my_report.txt
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ROOT        = Path(__file__).parent
RESULTS_DIR = (ROOT / ".." / ".." / ".." / "data" / "evaluation" / "predictions").resolve()
ANCHOR      = "VeriVul"
DATASETS    = ["TitanVul", "Mono", "ICVul", "FormAI", "ARVO"]   # paired against ANCHOR


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_jsonl(path: Path) -> list[dict]:
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


def find_latest(results_dir: Path, dataset: str) -> Path | None:
    """Return the most recently modified JSONL for a dataset in results_dir."""
    files = sorted(
        results_dir.glob(f"{dataset}_*.jsonl"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return files[0] if files else None


def load_dataset_results(results_dir: Path) -> dict[str, list[dict]]:
    """Load the latest results file for each available dataset."""
    data: dict[str, list[dict]] = {}
    for ds in [ANCHOR] + DATASETS:
        path = find_latest(results_dir, ds)
        if path:
            records = load_jsonl(path)
            if records:
                data[ds] = records
                print(f"  Loaded {ds:<20} {len(records):>5} records  ({path.name})")
    return data


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def compute_metrics(records: list[dict]) -> dict:
    """Compute binary classification metrics (VULNERABLE = positive class)."""
    tp = fp = tn = fn = errors = 0
    for r in records:
        pred = r.get("prediction", "")
        gt   = r.get("ground_truth", "")
        if pred in ("API_ERROR", "PARSE_ERROR"):
            errors += 1
            continue
        if   gt == "VULNERABLE" and pred == "VULNERABLE": tp += 1
        elif gt == "SAFE"       and pred == "VULNERABLE": fp += 1
        elif gt == "SAFE"       and pred == "SAFE":       tn += 1
        elif gt == "VULNERABLE" and pred == "SAFE":       fn += 1

    total     = tp + fp + tn + fn
    accuracy  = (tp + tn) / total            if total            > 0 else None
    precision = tp / (tp + fp)               if (tp + fp)        > 0 else None
    recall    = tp / (tp + fn)               if (tp + fn)        > 0 else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None
          and (precision + recall) > 0 else None)

    return {
        "total": total, "errors": errors,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": accuracy, "precision": precision,
        "recall": recall, "f1": f1,
    }


def group_by_cwe(records: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        cwe = r.get("primary_cwe") or "Unknown"
        groups[cwe].append(r)
    return dict(groups)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def fmt(value: float | None, pct: bool = True) -> str:
    if value is None:
        return "   N/A  "
    return f"{value * 100:6.1f}%" if pct else f"{value:.4f}"


def hline(widths: list[int], sep: str = "─") -> str:
    return "─┼─".join(sep * w for w in widths)


def row(cells: list[str], widths: list[int]) -> str:
    return " │ ".join(str(c).ljust(w) for c, w in zip(cells, widths))


def metrics_block(m: dict) -> str:
    return (f"Acc={fmt(m['accuracy'])}  "
            f"Prec={fmt(m['precision'])}  "
            f"Rec={fmt(m['recall'])}  "
            f"F1={fmt(m['f1'])}  "
            f"n={m['total']}  err={m['errors']}")


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
def build_report(data: dict[str, list[dict]], model_name: str) -> tuple[str, dict]:
    """
    Returns (text_report, json_report).
    json_report mirrors the text structure for programmatic consumption.
    """
    lines: list[str] = []
    report: dict = {"model": model_name, "anchor": ANCHOR, "pairs": {}}

    W = 80
    lines += [
        "=" * W,
        f"  MODEL  : {model_name}",
        f"  ANCHOR : {ANCHOR}",
        f"  DATE   : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "=" * W,
    ]

    if ANCHOR not in data:
        lines.append(f"\n  ERROR: No results found for anchor dataset {ANCHOR}.\n")
        return "\n".join(lines), report

    anchor_records = data[ANCHOR]
    partners = [ds for ds in DATASETS if ds in data]

    if not partners:
        lines.append("\n  No partner dataset results found.\n")
        return "\n".join(lines), report

    # ------------------------------------------------------------------ #
    # Section 1 — Overall pairwise comparison                             #
    # ------------------------------------------------------------------ #
    lines += ["", "━" * W, "  SECTION 1 — Overall Pairwise Performance", "━" * W]

    col_w = [20, 9, 10, 8, 8, 7, 6]
    headers = ["Dataset", "Accuracy", "Precision", "Recall", "F1", "Items", "Errors"]
    divider = "─┼─".join("─" * w for w in col_w)

    anchor_by_cwe = group_by_cwe(anchor_records)

    for partner in partners:
        partner_by_cwe = group_by_cwe(data[partner])
        shared_cwes = set(anchor_by_cwe.keys()) & set(partner_by_cwe.keys())

        anchor_common   = [r for r in anchor_records  if (r.get("primary_cwe") or "Unknown") in shared_cwes]
        partner_common  = [r for r in data[partner]   if (r.get("primary_cwe") or "Unknown") in shared_cwes]

        lines += ["", f"  ┌─ VeriVul  ×  {partner} {'─' * (W - 28 - len(partner))}"]
        lines.append(f"  (restricted to {len(shared_cwes)} shared CWEs)")
        lines.append("  " + row(headers, col_w))
        lines.append("  " + divider)

        pair_report: dict = {}

        for ds, records in [(ANCHOR, anchor_common), (partner, partner_common)]:
            m = compute_metrics(records)
            lines.append("  " + row([
                ds,
                fmt(m["accuracy"]),
                fmt(m["precision"]),
                fmt(m["recall"]),
                fmt(m["f1"]),
                str(m["total"]),
                str(m["errors"]),
            ], col_w))
            pair_report[ds] = m

        lines.append("  " + divider)
        report["pairs"][partner] = {"overall": pair_report, "per_cwe": {}}

    # ------------------------------------------------------------------ #
    # Section 2 — Per-CWE pairwise comparison                            #
    # ------------------------------------------------------------------ #
    lines += ["", "━" * W, "  SECTION 2 — Per-CWE Pairwise Performance", "━" * W]

    cwe_col_w = [10, 9, 10, 8, 8, 7, 9, 10, 8, 8, 7]
    cwe_headers = [
        "CWE",
        # anchor cols
        "Acc(A)", "Prec(A)", "Rec(A)", "F1(A)", "n(A)",
        # partner cols
        "Acc(P)", "Prec(P)", "Rec(P)", "F1(P)", "n(P)",
    ]

    for partner in partners:
        partner_by_cwe = group_by_cwe(data[partner])
        shared_cwes = sorted(set(anchor_by_cwe.keys()) & set(partner_by_cwe.keys()))

        lines += [
            "",
            f"  ┌─ VeriVul (A)  ×  {partner} (P) {'─' * max(0, W - 34 - len(partner))}",
            f"  {'(A) = VeriVul   (P) = ' + partner}",
            "  " + row(cwe_headers, cwe_col_w),
            "  " + "─┼─".join("─" * w for w in cwe_col_w),
        ]

        cwe_report: dict = {}

        for cwe in shared_cwes:
            ma = compute_metrics(anchor_by_cwe[cwe])
            mp = compute_metrics(partner_by_cwe[cwe])
            lines.append("  " + row([
                cwe,
                fmt(ma["accuracy"]), fmt(ma["precision"]),
                fmt(ma["recall"]),   fmt(ma["f1"]),
                str(ma["total"]),
                fmt(mp["accuracy"]), fmt(mp["precision"]),
                fmt(mp["recall"]),   fmt(mp["f1"]),
                str(mp["total"]),
            ], cwe_col_w))
            cwe_report[cwe] = {ANCHOR: ma, partner: mp}

        lines.append("  " + "─┼─".join("─" * w for w in cwe_col_w))

        # CWEs only in anchor or only in partner
        only_anchor  = sorted(set(anchor_by_cwe.keys())  - set(partner_by_cwe.keys()))
        only_partner = sorted(set(partner_by_cwe.keys()) - set(anchor_by_cwe.keys()))
        if only_anchor:
            lines.append(f"  CWEs only in VeriVul : {', '.join(only_anchor)}")
        if only_partner:
            lines.append(f"  CWEs only in {partner:<16}: {', '.join(only_partner)}")

        report["pairs"][partner]["per_cwe"] = cwe_report

    # ------------------------------------------------------------------ #
    # Section 3 — All-dataset comparison on universally shared CWEs       #
    # ------------------------------------------------------------------ #
    all_datasets = [ANCHOR] + partners
    all_by_cwe = {ds: group_by_cwe(data[ds]) for ds in all_datasets}
    universal_cwes = set.intersection(*(set(by_cwe.keys()) for by_cwe in all_by_cwe.values()))

    lines += ["", "━" * W,
              "  SECTION 3 — All-Dataset Performance on Universally Shared CWEs",
              "━" * W]

    if not universal_cwes:
        lines.append("\n  No CWEs are shared across all datasets.\n")
    else:
        cwe_list = sorted(universal_cwes)
        lines.append(f"\n  CWEs ({len(cwe_list)}): {', '.join(cwe_list)}\n")

        col_w3 = [20, 9, 10, 8, 8, 7, 6]
        lines.append("  " + row(headers, col_w3))
        lines.append("  " + "─┼─".join("─" * w for w in col_w3))

        all_overall: dict = {}
        for ds in all_datasets:
            filtered = [r for r in data[ds]
                        if (r.get("primary_cwe") or "Unknown") in universal_cwes]
            m = compute_metrics(filtered)
            lines.append("  " + row([
                ds,
                fmt(m["accuracy"]),
                fmt(m["precision"]),
                fmt(m["recall"]),
                fmt(m["f1"]),
                str(m["total"]),
                str(m["errors"]),
            ], col_w3))
            all_overall[ds] = m

        lines.append("  " + "─┼─".join("─" * w for w in col_w3))
        report["universal_cwes"] = {"cwes": cwe_list, "overall": all_overall}

    lines += ["", "=" * W, ""]
    return "\n".join(lines), report


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Pairwise evaluation of VeriVul inference results."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--model", default=None,
                        help="Model slug to evaluate (subdirectory under results/).")
    source.add_argument("--results-dir", default=None, dest="results_dir",
                        help="Explicit path to a results directory.")
    parser.add_argument("--output", default=None,
                        help="Path to write the text report "
                             "(default: <results_dir>/eval_report.txt). "
                             "Use '-' for stdout only.")
    parser.add_argument("--json", default=None, dest="json_out",
                        help="Also write a machine-readable JSON report to this path.")
    args = parser.parse_args()

    # Resolve results directories to evaluate
    if args.results_dir:
        model_dirs = [Path(args.results_dir)]
    elif args.model:
        model_dirs = [RESULTS_DIR / args.model]
    else:
        # Default: evaluate every model directory found under results/
        model_dirs = sorted(p for p in RESULTS_DIR.iterdir() if p.is_dir())
        if not model_dirs:
            raise SystemExit(f"No result directories found under {RESULTS_DIR}")

    for results_dir in model_dirs:
        if not results_dir.exists():
            print(f"[SKIP] {results_dir} — directory not found")
            continue

        model_name = results_dir.name
        print(f"\n{'═' * 80}")
        print(f"  Evaluating: {model_name}")
        print(f"{'═' * 80}")
        print(f"\nLoading results from: {results_dir}\n")

        data = load_dataset_results(results_dir)
        if not data:
            print(f"  [SKIP] No valid result files found in {results_dir}\n")
            continue

        print()
        text_report, json_report = build_report(data, model_name)

        # Print to terminal
        print(text_report)

        # Write text report
        if args.output != "-":
            out_path = Path(args.output) if args.output else results_dir / "eval_report.txt"
            out_path.write_text(text_report, encoding="utf-8")
            print(f"Report saved → {out_path}")

        # Write JSON report
        json_path = Path(args.json_out) if args.json_out else results_dir / "eval_report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2, ensure_ascii=False)
        print(f"JSON   saved → {json_path}")


if __name__ == "__main__":
    main()
