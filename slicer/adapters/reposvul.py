"""
ReposVul → universal slicer input adapter.

Reads ReposVul.jsonl and produces a JSONL in the universal slicer input format.

Each ReposVul record contains:
  - details[].function_before  (list of {function, target} per file)
  - details[].function_after   (list of {function, target} per file)
  - cwe_id (list), cve_id, project, commit_id, commit_message, cve_language

For each target=1 function in function_before:
  - code          = the vulnerable function source
  - fixed_code    = matched function in function_after by name (98% hit rate)
  - neighbors     = all non-target functions from the same file
  - language      = cve_language / file_language

Usage:
    python -m slicer.adapters.reposvul \\
        --input /path/to/ReposVul.jsonl \\
        --output /path/to/output.jsonl \\
        [--languages c,cpp]
"""
from __future__ import annotations

import argparse
import json
import re
import uuid
from pathlib import Path


def _extract_fname(code: str) -> str:
    """Heuristic: extract function name from source code."""
    # Skip lines that are preprocessor directives or comments
    for line in code.strip().split("\n"):
        line = line.strip()
        if line.startswith("#") or line.startswith("//") or line.startswith("/*"):
            continue
        m = re.search(r"\b(\w+)\s*\(", line)
        if m:
            return m.group(1)
    return ""


_EXT_LANG = {"c": "c", "cc": "cpp", "cpp": "cpp", "cxx": "cpp", "c++": "cpp", "hpp": "cpp", "hh": "cpp",
             "c plus plus": "cpp", "py": "python", "python": "python", "java": "java", "kt": "kotlin"}


def _normalize_lang(lang: str, default: str = "") -> str:
    lang = (lang or "").strip().lower()
    if lang in ("h",):           # header: take the language of the CVE
        return default
    return _EXT_LANG.get(lang, lang)


SUPPORTED_LANGUAGES = {"c", "cpp"}


def build(input_path: Path, output: Path, languages: set[str] | None = None) -> None:
    if languages is None:
        languages = SUPPORTED_LANGUAGES

    print(f"Loading {input_path} …")
    with open(input_path, encoding="utf-8") as f:
        raw_records = [json.loads(line) for line in f if line.strip()]
    print(f"  {len(raw_records)} raw records loaded")

    records = []
    skipped_lang = 0
    skipped_no_target = 0

    for raw in raw_records:
        lang = _normalize_lang(raw.get("cve_language", ""))
        if lang not in languages:
            skipped_lang += 1
            continue

        cve_id = raw.get("cve_id", "")
        cwes = raw.get("cwe_id", [])
        if isinstance(cwes, str):
            cwes = [cwes]
        project = raw.get("project", "")
        commit_hash = raw.get("commit_id", "")
        commit_message = raw.get("commit_message", "")
        html_url = raw.get("html_url", "")
        # Derive repo_url from html_url:  https://github.com/owner/repo/commit/... → https://github.com/owner/repo
        repo_url = ""
        if html_url:
            parts = html_url.split("/")
            if len(parts) >= 5:
                repo_url = "/".join(parts[:5])

        for detail in raw.get("details", []):
            file_lang = _normalize_lang(detail.get("file_language") or lang, default=lang)
            if file_lang not in languages:
                continue

            funcs_before = detail.get("function_before", [])
            funcs_after = detail.get("function_after", [])

            after_by_name: dict[str, str] = {}
            for af in funcs_after:
                name = _extract_fname(af["function"])
                if name:
                    after_by_name[name] = af["function"]

            # explicit target labels when present, otherwise the functions the patch changed
            targets = [f for f in funcs_before if f.get("target") == 1]
            target_method = "labeled"
            if not targets:
                target_method = "patch"
                targets = [f for f in funcs_before
                           if (after_by_name.get(_extract_fname(f["function"])) or "").strip()
                           not in ("", f["function"].strip())]
            if not targets:
                skipped_no_target += 1
                continue

            # Build neighbor list (non-target before-functions in same file)
            non_targets = [f for f in funcs_before if f not in targets]
            neighbors = []
            for nt in non_targets:
                name = _extract_fname(nt["function"])
                if name:
                    neighbors.append({"name": name, "code": nt["function"]})

            for target_fn in targets:
                code = target_fn["function"].strip()
                if not code:
                    continue

                fname = _extract_fname(code)
                fixed_code = after_by_name.get(fname) if fname else None

                records.append({
                    "uuid": str(uuid.uuid4()),
                    "code": code,
                    "language": file_lang,
                    "fixed_code": fixed_code,
                    "cwes": cwes,
                    "neighbor_functions": neighbors if neighbors else None,
                    "project": project,
                    "dataset": "ReposVul",
                    "commit_hash": commit_hash,
                    "cve": cve_id,
                    "repo_url": repo_url,
                    "commit_message": commit_message,
                    "target_method": target_method,
                    "publish_date": raw.get("publish_date"),
                    "commit_date": raw.get("commit_date"),
                })

    # ── Write ─────────────────────────────────────────────────────────────────
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    n_with_fixed = sum(1 for r in records if r.get("fixed_code"))
    n_with_neighbors = sum(1 for r in records if r.get("neighbor_functions"))
    print(f"  {len(records)} records written to {output}")
    print(f"  skipped (language): {skipped_lang}")
    print(f"  skipped (no target fn): {skipped_no_target}")
    if records:
        print(f"  with fixed_code: {n_with_fixed} ({n_with_fixed/len(records):.0%})")
        print(f"  with neighbors:  {n_with_neighbors} ({n_with_neighbors/len(records):.0%})")


def main():
    parser = argparse.ArgumentParser(
        description="Convert ReposVul dataset to universal slicer input."
    )
    parser.add_argument(
        "--input", type=Path,
        default=Path(__file__).resolve().parents[2] / "ReposVul" / "ReposVul.jsonl",
        help="Path to ReposVul.jsonl",
    )
    parser.add_argument(
        "--output", type=Path,
        default=Path(__file__).resolve().parents[2] / "Processed" / "reposvul_slicer_input.jsonl",
    )
    parser.add_argument(
        "--languages", type=str, default="c,cpp",
        help="Comma-separated languages to include (default: c,cpp)",
    )
    args = parser.parse_args()
    langs = {_normalize_lang(l) for l in args.languages.split(",")}
    build(args.input, args.output, langs)


if __name__ == "__main__":
    main()
