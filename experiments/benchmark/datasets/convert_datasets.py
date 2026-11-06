"""
Converts TitanVul, FormAI, Mono and ICVul into a unified JSON format.

Unified schema per record:
  id               - unique identifier: <source>_<index>
  source           - dataset name
  func_before      - vulnerable / pre-patch code (or the sole code for single-label datasets)
  func_after       - patched code (null for single-label datasets)
  label            - "VULNERABLE" | "SAFE" | "UNKNOWN" (null for pair datasets)
  cve_id           - CVE identifier string or null
  cwe_id           - list of CWE strings (empty list if none)
  cve_description  - textual description or null
  commit_link      - URL to commit or null
  commit_message   - commit message text or null
  file_name        - source file name or null
  language         - programming language or null
  date             - ISO date/datetime string or null
"""

import hashlib
import json
import os
from pathlib import Path

OUT_DIR = Path(__file__).parent
DATASETS_ROOT = Path(os.environ.get("EXTERNAL_DATASETS", OUT_DIR / "external"))

# Paired datasets are restricted to C/C++ for cross-dataset comparability.
C_LANGS = {"C", "C++"}


def _code_hash(code: str) -> str:
    return hashlib.sha256(code.strip().encode("utf-8")).hexdigest()


def dedup_records(records: list, is_pair: bool) -> list:
    """Remove records whose func_before (or func_after for pairs) was already seen."""
    seen: set = set()
    out = []
    for r in records:
        if is_pair:
            fb = r.get("func_before") or ""
            fa = r.get("func_after") or ""
            hb = _code_hash(fb) if fb else None
            ha = _code_hash(fa) if fa else None
            if (hb and hb in seen) or (ha and ha in seen):
                continue
            if hb: seen.add(hb)
            if ha: seen.add(ha)
        else:
            code = r.get("func_before") or ""
            hc = _code_hash(code) if code else None
            if hc and hc in seen:
                continue
            if hc: seen.add(hc)
        out.append(r)
    return out


def norm_str(v):
    v = str(v).strip() if v is not None else ""
    return v if v and v.lower() not in ("n/a", "none", "null", "") else None


def norm_list(v):
    """Normalize a CWE value into a deduplicated list of uppercase CWE strings."""
    if not v:
        return []
    if isinstance(v, list):
        items = v
    else:
        # Handle comma-separated strings like "CWE-125, CWE-787"
        items = str(v).split(",")
    seen = set()
    result = []
    for item in items:
        s = item.strip().upper()
        if s and s not in ("N/A", "NONE", "NULL", "") and s not in seen:
            seen.add(s)
            result.append(s)
    return result


_LANG_MAP = {
    # extensions
    "c": "C", "cpp": "C++", "cc": "C++", "cxx": "C++", "h": "C", "hpp": "C++",
    "java": "Java", "py": "Python", "js": "JavaScript",
    "ts": "TypeScript", "go": "Go", "rs": "Rust",
    "php": "PHP", "rb": "Ruby", "cs": "C#",
    # free-text language names (lowercase keys)
    "python": "Python", "javascript": "JavaScript", "typescript": "TypeScript",
    "golang": "Go", "rust": "Rust", "ruby": "Ruby", "csharp": "C#",
    "c#": "C#", "c++": "C++", "c/c++": "C++",
}


def norm_language(lang):
    """Return a consistently-capitalised language name, or None."""
    if not lang:
        return None
    key = lang.strip().lower()
    return _LANG_MAP.get(key, lang.strip())


def ext_to_language(ext):
    if not ext:
        return None
    return _LANG_MAP.get(ext.lstrip(".").lower(), ext.lstrip(".").upper())


# ---------------------------------------------------------------------------
# TitanVul
# ---------------------------------------------------------------------------
def convert_titanvul():
    src = DATASETS_ROOT / "TitanVul" / "TitanVul.json"
    with open(src, encoding="utf-8") as f:
        data = json.load(f)

    records = []
    for i, r in enumerate(data):
        lang = ext_to_language(norm_str(r.get("extension")))
        records.append({
            "id": f"TitanVul_{i}",
            "source": "TitanVul",
            "func_before": norm_str(r.get("func_before")),
            "func_after": norm_str(r.get("func_after")),
            "label": None,
            "cve_id": norm_str(r.get("cve_id")),
            "cwe_id": norm_list(r.get("cwe_id")),
            "cve_description": norm_str(r.get("cve_description")),
            "commit_link": norm_str(r.get("commit_link")),
            "commit_message": norm_str(r.get("commit_message")),
            "file_name": norm_str(r.get("file_name")),
            "language": lang,
            "date": norm_str(r.get("datetime")),
        })

    records = [r for r in records if r.get("language") in C_LANGS]
    records = dedup_records(records, is_pair=True)
    out = OUT_DIR / "TitanVul_unified.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    print(f"TitanVul  -> {len(records):>6} records  ->  {out.name}  (C/C++ only, deduped)")


# ---------------------------------------------------------------------------
# FormAI
# ---------------------------------------------------------------------------
def formAI_label(r):
    cat = str(r.get("category", "")).strip()
    if cat == "VULNERABLE":
        return "VULNERABLE"
    if cat == "NON-VULNERABLE":
        return "SAFE"
    return "UNKNOWN"


def convert_formai():
    src = DATASETS_ROOT / "FormAI-dataset" / "FormAI-v2.json"
    with open(src, encoding="utf-8") as f:
        data = json.load(f)

    records = []
    for i, r in enumerate(data):
        fname = norm_str(r.get("file_name"))
        ext = Path(fname).suffix if fname else ""
        lang = ext_to_language(ext)
        records.append({
            "id": f"FormAI_{i}",
            "source": "FormAI",
            "func_before": norm_str(r.get("source_code")),
            "func_after": None,
            "label": formAI_label(r),
            "cve_id": None,
            "cwe_id": norm_list(r.get("mapped_cwes")),
            "cve_description": None,
            "commit_link": None,
            "commit_message": None,
            "file_name": fname,
            "language": lang,
            "date": None,
        })

    records = dedup_records(records, is_pair=False)
    out = OUT_DIR / "FormAI_unified.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    print(f"FormAI    -> {len(records):>6} records  ->  {out.name}  (deduped)")


# ---------------------------------------------------------------------------
# Mono (mono-metadata)
# One record per patch across all CVE metadata files.
# Each file may have multiple commits; each commit may have multiple patches.
# ---------------------------------------------------------------------------
def convert_mono():
    import glob

    src_dir = DATASETS_ROOT / "mono-metadata"
    files = sorted(glob.glob(str(src_dir / "*.json")))

    records = []
    for fpath in files:
        with open(fpath, encoding="utf-8") as f:
            d = json.load(f)

        cve_id = norm_str(d.get("cve_id"))
        cwe_id = norm_list(d.get("cwe_ids"))
        description = norm_str(d.get("description"))
        language = norm_language(norm_str(d.get("language")))

        for commit_hash, commit in d.get("commits", {}).items():
            commit_url = norm_str(commit.get("commit_url"))
            commit_msg = norm_str(commit.get("commit_msg"))

            for patch_idx, patch in enumerate(commit.get("patches", [])):
                file_path = norm_str(patch.get("file_path"))
                ext = Path(file_path).suffix if file_path else ""
                # Prefer language from top-level field; fall back to extension
                lang = language or ext_to_language(ext)

                records.append({
                    "id": f"Mono_{cve_id}_{commit_hash[:8]}_{patch_idx}",
                    "source": "Mono",
                    "func_before": norm_str(patch.get("func_before")),
                    "func_after": norm_str(patch.get("func_after")),
                    "label": None,
                    "cve_id": cve_id,
                    "cwe_id": cwe_id,
                    "cve_description": description,
                    "commit_link": commit_url,
                    "commit_message": commit_msg,
                    "file_name": file_path,
                    "language": lang,
                    "date": None,
                })

    records = [r for r in records if r.get("language") in C_LANGS]
    records = dedup_records(records, is_pair=True)
    out = OUT_DIR / "Mono_unified.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    print(f"Mono      -> {len(records):>6} records  ->  {out.name}  (C/C++ only, deduped)")


# ---------------------------------------------------------------------------
# ICVul
# One record per unique (hash, name, filename) function group.
# before_change=True  -> func_before (vulnerable)
# before_change=False -> func_after  (patched)
# CVE/CWE joined from cve_fc_vcc_mapping via fc_hash == hash.
# Commit metadata (message, date) joined from commit_info via hash.
# A commit may fix multiple CVEs; all CWEs are collected into one list.
# ---------------------------------------------------------------------------
def convert_icvul():
    from collections import defaultdict

    src = DATASETS_ROOT / "ICVul-Dataset"

    with open(src / "function_info.json", encoding="utf-8") as f:
        func_rows = json.load(f)

    with open(src / "cve_fc_vcc_mapping.json", encoding="utf-8") as f:
        cve_map = json.load(f)

    with open(src / "commit_info.json", encoding="utf-8") as f:
        commit_list = json.load(f)

    # hash -> commit metadata
    commits = {r["hash"]: r for r in commit_list}

    # fc_hash -> list of {cve_id, cwe_id, repo_url}
    hash_to_cve = defaultdict(list)
    for r in cve_map:
        hash_to_cve[r["fc_hash"]].append({
            "cve_id": r["cve_id"],
            "cwe_id": r["cwe_id"],
            "repo_url": r["repo_url"],
        })

    # Group functions by (hash, name, filename)
    groups = defaultdict(lambda: {"before": None, "after": None})
    for r in func_rows:
        key = (r["hash"], r["name"], r["filename"])
        slot = "before" if r["before_change"] == "True" else "after"
        # Keep first occurrence when duplicates exist
        if groups[key][slot] is None:
            groups[key][slot] = r["code"]

    records = []
    for idx, ((commit_hash, func_name, filename), versions) in enumerate(groups.items()):
        cve_entries = hash_to_cve.get(commit_hash, [])
        commit = commits.get(commit_hash, {})

        # Collect all unique CVE ids and CWE ids for this commit
        cve_ids = list(dict.fromkeys(e["cve_id"] for e in cve_entries if e.get("cve_id")))
        cwe_ids = norm_list(",".join(e["cwe_id"] for e in cve_entries if e.get("cwe_id")))
        repo_url = norm_str(cve_entries[0]["repo_url"]) if cve_entries else None

        commit_url = (
            f"{repo_url}/commit/{commit_hash}" if repo_url else None
        )

        ext = Path(filename).suffix if filename else ""
        safe_fname = Path(filename).name if filename else "unknown"

        records.append({
            "id": f"{commit_hash}_{func_name}_{safe_fname}",
            "source": "ICVul",
            "func_before": norm_str(versions["before"]),
            "func_after": norm_str(versions["after"]),
            "label": None,
            "cve_id": cve_ids[0] if len(cve_ids) == 1 else (", ".join(cve_ids) if cve_ids else None),
            "cwe_id": cwe_ids,
            "cve_description": None,
            "commit_link": commit_url,
            "commit_message": norm_str(commit.get("msg")),
            "file_name": norm_str(filename),
            "language": ext_to_language(ext),
            "date": norm_str(commit.get("author_date")),
        })

    records = [r for r in records if r.get("language") in C_LANGS]
    records = dedup_records(records, is_pair=True)
    out = OUT_DIR / "ICVul_unified.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    print(f"ICVul     -> {len(records):>6} records  ->  {out.name}  (C/C++ only, deduped)")


if __name__ == "__main__":
    convert_titanvul()
    convert_formai()
    convert_mono()
    convert_icvul()
    print("\nDone. All unified files written to:", OUT_DIR)
