"""Writes croissant.json (Croissant 1.1 with core and Responsible AI fields) for the artifact.

    python dataset/build_croissant.py --root .. --base-url https://zenodo.org/records/<ID>/files

Without --base-url the contentUrl values are relative paths inside the artifact.
"""
import argparse
import hashlib
import json
from pathlib import Path

CONTEXT = {
    "@language": "en", "@vocab": "https://schema.org/", "citeAs": "cr:citeAs", "column": "cr:column",
    "conformsTo": "dct:conformsTo", "cr": "http://mlcommons.org/croissant/", "rai": "http://mlcommons.org/croissant/RAI/",
    "prov": "http://www.w3.org/ns/prov#", "data": {"@id": "cr:data", "@type": "@json"},
    "dataType": {"@id": "cr:dataType", "@type": "@vocab"}, "dct": "http://purl.org/dc/terms/",
    "equivalentProperty": "cr:equivalentProperty", "examples": {"@id": "cr:examples", "@type": "@json"},
    "extract": "cr:extract", "field": "cr:field", "fileProperty": "cr:fileProperty", "fileObject": "cr:fileObject",
    "fileSet": "cr:fileSet", "format": "cr:format", "includes": "cr:includes", "isLiveDataset": "cr:isLiveDataset",
    "jsonPath": "cr:jsonPath", "key": "cr:key", "md5": "cr:md5", "parentField": "cr:parentField", "path": "cr:path",
    "recordSet": "cr:recordSet", "references": "cr:references", "regex": "cr:regex", "repeated": "cr:repeated",
    "replace": "cr:replace", "samplingRate": "cr:samplingRate", "sc": "https://schema.org/", "separator": "cr:separator",
    "source": "cr:source", "subField": "cr:subField", "transform": "cr:transform", "isArray": "cr:isArray",
    "arrayShape": "cr:arrayShape",
}
T, I, F, B, U = "sc:Text", "sc:Integer", "sc:Float", "sc:Boolean", "sc:URL"
PROGRAM_FIELDS = [
    ("id", T, "$.id", "Stable identifier of the program (UUID)."),
    ("seed_id", T, "$.seed_id", "Identifier of the seed function the program was generated from."),
    ("parent_id", T, "$.parent_id", "Program this one was generated from when it is the counterpart of another program, if any."),
    ("pair_ids", T, "$.pair_ids", "Ids of the verified counterparts with the opposite label (vulnerable/safe pairs)."),
    ("label", T, "$.label", "VULNERABLE or SAFE (see the label interpretation in DATASHEET.md)."),
    ("language", T, "$.language", "c, cpp or python."),
    ("code", T, "$.code", "Complete self-contained program text that ESBMC verified."),
    ("code_sha256", T, "$.code_sha256", "SHA-256 of the program text."),
    ("loc", I, "$.loc", "Number of lines."),
    ("generation_model", T, "$.generation_model", "LLM that wrote the program."),
    ("generation_batch", T, "$.generation_batch", "Generation batch (A or B), both produced by the same pipeline."),
    ("origin_corpus", T, "$.origin.corpus", "Source corpus of the seed: ReposVul or ICVul."),
    ("origin_cve", T, "$.origin.cve", "CVE identifier of the seed."),
    ("origin_project", T, "$.origin.project", "Upstream project of the seed."),
    ("origin_repo_url", U, "$.origin.repo_url", "Repository URL of the seed."),
    ("origin_commit_hash", T, "$.origin.commit_hash", "Fixing commit of the seed."),
    ("cwes", T, "$.cwes", "Target CWEs of the seed. A SAFE program carries CWEs only through a verified vulnerable counterpart."),
    ("cwe_source", T, "$.cwe_source", "seed or assigned: whether the target CWE is the seed's own or was assigned from the verifiable set."),
    ("seed_cwes", T, "$.seed_cwes", "CWEs recorded for the seed in its source corpus."),
    ("esbmc_cwes", T, "$.esbmc_cwes", "CWEs that ESBMC attaches to the violation (vulnerable programs only)."),
    ("esbmc_cwe_source", T, "$.esbmc_cwe_source", "esbmc (annotation) or rules (catalogue fallback)."),
    ("category", T, "$.category", "Violation category."),
    ("property", T, "$.property", "Violated ESBMC property."),
    ("property_function", T, "$.property_function", "Function containing the violated property."),
    ("property_line", I, "$.property_line", "Line of the violated property."),
    ("trigger_line_number", I, "$.trigger_line_number", "Line of the violating statement from the counterexample."),
    ("trigger_line", T, "$.trigger_line", "Text of the violating statement."),
    ("trigger_in_program", B, "$.trigger_in_program", "Whether the violating statement is in the program text."),
    ("verification_esbmc_version", T, "$.verification.esbmc_version", "ESBMC version (8.4.0)."),
    ("verification_command", T, "$.verification.command", "Full ESBMC command line."),
    ("verification_image", T, "$.verification.image", "Verification container image."),
    ("verification_image_digest", T, "$.verification.image_digest", "Digest of the verification image."),
    ("verification_timeout_s", I, "$.verification.timeout_s", "Time budget in seconds."),
    ("verification_memlimit_mb", I, "$.verification.memlimit_mb", "Memory budget in MB."),
    ("verification_duration_s", F, "$.verification.duration_s", "Verification time in seconds."),
    ("verification_verdict", T, "$.verification.verdict", "ESBMC verdict (FAILED = counterexample, SUCCESSFUL = proof)."),
    ("verification_proof", T, "$.verification.proof", "Proof method for SAFE programs (forward condition)."),
    ("verification_k", I, "$.verification.k", "Induction depth k reached."),
    ("verification_log_excerpt", T, "$.verification.log_excerpt", "Violated-property block and final lines of the ESBMC log."),
    ("verification_log_shard", T, "$.verification.log_shard", "Shard in logs/ that holds the full log, witnesses and SARIF results."),
    ("sanitizer_level", T, "$.sanitizer.level", "Sanitizer result: confirmed_exact, confirmed_function, confirmed_class, other_defect, no_crash_found or crash_found."),
    ("sanitizer_kind", T, "$.sanitizer.kind", "Sanitizer report kind."),
    ("sanitizer_cwes", T, "$.sanitizer.cwes", "CWEs implied by the sanitizer report."),
    ("sanitizer_runs", I, "$.sanitizer.runs", "Executions of the search."),
    ("sanitizer_stage", T, "$.sanitizer.stage", "Stage that produced the finding: search, seeded or afl."),
    ("sanitizer_trace", T, "$.sanitizer.trace", "Sanitizer report of the reproducing run."),
    ("sanitizer_input_b64", T, "$.sanitizer.input_b64", "Base64 of the reproducing input."),
    ("flag_sanitizer_counterexample_on_safe", B, "$.flags.sanitizer_counterexample_on_safe", "A SAFE program on which the sanitizer search found a failing input."),
    ("flag_empty_main", B, "$.flags.empty_main", "The program's main has an empty body."),
    ("flag_lexically_obvious", B, "$.flags.lexically_obvious", "The vulnerability is lexically obvious."),
    ("flag_env_dependent", B, "$.flags.env_dependent", "The verdict depends on unconstrained environment calls."),
    ("provenance_created_at", T, "$.provenance.created_at", "Creation date."),
]
ARRAYS = {"pair_ids", "cwes", "seed_cwes", "esbmc_cwes", "sanitizer_cwes"}
PAIR_FIELDS = [("pair_id", T, "$.pair_id"), ("cwe", T, "$.cwe"), ("vulnerable_id", T, "$.vulnerable_id"), ("safe_id", T, "$.safe_id"),
               ("language", T, "$.language"), ("vulnerable_code", T, "$.vulnerable_code"), ("safe_code", T, "$.safe_code"),
               ("trigger_line_number", I, "$.trigger_line_number"), ("trigger_line", T, "$.trigger_line")]
FLAT = [("id", T), ("seed_id", T), ("parent_id", T), ("pair_ids", T), ("label", T), ("language", T), ("code", T), ("code_sha256", T), ("loc", I),
        ("generation_model", T), ("generation_batch", T), ("source_corpus", T), ("cve", T), ("project", T), ("repo_url", U),
        ("commit_hash", T), ("cwes", T), ("cwe_source", T), ("seed_cwes", T), ("esbmc_cwes", T), ("esbmc_cwe_source", T),
        ("category", T), ("property", T), ("property_function", T), ("property_line", I), ("trigger_line_number", I),
        ("trigger_line", T), ("trigger_in_program", B), ("esbmc_version", T), ("esbmc_verdict", T), ("esbmc_proof", T), ("esbmc_k", I),
        ("esbmc_timeout_s", I), ("esbmc_memlimit_mb", I), ("esbmc_duration_s", F), ("sanitizer_level", T), ("sanitizer_kind", T),
        ("sanitizer_runs", I), ("sanitizer_stage", T), ("flag_sanitizer_counterexample_on_safe", B), ("flag_empty_main", B),
        ("flag_lexically_obvious", B), ("flag_env_dependent", B), ("created_at", T)]


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def file_object(root, base, rel, fmt, description):
    return {"@type": "cr:FileObject", "@id": rel, "name": rel, "description": description, "contentUrl": f"{base}/{rel}" if base else rel,
            "encodingFormat": fmt, "sha256": sha(root / rel) if (root / rel).exists() else "", "contentSize": f"{(root / rel).stat().st_size} B" if (root / rel).exists() else ""}


LICENSES = {"icvul": "https://opensource.org/license/mit", "formai": "https://opensource.org/license/mit", "arvo": "https://opensource.org/license/bsd-2-clause"}
EVAL_FIELDS = [("pair_id", T), ("source", T), ("primary_cwe", T), ("cwe_id", T), ("language", T), ("vulnerable_code", T), ("patched_code", T), ("is_real_pair", T)]


def file_set(sid, description, includes, fmt):
    return {"@type": "cr:FileSet", "@id": sid, "name": sid, "description": description, "encodingFormat": fmt, "includes": includes}


def field(rs, name, dtype, source_key, source_value, description, array=False):
    rel, path = source_value
    keys = path[2:].split(".")
    source = {"fileObject": {"@id": rel}, "extract": {"column": keys[0]}}
    if len(keys) > 1:
        source["transform"] = {"jsonPath": "$." + ".".join(keys[1:])}
    f = {"@type": "cr:Field", "@id": f"{rs}/{name}", "name": name, "description": description, "dataType": dtype, "source": source}
    if array:
        f["isArray"] = True
        f["arrayShape"] = "-1"
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--base-url", default="")
    ap.add_argument("--url", default="https://doi.org/10.5281/zenodo.24017330")
    ap.add_argument("--bundle", action="store_true", help="describe the upload bundle, where small files are packed in data/extras.tar.gz")
    ap.add_argument("--hf", action="store_true", help="describe the Hugging Face mirror (no logs or archives)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    root = Path(args.root)
    base = args.base_url.rstrip("/")
    distribution = [
        file_object(root, base, "data/verivul.jsonl", "application/jsonlines", "All programs with labels, ESBMC and sanitizer records, flags and provenance."),
        file_object(root, base, "data/verivul.parquet", "application/x-parquet", "Flat table of the scalar fields (no traces, inputs or logs)."),
        file_object(root, base, "data/verivul_sample.jsonl", "application/jsonlines", "Random sample of 100 vulnerable and 100 safe programs for inspection."),
        file_object(root, base, "data/evaluation/seed_matched_400.jsonl", "application/jsonlines", "Evaluation set: 400 seed-matched vulnerable/safe pairs, 50 per CWE."),
        file_object(root, base, "data/evaluation/verified_pairs_98.jsonl", "application/jsonlines", "Evaluation set: 98 verified minimal-edit pairs."),
        file_object(root, base, "data/subsets/pairs.jsonl", "application/jsonlines", "The 102 verified vulnerable/safe pairs."),
    ]
    comparison = []
    for corpus, name in (("icvul", "ICVul"), ("formai", "FormAI"), ("arvo", "ARVO")):
        rel = f"data/comparison/{corpus}/eval_samples.jsonl"
        if (root / rel).exists():
            fo = file_object(root, base, rel, "application/jsonlines", f"{name} evaluation pairs used in the LLM comparison (license: {LICENSES[corpus].rsplit('/', 1)[1].upper()}).")
            fo["license"] = LICENSES[corpus]
            comparison.append(fo)
    distribution += comparison
    distribution.append(file_set("esbmc-logs", "Full ESBMC logs, witnesses and SARIF results, 1,000 programs per gzip-compressed JSONL shard (keyed by id).", "data/logs/*.jsonl.gz", "application/gzip"))
    extras = [
        ("subset-ids", "Id lists: c_cpp, python, strict, env_independent, flagged, vulnerable_exact.", "data/subsets/ids_*.txt", "text/plain"),
        ("model-predictions", "Zero-shot predictions of four LLMs on the evaluation sets and on the comparison corpora, with evaluation reports.", "data/evaluation/**/*.json*", "application/json"),
        ("realism", "Code metrics of the sampled programs of VeriVul and five comparison corpora, KS and embedding results.", "data/realism/*", "application/json"),
        ("memorisation", "Memorisation-probe outputs, pairs and 300 MIT-licensed seed functions.", "data/memorisation/*", "application/json"),
        ("pipeline-statistics", "Stage outcomes and failure modes of the generation run.", "data/pipeline_statistics/*.json", "application/json"),
        ("comparison-corpora", "Samples of the comparison corpora: code for ICVul (MIT), FormAI (MIT) and ARVO (BSD 2-Clause), identifiers and hashes only for TitanVul and Mono.", "data/comparison/**/*", "application/json"),
    ]
    if args.bundle:
        archive = file_object(root, base, "data/extras.tar.gz", "application/gzip", "Subsets, predictions, realism, memorisation and pipeline statistics (the directories of the plain tree).")
        distribution.append(archive)
        for sid, d, inc, fmt in extras:
            fs = file_set(sid, d, inc, fmt)
            fs["containedIn"] = {"@id": "data/extras.tar.gz"}
            distribution.append(fs)
    else:
        distribution += [file_set(*e) for e in extras]
    programs = [field("programs", n, t, "jsonPath", ("data/verivul.jsonl", p), d, n in ARRAYS) for n, t, p, d in PROGRAM_FIELDS]
    flat = [{"@type": "cr:Field", "@id": f"programs_flat/{n}", "name": n, "dataType": t,
             "source": {"fileObject": {"@id": "data/verivul.parquet"}, "extract": {"column": n}}} for n, t in FLAT]
    pairs = lambda rs, rel: [field(rs, n, t, "jsonPath", (rel, p), n) for n, t, p in PAIR_FIELDS]
    record_sets = [
        {"@type": "cr:RecordSet", "@id": "programs", "name": "programs", "description": "One record per verified program (13,908).", "field": programs},
        {"@type": "cr:RecordSet", "@id": "programs_flat", "name": "programs_flat", "description": "The same programs as a flat Parquet table.", "field": flat},
        {"@type": "cr:RecordSet", "@id": "seed_matched_400", "name": "seed_matched_400", "description": "Evaluation pairs (400).", "field": pairs("seed_matched_400", "data/evaluation/seed_matched_400.jsonl")},
        {"@type": "cr:RecordSet", "@id": "verified_pairs_98", "name": "verified_pairs_98", "description": "Verified minimal-edit pairs (98).", "field": pairs("verified_pairs_98", "data/evaluation/verified_pairs_98.jsonl")},
    ]
    for corpus, name in (("icvul", "ICVul"), ("formai", "FormAI"), ("arvo", "ARVO")):
        rel = f"data/comparison/{corpus}/eval_samples.jsonl"
        if (root / rel).exists():
            rid = f"{corpus}_eval_samples"
            record_sets.append({"@type": "cr:RecordSet", "@id": rid, "name": rid, "description": f"{name} evaluation pairs of the LLM comparison.",
                                "field": [field(rid, n, t, "jsonPath", (rel, f"$.{n}"), n) for n, t in EVAL_FIELDS]})
    rai = json.load(open(Path(__file__).with_name("rai_fields.json")))
    meta = {
        "@context": CONTEXT, "@type": "sc:Dataset", "name": "VeriVul",
        "description": rai.pop("description") + (" The framework is in the Zenodo record and the GitHub repository." if args.hf else ""), "conformsTo": "http://mlcommons.org/croissant/1.1",
        "citeAs": rai.pop("citeAs"), "license": "https://creativecommons.org/licenses/by/4.0/", "url": args.url, "version": "1.0.0",
        "datePublished": "2026-11-05", "keywords": rai.pop("keywords"), "inLanguage": "en", "isLiveDataset": False,
        "creator": [{"@type": "sc:Person", "name": n} for n in ("Ahmed Lekssays", "Hamza Mouhcine", "Issa Khalil")],
        "distribution": distribution, "recordSet": record_sets,
    }
    meta.update(rai)
    if args.hf:
        swap = {"data/verivul.jsonl": "data/verivul_full.parquet", "data/evaluation/seed_matched_400.jsonl": "data/evaluation/seed_matched_400.parquet",
                "data/evaluation/verified_pairs_98.jsonl": "data/evaluation/verified_pairs_98.parquet", "data/subsets/pairs.jsonl": "data/subsets/pairs.parquet"}
        for d in meta["distribution"]:
            if d["@id"] in swap:
                new = swap[d["@id"]]
                d.update({"@id": new, "name": new, "contentUrl": f"{base}/{new}" if base else new, "encodingFormat": "application/x-parquet",
                          "sha256": sha(root / new), "contentSize": f"{(root / new).stat().st_size} B"})
        for rs in meta["recordSet"]:
            for f in rs["field"]:
                old = f["source"]["fileObject"]["@id"]
                if old in swap:
                    f["source"]["fileObject"]["@id"] = swap[old]
    json.dump(meta, open(args.out or root / "croissant.json", "w"), indent=2)
    print("croissant.json:", len(distribution), "distribution entries,", len(record_sets), "record sets")


if __name__ == "__main__":
    main()
