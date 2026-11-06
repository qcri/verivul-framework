---
license: cc-by-4.0
pretty_name: VeriVul
language_creators:
- machine-generated
annotations_creators:
- machine-generated
multilinguality:
- other-programming-languages
size_categories:
- 10K<n<100K
source_datasets:
- extended
task_categories:
- text-classification
task_ids:
- multi-class-classification
tags:
- code
- vulnerability-detection
- software-security
- formal-verification
- bounded-model-checking
- esbmc
- cwe
- synthetic
- benchmark
configs:
- config_name: default
  default: true
  data_files:
  - split: train
    path: data/verivul.parquet
- config_name: full
  data_files:
  - split: train
    path: data/verivul_full.parquet
- config_name: strict
  data_files:
  - split: train
    path: data/subsets/strict.parquet
- config_name: c_cpp
  data_files:
  - split: train
    path: data/subsets/c_cpp.parquet
- config_name: python
  data_files:
  - split: train
    path: data/subsets/python.parquet
- config_name: pairs
  data_files:
  - split: train
    path: data/subsets/pairs.parquet
- config_name: eval_seed_matched_400
  data_files:
  - split: test
    path: data/evaluation/seed_matched_400.parquet
- config_name: eval_verified_pairs_98
  data_files:
  - split: test
    path: data/evaluation/verified_pairs_98.parquet
---

# VeriVul

13,908 self-contained programs (10,225 vulnerable, 3,683 safe) that LLMs generated from real CVE seed functions of ReposVul and ICVul. Each program has an ESBMC 8.4 verdict. C and C++ programs also have a sanitizer record. The language mix is C 87.4%, C++ 12.2% and Python 0.4%.

Paper: *VeriVul: A Verification-Guided Framework for Generating Realistic Vulnerability Benchmarks*, NeurIPS 2026 Evaluations and Datasets Track.

## Configurations

| Config | Split | Contents |
|---|---|---|
| `default` | train | all programs, scalar fields |
| `full` | train | all programs with nested verifier, sanitizer and flag records |
| `strict` | train | 13,608 programs without flags |
| `c_cpp`, `python` | train | 13,851 C and C++ programs, 57 Python programs |
| `pairs` | train | 102 verified vulnerable and safe pairs |
| `eval_seed_matched_400` | test | 400 pairs, 50 for each of eight CWEs |
| `eval_verified_pairs_98` | test | 98 verified minimal-edit pairs |

```python
from datasets import load_dataset
ds = load_dataset("qcri/verivul-dataset", "strict", split="train")
ds = ds.filter(lambda r: r["label"] == "VULNERABLE" and r["language"] == "c")
```

## Labels

SAFE means ESBMC proves that no checked property is violated under the modelling assumptions in the recorded command. VULNERABLE means ESBMC found a violating execution. Both labels describe the program, not its source CVE. For C and C++ a bounded sanitizer search adds evidence but does not prove the verdict. Two groups of programs are flagged: SAFE programs where the search found a failure, and programs with an empty `main`. The `strict` config excludes them. Read the [datasheet](DATASHEET.md) before use.

## Files outside the configs

The configs read the parquet files. The repository also holds the raw files. They are not part of any config.

| Path | Content |
|---|---|
| `data/verivul.jsonl` | all programs with nested records (same content as the `full` config) |
| `data/verivul_sample.jsonl` | 100 vulnerable and 100 safe programs |
| `data/logs/` | full ESBMC logs, witnesses and SARIF results, `esbmc_logs_<batch>_<n>.jsonl.gz` |
| `data/subsets/` | id lists (`ids_*.txt`), `pairs.jsonl`, `flagged.jsonl` |
| `data/evaluation/` | evaluation sets (`*.jsonl`), `trigger_ground_truth.jsonl`, LLM predictions and reports |
| `data/comparison/` | samples of the comparison corpora, one folder per corpus |
| `data/realism/`, `data/memorisation/`, `data/pipeline_statistics/` | inputs and results of the paper's analyses |

Each log shard holds 1,000 programs, one JSON object per line with `id`, `esbmc_log`, `witness_graphml`, `witness_yaml`, `sarif_results` and `violated_properties`. The field `verification.log_shard` of a program names its shard, and `data/logs/index.json` maps every id to its shard.

```python
import gzip, json
with gzip.open("data/logs/esbmc_logs_A_000.jsonl.gz", "rt") as f:
    log = json.loads(next(f))
print(log["id"], log["esbmc_log"][-200:])
```

## Comparison corpora

`data/comparison/` has the samples of ICVul, FormAI, ARVO, TitanVul and Mono that the paper compares with. ICVul (MIT), FormAI (MIT) and ARVO (BSD 2-Clause) are shipped with code and keep their licenses. TitanVul and Mono are not redistributed because no license was found, so their folders hold identifiers and SHA-256 hashes. The Zenodo record has a script that rebuilds them from the originals. The LLM predictions and code metrics are included for all five.

## More material

The Zenodo record has the framework, the scripts that recompute the paper's numbers and the same data: https://doi.org/10.5281/zenodo.24017330. The framework repository is https://github.com/qcri/verivul-framework.

## License and citation

Data under CC BY 4.0. Seeds derive from ReposVul and ICVul, both MIT. The comparison samples keep the licenses of their sources. See `NOTICE` and `licenses/`.

```bibtex
@inproceedings{lekssays2026verivul,
  title     = {VeriVul: A Verification-Guided Framework for Generating Realistic Vulnerability Benchmarks},
  author    = {Lekssays, Ahmed and Mouhcine, Hamza and Khalil, Issa},
  booktitle = {Advances in Neural Information Processing Systems, Evaluations and Datasets Track},
  year      = {2026},
  note      = {Dataset DOI: 10.5281/zenodo.24017330, code: https://github.com/qcri/verivul-framework}
}
```
