# Dataset construction

Builds the released dataset files in `../data` from two exports of the pipeline database. Run from the framework root.

| Script | Purpose |
|---|---|
| `build_release.py` | merges the exports, derives CWEs and flags, writes `verivul.jsonl` and the log shards |
| `rerun_safe_sanitizer.py` | bounded sanitizer search on every SAFE C and C++ program |
| `build_subsets.py` | id lists and verified pairs |
| `build_parquet.py` | flat Parquet table |
| `build_croissant.py` | Croissant 1.1 file with Responsible AI fields |
| `yield_statistics.py` | stage outcomes of a generation run |
| `build_comparison.py` | writes `data/comparison` from the evaluation and realism samples |
| `build_hf.py` | writes the Hugging Face folder |

```bash
python dataset/rerun_safe_sanitizer.py --input export_a.jsonl --out safe_rerun.jsonl --image esbmc:8.4
python dataset/build_release.py --batch A=slim_a.jsonl,logs_a.jsonl --batch B=slim_b.jsonl,logs_b.jsonl \
    --safe-rerun safe_rerun.jsonl --out ../data
python dataset/build_subsets.py --release ../data/verivul.jsonl --out ../data/subsets
python dataset/build_parquet.py --release ../data/verivul.jsonl --out ../data/verivul.parquet
python experiments/benchmark/build_eval_sets.py --release ../data/verivul.jsonl --out ../data/evaluation
python dataset/build_croissant.py --root ..
```

The pipeline databases are not released.
