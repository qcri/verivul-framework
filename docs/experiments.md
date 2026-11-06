# Experiments

The framework (`src/`, `slicer/`, `scripts/`, `main.py`) generates and labels programs. Everything that produced the paper's measurements lives in `experiments/` and needs the released dataset plus the external datasets it compares against.

```
experiments/
  realism/         program-level realism: metric distributions (KS test), embedding clusters, t-SNE
  contamination/   continuation probe for memorisation of the seed functions
  benchmark/       zero-shot vulnerability detection with LLMs on VeriVul and five other datasets
  requirements.txt
```

Install with `pip install -r experiments/requirements.txt`. Each directory has its own README with the exact commands.

| experiment | input | output |
|---|---|---|
| `realism/sample_realism.py` | `data/verivul.jsonl`, the matched-sample ids, the external datasets under `$EXTERNAL_DATASETS` | `func_<dataset>.jsonl` |
| `realism/ks_analysis.py` | the samples (or the shipped `metrics_func_*.jsonl`) | `ks_results.json`, `ks_summary.txt` |
| `realism/embed_datasets.py` | the samples, an embedding endpoint | `emb_<tag>_<dataset>.npy` |
| `realism/cluster_analysis.py` | the embeddings | cluster metrics, PCA and t-SNE figures |
| `realism/sensitivity.py` | embeddings of all vulnerable programs and of the corpora | per-generator wins over FormAI |
| `contamination/prepare_pairs.py`, `contamination_probe.py` | `data/verivul.jsonl`, seed functions, an OpenAI-compatible endpoint | per-pair similarity scores |
| `benchmark/build_eval_sets.py` | `data/verivul.jsonl` | evaluation sets in `data/evaluation` |
| `benchmark/inference.py` and `evaluate*.py` | evaluation sets, model API keys | predictions, reports |

The scripts in `dataset/` build the released files from pipeline exports (`build_release.py`, `build_subsets.py`, `build_parquet.py`, `build_croissant.py`), re-run the sanitizer search on SAFE programs (`rerun_safe_sanitizer.py`) and collect stage statistics (`yield_statistics.py`). `scripts/reproduce_*.py` at the artifact root recompute every number of the paper from the shipped files.
