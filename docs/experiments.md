# Experiments

Code for the evaluation of the dataset. The framework (`src/`, `slicer/`, `scripts/`, `main.py`) does not import anything from here. The inputs are the VeriVul dataset from https://huggingface.co/datasets/qcri/verivul-dataset and the public corpora that VeriVul is compared with.

```
experiments/
  realism/         metric distributions (KS test), embedding clusters, t-SNE
  contamination/   continuation probe for memorisation of the seed functions
  benchmark/       zero-shot vulnerability detection with LLMs
  requirements.txt
```

Install with `pip install -r experiments/requirements.txt`. Each directory has its own README with the exact commands.

| Experiment | Input | Output |
|---|---|---|
| `realism/sample_realism.py` | `verivul.jsonl`, the external corpora under `$EXTERNAL_DATASETS` | `func_<dataset>.jsonl` |
| `realism/ks_analysis.py` | the samples | `ks_results.json`, `ks_summary.txt` |
| `realism/embed_datasets.py` | the samples, an embedding endpoint | `emb_<tag>_<dataset>.npy` |
| `realism/cluster_analysis.py` | the embeddings | cluster metrics, PCA and t-SNE figures |
| `realism/sensitivity.py` | embeddings of all vulnerable programs and of the corpora | per-generator wins over FormAI |
| `contamination/prepare_pairs.py`, `contamination_probe.py` | `verivul.jsonl`, seed functions, an OpenAI-compatible endpoint | per-pair similarity scores |
| `benchmark/build_eval_sets.py` | `verivul.jsonl` | evaluation sets |
| `benchmark/inference.py`, `evaluate*.py` | evaluation sets, model API keys | predictions, reports |
