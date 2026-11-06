# Realism

Compares VeriVul programs with ICVul, TitanVul, Mono, ARVO and FormAI. Run the scripts from this directory. Set `REALISM_DIR` to use another sample directory. The default is `data/realism_samples`, and the artifact's `data/realism` also works.

```bash
export EXTERNAL_DATASETS=/path/to/external
python sample_realism.py
python ks_analysis.py
python embed_datasets.py --endpoint http://localhost:8000 --model <embedding model> --suffix <tag>
python cluster_analysis.py --suffix <tag> --no-title
python sensitivity.py --embeddings <dir> --tag <tag>
```

## VeriVul sample

5,000 vulnerable C programs drawn with the generator mix used in the paper: gemma-4-31b-it 44.8%, seed-coder-8b 24.5%, gpt-oss-120b 23.0% and qwen3.6-35b-a3b 7.7%. The ids are in `data/realism/matched_sample.json`, and `sample_realism.py` uses them when present. The other corpora contribute 6,000 vulnerable functions each, and ARVO 2,917.

## Reproducing without the corpora

`data/realism/metrics_func_<dataset>.jsonl` holds the 17 code metrics of every sampled function. Running `ks_analysis.py` on a copy of that folder reproduces `ks_results.json`, and `scripts/reproduce_realism.py` does this. The embedding results need the corpora, and embeddings are not shipped.

`code_metrics.py` and `structural_metrics.py` hold the metric extractors.
