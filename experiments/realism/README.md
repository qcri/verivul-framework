# Realism

Compares VeriVul programs with ICVul, TitanVul, Mono, ARVO and FormAI. Run the scripts from this directory. Set `REALISM_DIR` to choose the sample directory. The default is `data/realism_samples`.

```bash
export EXTERNAL_DATASETS=/path/to/external
python sample_realism.py
python ks_analysis.py
python embed_datasets.py --endpoint http://localhost:8000 --model <embedding model> --suffix <tag>
python cluster_analysis.py --suffix <tag> --no-title
python sensitivity.py --embeddings <dir> --tag <tag>
```

## VeriVul sample

5,000 vulnerable C programs of the dataset, drawn with the generator mix used in the paper: gemma-4-31b-it 44.8%, seed-coder-8b 24.5%, gpt-oss-120b 23.0% and qwen3.6-35b-a3b 7.7%. The other corpora contribute 6,000 vulnerable functions each, and ARVO 2,917. `sample_realism.py` reads `verivul.jsonl` and uses `matched_sample.json` in the sample directory when it exists.

`code_metrics.py` and `structural_metrics.py` hold the metric extractors.
