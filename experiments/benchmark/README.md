# Zero-shot benchmark

Each model sees the vulnerable and the safe program of a pair as two separate queries. It answers `VULNERABLE` or `SAFE` and names the triggering line. VeriVul is compared with TitanVul, Mono, ICVul, ARVO and FormAI on the CWEs each pair of datasets shares.

| Path | Purpose |
|---|---|
| `build_eval_sets.py` | builds the VeriVul evaluation sets from `data/verivul.jsonl` |
| `inference.py` | OpenRouter chat completions (`OPENROUTER_API_KEY`) |
| `inference_openrouter_reasoning.py` | OpenRouter with reasoning enabled |
| `inference_deepseek.py` | DeepSeek API (`DEEPSEEK_API_KEY`) |
| `inference_local.py` | self-hosted `/v1/responses` server |
| `evaluate.py` | accuracy, precision, recall and F1, overall and per CWE |
| `evaluate_trigger.py` | trigger-line localisation against the ESBMC trigger line |
| `prompts/` | the prompt used by every inference script |
| `datasets/convert_datasets.py` | converts the comparison corpora to one schema |
| `datasets/rebuild_withheld_samples.py` | rebuilds the TitanVul and Mono samples from the originals and checks their hashes |

## Evaluation sets

`build_eval_sets.py` writes `data/evaluation/` with three files. `seed_matched_400.jsonl` has 50 vulnerable and safe pairs from the same seed for each of CWE-20, 119, 120, 125, 190, 401, 416 and 476. `verified_pairs_98.jsonl` has all verified parent and child pairs. `trigger_ground_truth.jsonl` has the ESBMC trigger lines. Programs flagged for a sanitizer counterexample on a SAFE label or for an empty `main` are excluded. The shipped files are the ones used in the paper.

## Commands

```bash
python build_eval_sets.py --release ../../../data/verivul.jsonl --out ../../../data/evaluation
python inference.py --model openai/gpt-5.4 --dataset VeriVul --workers 16 --max-tokens 4096 --resume --output <file>
python inference.py --model deepseek/deepseek-v4-pro --no-thinking ...
python inference.py --model openai/gpt-oss-120b ...
python inference.py --model anthropic/claude-opus-4.7 ...
python evaluate.py && python evaluate_trigger.py
```

`inference.py` reads `datasets/Samples/<Dataset>_samples.json`. To convert an evaluation file, rename `safe_code` to `patched_code` and `cwe` to `primary_cwe`. All inference scripts accept `--dataset`, `--all`, `--test`, `--workers`, `--max-samples`, `--output` and `--resume`.

## Comparison corpora

Predictions on the comparison corpora are in `data/evaluation/predictions/<model>/`. The corpora are not redistributed. `datasets/convert_datasets.py` converts the originals found in `$EXTERNAL_DATASETS`.

## Results

`evaluate.py` and `evaluate_trigger.py` read `data/evaluation/predictions` and write `eval_report.{txt,json}` per model and `trigger_eval_report.{txt,json}`. The shipped reports are the ones behind the paper's tables.

## Comparison corpora

The samples are in `data/comparison/<corpus>/` and the predictions in `data/evaluation/predictions/<model>/`. The samples of ICVul, FormAI and ARVO are shipped with code. TitanVul and Mono are withheld because no license was found. To rebuild them run `python datasets/rebuild_withheld_samples.py --external <dir> --manifest ../../../data/comparison --out rebuilt`, where `<dir>` holds `TitanVul/TitanVul.csv` and `monoVul/*.json`. `scripts/reproduce_benchmark_full.py` recomputes Table 3 and the per-CWE tables from these files.
