# Zero-shot benchmark

Each model sees the vulnerable and the safe program of a pair as two separate queries. It answers `VULNERABLE` or `SAFE` and names the triggering line. VeriVul is compared with TitanVul, Mono, ICVul, ARVO and FormAI on the CWEs each pair of datasets shares.

| Path | Purpose |
|---|---|
| `inference.py` | OpenRouter chat completions (`OPENROUTER_API_KEY`) |
| `inference_openrouter_reasoning.py` | OpenRouter with reasoning enabled |
| `inference_deepseek.py` | DeepSeek API (`DEEPSEEK_API_KEY`) |
| `inference_local.py` | self-hosted `/v1/responses` server |
| `evaluate.py` | accuracy, precision, recall and F1, overall and per CWE |
| `evaluate_trigger.py` | trigger-line localisation against the ESBMC trigger line |
| `prompts/` | the prompt used by every inference script |

## Evaluation sets

The two VeriVul evaluation sets come with the dataset. `seed_matched_400.jsonl` has 50 vulnerable and safe pairs from the same seed for each of CWE-20, 119, 120, 125, 190, 401, 416 and 476. `verified_pairs_98.jsonl` has all verified parent and child pairs.

## Commands

```bash
python inference.py --model openai/gpt-5.4 --dataset VeriVul --workers 16 --max-tokens 4096 --resume --output <file>
python inference.py --model deepseek/deepseek-v4-pro --no-thinking ...
python inference.py --model openai/gpt-oss-120b ...
python inference.py --model anthropic/claude-opus-4.7 ...
python evaluate.py && python evaluate_trigger.py
```

The inference scripts read `<Dataset>_samples.json` files from `$VERIVUL_SAMPLES` (default `samples/`). Each file is a list of pairs with `vulnerable_code`, `patched_code` and `primary_cwe`. To convert an evaluation set from the dataset, rename `safe_code` to `patched_code` and `cwe` to `primary_cwe`. All inference scripts accept `--dataset`, `--all`, `--test`, `--workers`, `--max-samples`, `--output` and `--resume`.

## Comparison corpora

TitanVul, Mono, ICVul, FormAI and ARVO are public datasets that you download from their own sources. The paper uses 50 pairs per shared CWE, drawn with seed 42, and converts them to the same sample format.

## Results

`evaluate.py` reads the predictions in `results/<model>/` and writes `eval_report.{txt,json}` per model. `evaluate_trigger.py` writes `trigger_eval_report.{txt,json}`.
