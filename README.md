# VeriVul framework

Generates vulnerability benchmarks whose labels are checked by a bounded model checker. LLMs rewrite sliced real-world vulnerable functions into self-contained programs. ESBMC 8.4 labels each program VULNERABLE (counterexample) or SAFE (proof). For C and C++, a sanitizer run (ASan, LSan, UBSan) tries to reproduce each counterexample.

```
seed file -> LLM generation -> compile -> ESBMC -> sanitizer reproduction -> export
```

## Dataset

The VeriVul dataset is released separately and is not part of this repository. It holds the verified programs, the ESBMC logs, the subsets and the evaluation sets used in the paper.

* Zenodo: https://doi.org/10.5281/zenodo.24021165
* Hugging Face: https://huggingface.co/datasets/qcri/verivul-dataset

This repository holds the code that produces and evaluates it.

## Layout

| Path | Contents |
|---|---|
| `main.py` | pipeline entry point |
| `src/` | agents, queue, database, dashboard, sanitizer confirmation |
| `slicer/` | seed construction |
| `config/`, `assets/` | models and budgets, prompts |
| `scripts/` | resume, requeue, export, confirm, maintenance |
| `tests/` | unit tests and ESBMC probe programs |
| `experiments/` | realism, contamination and benchmark code |
| `docs/` | pipeline, labels, seeds, experiments |

## Setup

You need Docker, Python 3.12, an OpenAI-compatible LLM endpoint and Node.js for the dashboard.

```bash
pip install -r requirements.txt
bash scripts/setup.sh
cp .env.example .env
docker compose up -d
```

Set `api_base` and `model_name` for each model in `config/config.yaml`, then build the seed file as described in [docs/seeds.md](docs/seeds.md).

## Run

```bash
python main.py data/seeds/seeds.jsonl
python main.py data/seeds/seeds.jsonl --resume
bash scripts/start_web.sh
```

## Export

```bash
python scripts/export_verified.py --output verified_samples.jsonl
python scripts/export_pairs.py --output pairs.jsonl
```

Each record holds the program, the ESBMC verdict and log, and the sanitizer result.

## Tests

```bash
python -m pytest tests -v
```

Tests that run ESBMC need the `esbmc:8.4` image and are skipped without it.

## License

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
