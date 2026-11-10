# Contamination probe

Gives a model the first lines of a seed function or of a released program and scores how closely its continuation reproduces the rest. The scores are longest common substring, identifier recall and edit distance. Higher fidelity on seeds than on released programs indicates memorisation.

```bash
python prepare_pairs.py --release verivul.jsonl --seeds seeds.jsonl
python contamination_probe.py --n 300 --model <model> --api-base https://openrouter.ai/api/v1 --api-key $OPENROUTER_API_KEY \
    --workers 10 --output results/<model>.jsonl
```

`seeds.jsonl` holds the ReposVul functions, with a `uuid` that matches the `seed_uuid` of the released programs. `prepare_pairs.py` picks one released C program per seed.
