# Seeds

A seed is a sliced pre-patch function with provenance. The generation models rewrite it into a new, self-contained program that must reproduce the seed's weakness class. Seeds come from [ReposVul](https://github.com/Eshe0922/ReposVul) and ICVul, both released under the MIT license. Download them separately. They are not part of this repository.

```bash
python -m slicer.adapters.reposvul --input ReposVul.jsonl --output data/seeds/reposvul.universal.jsonl --languages c,cpp,python,java
python -m slicer.adapters.icvul --dataset-dir ICVul-Dataset --output data/seeds/icvul.universal.jsonl
python -m slicer.run --input data/seeds/reposvul.universal.jsonl --output data/seeds/reposvul.sliced.jsonl --workers 24
python -m slicer.run --input data/seeds/icvul.universal.jsonl --output data/seeds/icvul.sliced.jsonl --workers 24
python -m slicer.prepare_seeds --input data/seeds/reposvul.sliced.jsonl data/seeds/icvul.sliced.jsonl --output data/seeds/seeds.jsonl
```

`slicer.run` applies the heuristic inter-procedural backward slicer described in [../slicer/README.md](../slicer/README.md) to C and C++ functions. `prepare_seeds` assigns `target_cwe`. It is the seed's own CWE when ESBMC can verify that class. Otherwise it is a deterministic choice (seeded by the uuid) among the verifiable classes, and `target_cwe_source` records which rule applied. Only byte-identical duplicate functions are dropped.

Required seed fields: `uuid`, `code`, `language`, `slice_code`, `cwes`, `project`. The fields `target_cwe`, `target_cwe_source`, `cve`, `repo_url`, `commit_hash`, `commit_message`, `dataset`, `fixed_code` and `publish_date` are carried through when present.

The pipeline reads the file with `python main.py data/seeds/seeds.jsonl`.
