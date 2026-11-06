"""Writes the Hugging Face mirror (dataset card, parquet and JSONL files, Croissant) from the artifact tree.

    python dataset/build_hf.py --root .. --out ../../verivul_hf
"""
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pyarrow
import pyarrow.compute as pc
import pyarrow.parquet as pq


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    root, out = Path(args.root), Path(args.out)
    here = Path(__file__).resolve().parent
    shutil.rmtree(out, ignore_errors=True)
    for d in ("data/subsets", "data/evaluation", "licenses"):
        (out / d).mkdir(parents=True)
    for rel in ("data/verivul.parquet", "data/verivul_sample.jsonl"):
        shutil.copy(root / rel, out / rel)
    for rel, dest in (("data/verivul.jsonl", "data/verivul_full.parquet"), ("data/subsets/pairs.jsonl", "data/subsets/pairs.parquet"),
                      ("data/evaluation/seed_matched_400.jsonl", "data/evaluation/seed_matched_400.parquet"),
                      ("data/evaluation/verified_pairs_98.jsonl", "data/evaluation/verified_pairs_98.parquet")):
        pq.write_table(pyarrow.Table.from_pylist([json.loads(line) for line in open(root / rel)]), out / dest, compression="zstd")
    table = pq.read_table(root / "data" / "verivul.parquet")
    for name in ("strict", "c_cpp", "python"):
        ids = (root / "data" / "subsets" / ("ids_%s.txt" % name)).read_text().split()
        pq.write_table(table.filter(pc.is_in(table["id"], value_set=pyarrow.array(ids))), out / "data" / "subsets" / f"{name}.parquet", compression="zstd")
    shutil.copy(here / "hf_card.md", out / "README.md")
    for name in ("DATASHEET.md", "LICENSE-DATA", "NOTICE"):
        shutil.copy(root / name, out / name)
    for f in (root / "licenses").iterdir():
        shutil.copy(f, out / "licenses" / f.name)
    subprocess.run([sys.executable, str(here / "build_croissant.py"), "--root", str(out), "--hf", "--out", str(out / "croissant.json")], check=True)
    print(sum(1 for _ in out.rglob("*") if _.is_file()), "files")


if __name__ == "__main__":
    main()
