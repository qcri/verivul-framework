"""
Embed function-level samples from all five datasets via a vLLM endpoint.

Defaults to jina-embeddings-v5-text-small-retrieval; override via:
  --endpoint URL  (e.g. http://localhost:63009)
  --model NAME    (e.g. jinaai/jina-code-embeddings-1.5b)
  --suffix TAG    (output filename: emb_<TAG>_<dataset>.npy)

Output: data/realism_samples/emb[_<suffix>]_<dataset>.npy
"""
import argparse
import json
import os
import sys
import time
import numpy as np
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

SAMPLES  = Path(os.environ.get("REALISM_DIR", Path(__file__).parent / "data" / "realism_samples"))
DATASETS = ["verivul", "icvul", "titanvul", "mono", "arvo", "formai"]

# vLLM max_model_len = 32768; trim to 24000 chars to leave headroom for tokens.
MAX_CHARS = 24000
BATCH     = 16
WORKERS   = 8


def embed_batch(texts, endpoint, model, api):
    if api == "tei":
        payload = {"inputs": texts}
    else:  # vllm / openai-compatible
        payload = {"model": model, "input": texts}
    for attempt in range(5):
        try:
            r = requests.post(endpoint, json=payload, timeout=300)
            r.raise_for_status()
            body = r.json()
            if api == "tei":
                # TEI returns a flat list of embeddings
                return body
            return [d["embedding"] for d in body["data"]]
        except Exception as e:
            wait = 2 ** attempt
            print(f"  retry {attempt+1} after {wait}s: {e}", flush=True)
            time.sleep(wait)
    raise RuntimeError("embedding endpoint failed 5 times")


def embed_dataset(name, endpoint, model, api, suffix, max_chars, batch, workers):
    tag = f"_{suffix}" if suffix else ""
    path_in  = SAMPLES / f"func_{name}.jsonl"
    path_out = SAMPLES / f"emb{tag}_{name}.npy"
    if path_out.exists():
        print(f"{name}: cached → {path_out}")
        return

    with open(path_in) as f:
        records = [json.loads(l) for l in f]
    texts = [r["code"][:max_chars] for r in records]
    n = len(texts)
    print(f"{name}: embedding {n} samples → {path_out.name}", flush=True)

    batches = [(i, texts[i:i+batch]) for i in range(0, n, batch)]
    out = [None] * len(batches)
    t0 = time.time()
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(embed_batch, b, endpoint, model, api): i
                   for i, (idx, b) in enumerate(batches)}
        for fut in as_completed(futures):
            i = futures[fut]
            out[i] = fut.result()
            done += 1
            if done % 20 == 0:
                rate = done * batch / (time.time() - t0 + 1e-6)
                print(f"  {done}/{len(batches)} batches  ({rate:.0f} samples/s)", flush=True)

    embs = np.array([v for b in out for v in b], dtype=np.float32)
    assert embs.shape[0] == n, f"expected {n}, got {embs.shape[0]}"
    np.save(path_out, embs)
    print(f"{name}: saved {embs.shape} → {path_out}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--endpoint", default="http://localhost:8000",
                   help="server base URL (no path suffix)")
    p.add_argument("--api",      default="vllm", choices=["vllm", "tei"],
                   help="vllm = OpenAI-compatible /v1/embeddings; "
                        "tei = HuggingFace TEI /embed")
    p.add_argument("--model",    default="jinaai/jina-embeddings-v5-text-small-retrieval")
    p.add_argument("--suffix",   default="",
                   help="filename tag, e.g. 'codev1' → emb_codev1_<dataset>.npy")
    p.add_argument("--max-chars", type=int, default=24000)
    p.add_argument("--batch",    type=int, default=16)
    p.add_argument("--workers",  type=int, default=8)
    p.add_argument("datasets", nargs="*", help="subset of " + ",".join(DATASETS))
    args = p.parse_args()

    base = args.endpoint.rstrip("/")
    endpoint = base + ("/embed" if args.api == "tei" else "/v1/embeddings")
    only = args.datasets or DATASETS
    print(f"api={args.api}  endpoint={endpoint}  model={args.model}  "
          f"suffix={args.suffix or '(none)'}  batch={args.batch}  workers={args.workers}")
    for ds in only:
        embed_dataset(ds, endpoint, args.model, args.api, args.suffix,
                      args.max_chars, args.batch, args.workers)


if __name__ == "__main__":
    main()
