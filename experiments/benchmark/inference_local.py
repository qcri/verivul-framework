"""
inference_local.py — Zero-shot vulnerability detection via a local OpenAI Responses API.

Mirrors inference.py but targets a self-hosted endpoint that speaks the
OpenAI Responses API (/v1/responses) instead of OpenRouter's Chat Completions.

Payload differences vs inference.py:
  - endpoint : /v1/responses  (not /v1/chat/completions)
  - input    : plain string   (not messages array)
  - max_output_tokens instead of max_tokens
  - response : output[0].content[0].text

Usage
-----
  python inference_local.py --model gpt-oss --dataset VeriVul

  python inference_local.py --model gpt-oss --all \\
      --host http://<server>:8000 --api-key <key> --workers 4

  python inference_local.py --model gpt-oss --test
"""

import argparse
import json
import os
import re
import threading
import time
import traceback as _tb
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from string import Template

import requests
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT        = Path(__file__).parent
SAMPLES_DIR = ROOT / "datasets" / "Samples"
RESULTS_DIR = ROOT / "results"
PROMPTS_DIR = ROOT / "prompts"

AVAILABLE_DATASETS = [p.stem.replace("_samples", "")
                      for p in SAMPLES_DIR.glob("*_samples.json")]

# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------
def _load_prompt_file(name: str) -> str:
    path = PROMPTS_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Prompt file not found: {path}")
    return path.read_text(encoding="utf-8").strip()


PROMPT_TEMPLATE = _load_prompt_file("vulnerability_detection.txt")


def build_prompt(code: str) -> str:
    return Template(PROMPT_TEMPLATE).safe_substitute(code=code)


# ---------------------------------------------------------------------------
# Local Responses API client
# ---------------------------------------------------------------------------
SYSTEM_MSG = (
    "You are a security expert specialising in static code analysis. "
    "You must respond with a single valid JSON object and nothing else. "
    "Do not include any explanation, markdown, or text outside the JSON."
)


def call_local(
    host: str,
    model: str,
    prompt: str,
    api_key: str,
    max_output_tokens: int = 6000,
    timeout: int = 120,
) -> str:
    """Call /v1/responses and return the assistant text content."""
    url = host.rstrip("/") + "/v1/responses"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "input": [
            {"role": "system", "content": SYSTEM_MSG},
            {"role": "user",   "content": prompt},
        ],
        "max_output_tokens": max_output_tokens,
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()

    # Surface application-level errors returned as 200 OK
    if "error" in data:
        raise requests.HTTPError(
            f"API error: {data['error']}", response=resp
        )

    # Extract text from Responses API output structure.
    # Reasoning models return output as a list that may start with one or more
    # {"type": "reasoning", ...} items before the final {"type": "message", ...}
    # item.  We skip reasoning items and look for the message item.
    try:
        output = data["output"]
        if isinstance(output, list):
            for item in output:
                if item.get("type") == "reasoning":
                    continue
                # "message" item — content is a list of content blocks
                content = item.get("content")
                if isinstance(content, list):
                    for block in content:
                        text = block.get("text")
                        if text:
                            return text
                # Some servers put text directly on the item
                text = item.get("text")
                if isinstance(text, str) and text:
                    return text

        # Flat fallback used by some server variants
        if "output_text" in data and data["output_text"]:
            return data["output_text"]
    except (KeyError, IndexError, TypeError):
        pass

    raise ValueError(f"Unexpected response structure: {json.dumps(data)[:300]}")


def parse_response(raw: str) -> dict:
    """Extract the JSON object from the model response."""
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()

    # 1. Try the whole cleaned string
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # 2. Walk the string to find the outermost {...} block, handles preamble text
    depth = best_start = best_end = -1
    for i, ch in enumerate(cleaned):
        if ch == "{":
            if depth == -1:
                best_start = i
                depth = 0
            depth += 1
        elif ch == "}" and depth >= 0:
            depth -= 1
            if depth == 0:
                best_end = i + 1
    if best_start != -1 and best_end != -1:
        try:
            return json.loads(cleaned[best_start:best_end])
        except json.JSONDecodeError:
            pass

    return {"analysis": raw, "vulnerability_status": "PARSE_ERROR", "cwe": None,
            "trigger_line": None, "trigger_code": None}


# ---------------------------------------------------------------------------
# Per-item worker
# ---------------------------------------------------------------------------
def process_item(
    item: dict,
    host: str,
    model: str,
    api_key: str,
    max_output_tokens: int,
    delay: float,
) -> dict:
    """Run inference for a single evaluation item and return the result dict."""
    _log = open(ROOT / "debug_errors_local.log", "a")

    def _err(msg: str):
        print(msg, flush=True)
        _log.write(msg + "\n")
        _log.flush()

    try:
        prompt = build_prompt(item["code"])
    except Exception as exc:
        _err(f"  [{item['pair_id']}] build_prompt FAILED: {type(exc).__name__}: {exc}")
        _tb.print_exc(file=_log)
        _log.close()
        return _error_result(item, str(exc))

    raw = None
    for attempt in range(1, 4):
        _err(f"  [{item['pair_id']}] attempt {attempt}/3 ...")
        try:
            raw = call_local(host, model, prompt, api_key,
                             max_output_tokens=max_output_tokens)
            break
        except requests.HTTPError as e:
            r = e.response
            status = r.status_code if r is not None else "?"
            try:
                body = r.json() if r is not None else ""
            except Exception:
                body = r.text[:500] if r is not None else ""
            if status == 429:
                wait = 10 * attempt
                _err(f"  [{item['pair_id']}] Rate limited — waiting {wait}s (attempt {attempt}/3)")
                time.sleep(wait)
            else:
                _err(f"  [{item['pair_id']}] HTTP {status} (attempt {attempt}/3): {body}")
                time.sleep(2 * attempt)
        except BaseException as e:
            _err(f"  [{item['pair_id']}] {type(e).__name__} (attempt {attempt}/3): {e}")
            _tb.print_exc(file=_log)
            _log.flush()
            time.sleep(2 * attempt)

    _log.close()

    if raw is None:
        print(f"  [{item['pair_id']}] All retries exhausted — recorded as API_ERROR", flush=True)
        parsed = {"analysis": None, "vulnerability_status": "API_ERROR",
                  "cwe": None, "trigger_line": None, "trigger_code": None}
    else:
        parsed = parse_response(raw)

    prediction = parsed.get("vulnerability_status", "").upper()
    is_correct = prediction == item["ground_truth"] and prediction in ("VULNERABLE", "SAFE")

    raw_trigger = parsed.get("trigger_line")
    try:
        trigger_line = int(raw_trigger) if raw_trigger is not None else None
    except (ValueError, TypeError):
        trigger_line = None

    if delay > 0:
        time.sleep(delay)

    return {
        "pair_id":       item["pair_id"],
        "source":        item["source"],
        "primary_cwe":   item["primary_cwe"],
        "language":      item["language"],
        "code_type":     item["code_type"],
        "ground_truth":  item["ground_truth"],
        "is_real_pair":  item["is_real_pair"],
        "prediction":    prediction,
        "correct":       is_correct,
        "analysis":      parsed.get("analysis"),
        "cwe_predicted": parsed.get("cwe"),
        "trigger_line":  trigger_line,
        "trigger_code":  parsed.get("trigger_code"),
        "raw_response":  raw,
    }


def _error_result(item: dict, msg: str) -> dict:
    return {
        "pair_id": item["pair_id"], "source": item["source"],
        "primary_cwe": item["primary_cwe"], "language": item["language"],
        "code_type": item["code_type"], "ground_truth": item["ground_truth"],
        "is_real_pair": item["is_real_pair"], "prediction": "API_ERROR",
        "correct": False, "analysis": msg, "cwe_predicted": None,
        "trigger_line": None, "trigger_code": None, "raw_response": None,
    }


# ---------------------------------------------------------------------------
# Inference loop
# ---------------------------------------------------------------------------
def run_inference(
    host: str,
    model: str,
    dataset: str,
    api_key: str,
    output_path: Path,
    max_output_tokens: int,
    delay: float,
    max_samples: int | None,
    resume: bool,
    workers: int,
):
    samples_file = SAMPLES_DIR / f"{dataset}_samples.json"
    with open(samples_file, encoding="utf-8") as f:
        samples = json.load(f)

    items = []
    for s in samples:
        items.append({
            "pair_id":     s["pair_id"],
            "source":      s["source"],
            "primary_cwe": s["primary_cwe"],
            "language":    s.get("language"),
            "code_type":   "vulnerable",
            "code":        s["vulnerable_code"],
            "ground_truth":"VULNERABLE",
            "is_real_pair":s.get("is_real_pair", True),
        })
        items.append({
            "pair_id":     s["pair_id"],
            "source":      s["source"],
            "primary_cwe": s["primary_cwe"],
            "language":    s.get("language"),
            "code_type":   "patched",
            "code":        s["patched_code"],
            "ground_truth":"SAFE",
            "is_real_pair":s.get("is_real_pair", True),
        })

    if max_samples:
        items = items[:max_samples]

    done: set[tuple] = set()
    if resume and output_path.exists():
        with open(output_path, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                    done.add((r["pair_id"], r["code_type"]))
                except (json.JSONDecodeError, KeyError):
                    pass
        print(f"Resuming: {len(done)} items already done, skipping.")

    pending = [it for it in items if (it["pair_id"], it["code_type"]) not in done]
    total = len(pending)
    print(f"Dataset : {dataset}  ({len(samples)} pairs → {len(items)} items, "
          f"{total} pending)")
    print(f"Model   : {model}  @  {host}")
    print(f"Workers : {workers}  |  delay: {delay}s per worker")
    print(f"Output  : {output_path}\n")

    write_lock = threading.Lock()
    print_lock = threading.Lock()
    stats = {"done": 0, "correct": 0, "errors": 0}

    with open(output_path, "a", encoding="utf-8") as out_f:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    process_item, item, host, model, api_key,
                    max_output_tokens, delay
                ): item
                for item in pending
            }

            for future in as_completed(futures):
                result = future.result()

                with write_lock:
                    stats["done"] += 1
                    if result["prediction"] in ("API_ERROR", "PARSE_ERROR"):
                        stats["errors"] += 1
                    elif result["correct"]:
                        stats["correct"] += 1
                    done_n    = stats["done"]
                    correct_n = stats["correct"]
                    errors_n  = stats["errors"]

                    out_f.write(json.dumps(result, ensure_ascii=False) + "\n")
                    out_f.flush()

                processed = done_n - errors_n
                acc = correct_n / processed if processed > 0 else 0.0
                mark = "✓" if result["correct"] else (
                    "!" if result["prediction"] in ("API_ERROR", "PARSE_ERROR") else "✗"
                )
                with print_lock:
                    print(f"  [{done_n:>5}/{total}] {result['pair_id']} "
                          f"({result['code_type'][:4]}) "
                          f"gt={result['ground_truth'][:4]} "
                          f"pred={result['prediction'][:4]} {mark}  "
                          f"acc={acc:.1%}")

    processed = stats["done"] - stats["errors"]
    final_acc = stats["correct"] / processed if processed > 0 else 0.0
    print(f"\nDone. {stats['correct']}/{processed} correct  ({final_acc:.1%})  "
          f"| {stats['errors']} API/parse errors")
    print(f"Results → {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Zero-shot vulnerability detection via a local OpenAI Responses API."
    )
    parser.add_argument("--model", required=True,
                        help='Model ID served by the local endpoint, e.g. "gpt-oss"')
    parser.add_argument("--host", default="http://localhost:8000",
                        help="Base URL of the local API server "
                             "(default: http://localhost:8000)")
    parser.add_argument("--api-key", default="EMPTY", dest="api_key",
                        help='Bearer token for the local server (default: "EMPTY")')

    dataset_group = parser.add_mutually_exclusive_group(required=True)
    dataset_group.add_argument(
        "--dataset", choices=AVAILABLE_DATASETS,
        help=f"Dataset to evaluate. Available: {', '.join(sorted(AVAILABLE_DATASETS))}",
    )
    dataset_group.add_argument(
        "--all", action="store_true", dest="all_datasets",
        help="Run inference on all available datasets sequentially.",
    )
    dataset_group.add_argument(
        "--test", action="store_true", dest="test_mode",
        help="Send a single minimal request and print the raw API response.",
    )

    parser.add_argument("--output", default=None,
                        help="Output JSONL path (default: results/{model}/{dataset}_{ts}.jsonl).")
    parser.add_argument("--max-output-tokens", type=int, default=6000, dest="max_output_tokens",
                        help="Max tokens for model response (default: 6000)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Seconds to wait between calls per worker (default: 0.1)")
    parser.add_argument("--max-samples", type=int, default=None,
                        help="Cap total evaluation items (for quick smoke tests)")
    parser.add_argument("--workers", type=int, default=1,
                        help="Number of parallel request threads (default: 1)")
    parser.add_argument("--resume", action="store_true",
                        help="Skip already-processed items in an existing output file")

    args = parser.parse_args()

    if args.test_mode:
        print(f"Testing {args.model} @ {args.host}")
        try:
            raw = call_local(
                args.host, args.model,
                "Reply with just the word: OK",
                args.api_key,
                max_output_tokens=500,
                timeout=60,
            )
            print(f"Response text: {raw!r}")
        except Exception as e:
            print(f"Error: {type(e).__name__}: {e}")
        return

    model_slug = args.model.replace("/", "__").replace(":", "-")
    datasets = sorted(AVAILABLE_DATASETS) if args.all_datasets else [args.dataset]

    for dataset in datasets:
        if args.all_datasets or not args.output:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = RESULTS_DIR / model_slug / f"{dataset}_{ts}.jsonl"
        else:
            output_path = Path(args.output)

        output_path.parent.mkdir(parents=True, exist_ok=True)

        if args.all_datasets:
            print(f"\n{'='*60}")
            print(f"  Dataset {datasets.index(dataset)+1}/{len(datasets)}: {dataset}")
            print(f"{'='*60}")

        run_inference(
            host=args.host,
            model=args.model,
            dataset=dataset,
            api_key=args.api_key,
            output_path=output_path,
            max_output_tokens=args.max_output_tokens,
            delay=args.delay,
            max_samples=args.max_samples,
            resume=args.resume,
            workers=args.workers,
        )


if __name__ == "__main__":
    main()
