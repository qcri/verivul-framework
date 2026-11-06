"""
inference.py — Zero-shot vulnerability detection via OpenRouter.

For each sample in a dataset's Samples file the script evaluates both
sides of the pair independently:
  - vulnerable_code  →  ground truth VULNERABLE
  - patched_code     →  ground truth SAFE

The model is prompted to analyse the code and respond with a JSON object:
  {
    "analysis": "<short paragraph>",
    "vulnerability_status": "VULNERABLE" | "SAFE",
    "trigger_line": <1-indexed line number or null>,
    "trigger_code": "<verbatim source line or null>"
  }

The prompt does not ask for a CWE, so the "cwe_predicted" output field is
always null.

Results are written incrementally to a JSONL file so the run can be
resumed after interruption.

Multi-threading
---------------
  Use --workers N to send N requests in parallel. Each worker thread sleeps
  --delay seconds between its own calls, so effective throughput is roughly
  N / delay requests per second. The output file and progress counters are
  protected by locks; results are written in completion order (not submission
  order), which is fine for JSONL.

Usage
-----
  # required: OPENROUTER_API_KEY in environment (or .env file)
  python inference.py --model "meta-llama/llama-3.3-70b-instruct" \
                      --dataset VeriVul

  python inference.py --model "meta-llama/llama-3.3-70b-instruct" \
                      --dataset TitanVul --workers 8 --delay 0.2

  python inference.py --help
"""

import argparse
import json
import os
import re
import threading
import time
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
# Prompt  (loaded from prompts/vulnerability_detection.txt at startup)
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
# OpenRouter client
# ---------------------------------------------------------------------------
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


def call_openrouter(
    model: str,
    messages: list[dict],
    api_key: str,
    temperature: float = 0.0,
    max_tokens: int = 512,
    timeout: int = 60,
    no_thinking: bool = False,
) -> str:
    """Call OpenRouter and return the raw assistant message content."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/VeriVul",
        "X-Title": "VeriVul",
    }
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if no_thinking:
        payload["reasoning"] = {"enabled": False}
    resp = requests.post(OPENROUTER_URL, headers=headers,
                         json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    # OpenRouter sometimes returns 200 OK with {"error": {...}} instead of a proper error code
    if "error" in data:
        raise requests.HTTPError(
            f"OpenRouter error: {data['error']}", response=resp
        )
    return data["choices"][0]["message"]["content"]


def parse_response(raw: str) -> dict:
    """Extract the JSON object from the model response."""
    # Strip markdown code fences if the model wrapped the JSON
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Fallback: try to find the first {...} block
        m = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
    return {"analysis": raw, "vulnerability_status": "PARSE_ERROR", "cwe": None}


# ---------------------------------------------------------------------------
# Per-item worker  (called from thread pool)
# ---------------------------------------------------------------------------
def process_item(
    item: dict,
    model: str,
    api_key: str,
    temperature: float,
    max_tokens: int,
    delay: float,
    no_thinking: bool = False,
) -> dict:
    """Run inference for a single evaluation item and return the result dict."""
    import sys, traceback as _tb
    _log = open(ROOT / "debug_errors.log", "a")
    def _err(msg):
        print(msg, flush=True)
        _log.write(msg + "\n"); _log.flush()

    try:
        messages = [{"role": "user", "content": build_prompt(item["code"])}]
    except Exception as exc:
        _err(f"  [{item['pair_id']}] build_prompt FAILED: {type(exc).__name__}: {exc}")
        _tb.print_exc(file=_log); _log.flush()
        _log.close()
        return {"pair_id": item["pair_id"], "source": item["source"],
                "primary_cwe": item["primary_cwe"], "language": item["language"],
                "code_type": item["code_type"], "ground_truth": item["ground_truth"],
                "is_real_pair": item["is_real_pair"], "prediction": "API_ERROR",
                "correct": False, "analysis": str(exc), "cwe_predicted": None,
                "trigger_line": None, "trigger_code": None, "raw_response": None}

    raw = None
    for attempt in range(1, 4):
        _err(f"  [{item['pair_id']}] attempt {attempt}/3 ...")
        try:
            raw = call_openrouter(
                model, messages, api_key,
                temperature=temperature,
                max_tokens=max_tokens,
                no_thinking=no_thinking,
            )
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
            _tb.print_exc(file=_log); _log.flush()
            time.sleep(2 * attempt)

    _log.close()
    if raw is None:
        parsed = {"analysis": None, "vulnerability_status": "API_ERROR",
                  "cwe": None, "trigger_line": None}
        print(f"  [{item['pair_id']}] All retries exhausted — recorded as API_ERROR",
              flush=True)
    else:
        parsed = parse_response(raw)

    prediction = parsed.get("vulnerability_status", "").upper()
    is_correct = prediction == item["ground_truth"] and prediction in ("VULNERABLE", "SAFE")

    # Normalise trigger_line: accept int or int-like string; discard anything else
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


# ---------------------------------------------------------------------------
# Inference loop
# ---------------------------------------------------------------------------
def run_inference(
    model: str,
    dataset: str,
    api_key: str,
    output_path: Path,
    temperature: float,
    max_tokens: int,
    delay: float,
    max_samples: int | None,
    resume: bool,
    workers: int,
    no_thinking: bool = False,
):
    samples_file = SAMPLES_DIR / f"{dataset}_samples.json"
    with open(samples_file, encoding="utf-8") as f:
        samples = json.load(f)

    # Each sample produces two evaluation items (vulnerable + patched)
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

    # Resume: skip already-processed pair_id+code_type combinations
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
    print(f"Model   : {model}")
    print(f"Workers : {workers}  |  delay: {delay}s per worker")
    print(f"Output  : {output_path}\n")

    write_lock  = threading.Lock()
    print_lock  = threading.Lock()
    stats = {"done": 0, "correct": 0, "errors": 0}

    with open(output_path, "a", encoding="utf-8") as out_f:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    process_item, item, model, api_key,
                    temperature, max_tokens, delay, no_thinking
                ): item
                for item in pending
            }

            for future in as_completed(futures):
                result = future.result()

                # Update shared stats
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
        description="Zero-shot vulnerability detection via OpenRouter."
    )
    parser.add_argument(
        "--model", required=True,
        help='OpenRouter model ID, e.g. "meta-llama/llama-3.3-70b-instruct"',
    )
    dataset_group = parser.add_mutually_exclusive_group(required=True)
    dataset_group.add_argument(
        "--dataset",
        choices=AVAILABLE_DATASETS,
        help=f"Dataset to evaluate. Available: {', '.join(sorted(AVAILABLE_DATASETS))}",
    )
    dataset_group.add_argument(
        "--all", action="store_true", dest="all_datasets",
        help="Run inference on all available datasets sequentially.",
    )
    dataset_group.add_argument(
        "--test", action="store_true", dest="test_mode",
        help="Send a single minimal request and print the raw API response. "
             "Use this to verify a model ID works before a full run.",
    )
    parser.add_argument(
        "--output", default=None,
        help="Output JSONL file path (default: results/{model_slug}/{dataset}_{ts}.jsonl). "
             "Ignored when --all is used.",
    )
    parser.add_argument(
        "--temperature", type=float, default=0.0,
        help="Sampling temperature (default: 0.0 for greedy / deterministic)",
    )
    parser.add_argument(
        "--max-tokens", type=int, default=1000,
        help="Max tokens for model response (default: 1000)",
    )
    parser.add_argument(
        "--delay", type=float, default=0.5,
        help="Seconds to wait between API calls (default: 0.5)",
    )
    parser.add_argument(
        "--max-samples", type=int, default=None,
        help="Cap total evaluation items (for quick smoke tests)",
    )
    parser.add_argument(
        "--workers", type=int, default=1,
        help="Number of parallel API threads (default: 1). Each thread sleeps "
             "--delay seconds between its own calls, so effective throughput is "
             "~workers/delay req/s.",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Skip already-processed items in an existing output file",
    )
    parser.add_argument(
        "--no-thinking", action="store_true", dest="no_thinking",
        help="Disable thinking/reasoning for models that support it (e.g. Gemini 2.5 Pro). "
             "Passes reasoning={enabled:false} to OpenRouter.",
    )
    args = parser.parse_args()

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise SystemExit("OPENROUTER_API_KEY not set. Export it or add it to a .env file.")

    if args.test_mode:
        print(f"Testing model: {args.model}")
        try:
            resp = requests.post(
                OPENROUTER_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={"model": args.model, "messages": [{"role": "user", "content": "Hi"}],
                      "max_tokens": 16},
                timeout=30,
            )
            print(f"HTTP status : {resp.status_code}")
            print(f"Response    : {resp.text[:1000]}")
        except Exception as e:
            print(f"Error: {e}")
        return

    model_slug = args.model.replace("/", "__").replace(":", "-")
    datasets = sorted(AVAILABLE_DATASETS) if args.all_datasets else [args.dataset]

    for dataset in datasets:
        if args.all_datasets:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = RESULTS_DIR / model_slug / f"{dataset}_{ts}.jsonl"
        elif args.output:
            output_path = Path(args.output)
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = RESULTS_DIR / model_slug / f"{dataset}_{ts}.jsonl"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        if args.all_datasets:
            print(f"\n{'='*60}")
            print(f"  Dataset {datasets.index(dataset)+1}/{len(datasets)}: {dataset}")
            print(f"{'='*60}")

        run_inference(
            model=args.model,
            dataset=dataset,
            api_key=api_key,
            output_path=output_path,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            delay=args.delay,
            max_samples=args.max_samples,
            resume=args.resume,
            workers=args.workers,
            no_thinking=args.no_thinking,
        )


if __name__ == "__main__":
    main()
