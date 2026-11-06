"""
inference_deepseek.py — Zero-shot vulnerability detection via DeepSeek API.

Uses the official OpenAI SDK pointed at DeepSeek's base URL, exactly as shown
in DeepSeek's API documentation.

  Model    : deepseek-v4-pro  (thinking is always disabled)
  Endpoint : https://api.deepseek.com
  Auth     : DEEPSEEK_API_KEY environment variable (or --api-key flag)

Usage
-----
  # required: DEEPSEEK_API_KEY in environment (or .env file)
  python inference_deepseek.py --dataset VeriVul

  python inference_deepseek.py --all --workers 4

  python inference_deepseek.py --test
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

from dotenv import load_dotenv
from openai import OpenAI, APIStatusError, APIConnectionError, RateLimitError

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

DEFAULT_MODEL = "deepseek-v4-pro"

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
# DeepSeek client
# ---------------------------------------------------------------------------
def make_client(api_key: str) -> OpenAI:
    return OpenAI(api_key=api_key, base_url="https://api.deepseek.com")


def call_deepseek(
    client: OpenAI,
    model: str,
    messages: list[dict],
    max_tokens: int = 1000,
    temperature: float = 0.0,
) -> str:
    """Call DeepSeek and return the assistant message content."""
    kwargs = dict(
        model=model,
        messages=messages,
        max_tokens=max_tokens,
        temperature=temperature,
        stream=False,
    )
    # Thinking is always disabled; all reported deepseek-v4-pro results use this setting.
    kwargs["extra_body"] = {"thinking": {"type": "disabled"}}

    resp = client.chat.completions.create(**kwargs)
    return resp.choices[0].message.content


def parse_response(raw: str) -> dict:
    """Extract the JSON object from the model response."""
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
    return {"analysis": raw, "vulnerability_status": "PARSE_ERROR",
            "cwe": None, "trigger_line": None, "trigger_code": None}


# ---------------------------------------------------------------------------
# Per-item worker
# ---------------------------------------------------------------------------
def process_item(
    item: dict,
    client: OpenAI,
    model: str,
    temperature: float,
    max_tokens: int,
    delay: float,
) -> dict:
    """Run inference for a single evaluation item and return the result dict."""
    _log = open(ROOT / "debug_errors_deepseek.log", "a")

    def _err(msg: str):
        print(msg, flush=True)
        _log.write(msg + "\n")
        _log.flush()

    try:
        messages = [
            {"role": "system", "content": "You are a security expert specialising in static code analysis."},
            {"role": "user",   "content": build_prompt(item["code"])},
        ]
    except Exception as exc:
        _err(f"  [{item['pair_id']}] build_prompt FAILED: {type(exc).__name__}: {exc}")
        _tb.print_exc(file=_log)
        _log.close()
        return _error_result(item, str(exc))

    raw = None
    for attempt in range(1, 4):
        try:
            raw = call_deepseek(client, model, messages,
                                max_tokens=max_tokens,
                                temperature=temperature)
            break
        except RateLimitError:
            wait = 10 * attempt
            _err(f"  [{item['pair_id']}] Rate limited — waiting {wait}s (attempt {attempt}/3)")
            time.sleep(wait)
        except APIStatusError as e:
            _err(f"  [{item['pair_id']}] HTTP {e.status_code} (attempt {attempt}/3): {e.message}")
            time.sleep(2 * attempt)
        except APIConnectionError as e:
            _err(f"  [{item['pair_id']}] Connection error (attempt {attempt}/3): {e}")
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
):
    client = make_client(api_key)

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
    print(f"Dataset  : {dataset}  ({len(samples)} pairs → {len(items)} items, {total} pending)")
    print(f"Model    : {model}")
    print(f"Thinking : disabled")
    print(f"Workers  : {workers}  |  delay: {delay}s per worker")
    print(f"Output   : {output_path}\n")

    write_lock = threading.Lock()
    print_lock = threading.Lock()
    stats = {"done": 0, "correct": 0, "errors": 0}

    with open(output_path, "a", encoding="utf-8") as out_f:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    process_item, item, client, model,
                    temperature, max_tokens, delay
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
        description="Zero-shot vulnerability detection via DeepSeek API (deepseek-v4-pro)."
    )
    parser.add_argument(
        "--model", default=DEFAULT_MODEL,
        help=f'DeepSeek model ID (default: "{DEFAULT_MODEL}")',
    )
    parser.add_argument(
        "--api-key", default=None, dest="api_key",
        help="DeepSeek API key. Falls back to DEEPSEEK_API_KEY env var.",
    )

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
        help="Send a single minimal request to verify the API key and model.",
    )

    parser.add_argument("--output", default=None,
                        help="Output JSONL path (default: results/{model}/{dataset}_{ts}.jsonl).")
    parser.add_argument("--temperature", type=float, default=0.0,
                        help="Sampling temperature (default: 0.0)")
    parser.add_argument("--max-tokens", type=int, default=1000, dest="max_tokens",
                        help="Max tokens for model response (default: 1000)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Seconds to wait between calls per worker (default: 0.5)")
    parser.add_argument("--max-samples", type=int, default=None,
                        help="Cap total evaluation items (for quick smoke tests)")
    parser.add_argument("--workers", type=int, default=1,
                        help="Number of parallel request threads (default: 1)")
    parser.add_argument("--resume", action="store_true",
                        help="Skip already-processed items in an existing output file")

    args = parser.parse_args()

    api_key = args.api_key or os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        raise SystemExit(
            "DeepSeek API key not set. Export DEEPSEEK_API_KEY or pass --api-key."
        )

    if args.test_mode:
        print(f"Testing model: {args.model}")
        client = make_client(api_key)
        try:
            content = call_deepseek(
                client, args.model,
                [{"role": "user", "content": "Reply with just: OK"}],
                max_tokens=32,
            )
            print(f"Response: {content}")
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
        )


if __name__ == "__main__":
    main()
