import argparse
import json
import re
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any
from tqdm import tqdm

# Comprehensive list of keywords to remove entirely from the code to prevent
# data leakage to a model. Matching is case-insensitive.
LEAKAGE_KEYWORDS = [
    # Vulnerability status descriptors
    "vulnerable", "vulnerability", "vulnerabilities", "exploit", "exploitable",
    "attack", "malicious", "threat", "cve", "issue", "problem", "flaw", "danger", "cwe",
    # Safety status descriptors
    "safe", "unsafe", "secure", "insecure", "security", "benign",
    # Memory corruption types (often used in comments)
    "overflow", "underflow", "heap-overflow", "stack-overflow", "buffer-overflow",
    "heap_overflow", "stack_overflow", "buffer_overflow",
    "uaf", "use-after-free", "double-free", "memory-corruption", "corrupt", "corruption",
    "null-pointer", "null-dereference", "dangling-pointer",
    # Code analysis status descriptors
    # Fix/Patch status descriptors
    "fix", "patch", "remediate", "remediation", "fixed", "patched", "corrected",
    # Sanitization status descriptors
    "sanitized", "unsanitized", "clean", "dirty", "validation"
]

class CodeCleaner:
    """
    Orchestrates the cleaning process for C/C++ code snippets.
    Designed to be thread-safe for concurrent processing of entries.
    """

    def __init__(self):
        # Compile leakage keywords into a single regex pattern for efficiency.
        leakage_pattern = "|".join(rf"\b{re.escape(kw)}\b" for kw in LEAKAGE_KEYWORDS)
        self.leakage_regex = re.compile(leakage_pattern, re.IGNORECASE)

    def remove_c_comments(self, code_text: str) -> str:
        """Removes C/C++ style comments (both // and /* */) from a code string."""
        # Rule 1: Remove multi-line comments /* ... */ first.
        code_without_multiline = re.sub(r"/\*.*?\*/", "", code_text, flags=re.DOTALL)

        # Rule 2 & 3: Process single-line comments line by line.
        processed_lines = []
        for line in code_without_multiline.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("//"):
                processed_lines.append("")
            else:
                processed_lines.append(re.sub(r"//.*", "", line))

        return "\n".join(processed_lines)

    def process_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Cleans a single entry from the dataset."""
        language = entry.get("language", "").lower()
        # Apply cleaning only to C or C++ code snippets.
        if language not in ["c", "cpp", "c++"]:
            return entry

        code = entry.get("code", "")
        esbmc_log = entry.get("esbmc_log", "")

        # Step 1: Remove comments from the code itself.
        cleaned_code = self.remove_c_comments(code)

        # Step 2: Sanitize leakage keywords from the code.
        cleaned_code = self.leakage_regex.sub("", cleaned_code)

        entry["code"] = cleaned_code

        return entry

def load_jsonl_dataset(filepath: str) -> List[Dict[str, Any]]:
    """Loads a JSONL dataset from a file."""
    data = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    print(f"Warning: Skipping malformed JSON line: {line[:100]}...")
    except FileNotFoundError:
        print(f"Error: Input file not found at {filepath}")
        return []
    return data


def save_jsonl_dataset(data: List[Dict[str, Any]], filepath: str):
    """Saves the processed data to a new JSONL file."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            for entry in data:
                f.write(json.dumps(entry) + "\n")
    except IOError as e:
        print(f"Error writing to output file {filepath}: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Clean synthetic C/C++ code snippets using multithreading."
    )
    parser.add_argument(
        "-i",
        "--input",
        type=str,
        required=True,
        help="Path to the input JSONL file.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        required=True,
        help="Path to save the cleaned output JSONL file.",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=None,
        help="Number of worker threads (default: system CPU count).",
    )
    args = parser.parse_args()

    # Determine number of workers
    num_workers = args.workers or os.cpu_count() or 4

    print(f"Loading dataset from {args.input}...")
    dataset = load_jsonl_dataset(args.input)

    if not dataset:
        print("No data loaded. Exiting.")
        return

    cleaner = CodeCleaner()
    total_entries = len(dataset)
    print(f"Processing {total_entries} entries using up to {num_workers} workers...")

    cleaned_dataset = []
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        results_iterator = executor.map(cleaner.process_entry, dataset)
        cleaned_dataset = list(
            tqdm(results_iterator, total=total_entries, desc="Cleaning snippets")
        )

    print(f"\nSaving cleaned dataset to {args.output}...")
    save_jsonl_dataset(cleaned_dataset, args.output)
    print("Cleaning complete.")


if __name__ == "__main__":
    main()
