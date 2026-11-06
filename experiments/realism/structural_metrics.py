# utils/structural_metrics.py
import os
import subprocess
import sys
from pathlib import Path
from collections import Counter
from tree_sitter import Language, Parser

class StructuralMetricsExtractor:
    """
    Extracts structural code metrics using the tree-sitter parser.
    This version is fully compatible with modern tree-sitter APIs.
    """
    def __init__(self, grammar_dir='tree-sitter-grammars'):
        script_dir = Path(__file__).parent.resolve()
        self.grammar_dir = script_dir / grammar_dir
        
        try:
            from tree_sitter_cpp import language as cpp_language_id
        except ImportError:
            print("tree-sitter-cpp package not found. Performing one-time setup...")
            self._setup_grammars()
            from tree_sitter_cpp import language as cpp_language_id

        self.CPP_LANGUAGE = Language(cpp_language_id())
        self.parser = Parser()
        self.parser.language = self.CPP_LANGUAGE

    def _run_command(self, command, error_message, cwd=None):
        """Helper to run a subprocess command with clear error reporting."""
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, cwd=cwd)
        except FileNotFoundError:
            compiler = command[0]
            print(f"\n--- COMMAND '{compiler}' NOT FOUND ---")
            raise
        except subprocess.CalledProcessError as e:
            print(f"\n--- {error_message} FAILED ---")
            print("Command:", " ".join(map(str, command)))
            print("STDERR:", e.stderr)
            raise

    def _setup_grammars(self):
        """Clones and installs the C++ grammar package."""
        cpp_grammar_path = self.grammar_dir / 'tree-sitter-cpp'

        if not cpp_grammar_path.exists():
            print("Cloning C++ grammar repository...")
            self._run_command(
                ['git', 'clone', 'https://github.com/tree-sitter/tree-sitter-cpp.git', str(cpp_grammar_path)],
                "GIT CLONE"
            )
        
        print("Installing C++ grammar package via pip...")
        self._run_command(
            [sys.executable, '-m', 'pip', 'install', str(cpp_grammar_path)],
            "PIP INSTALL"
        )
        print("Setup complete.")

    def extract_metrics(self, code: str) -> dict:
        if not isinstance(code, str) or not code.strip(): return {}
        tree = self.parser.parse(bytes(code, "utf8"))
        node_counts = Counter()
        max_depth = 0
        def traverse(node, depth=0):
            nonlocal max_depth
            if node.is_named:
                node_counts[node.type] += 1
                max_depth = max(max_depth, depth)
            for child in node.children: traverse(child, depth + 1)
        traverse(tree.root_node)
        flat_metrics = {f"cst_{k}": v for k, v in node_counts.items()}
        flat_metrics['cst_max_depth'] = max_depth
        if tree.root_node.has_error: flat_metrics['cst_has_error'] = 1
        return flat_metrics
