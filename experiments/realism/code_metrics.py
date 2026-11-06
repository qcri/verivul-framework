# utils/code_metrics.py
import re
import math
from collections import Counter
import numpy as np
from typing import Dict, List, Any

class CppCodeMetricsExtractor:
    """
    Extracts a focused set of code metrics for C/C++ to evaluate semantic realism.
    This version prioritizes discriminative metrics and produces a flat dictionary.
    """
    def __init__(self):
        self.c_keywords = {
            'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do',
            'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if',
            'int', 'long', 'register', 'return', 'short', 'signed', 'sizeof',
            'static', 'struct', 'switch', 'typedef', 'union', 'unsigned', 'void',
            'volatile', 'while', 'class', 'namespace', 'template', 'try', 'catch', 
            'throw', 'new', 'delete', 'virtual', 'override', 'final', 'constexpr',
            'public', 'private', 'protected', 'using', 'friend', 'inline'
        }
        # A simplified but effective regex for operators
        self.operator_pattern = re.compile(r'\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^<>=!~?:]')

    def extract_metrics(self, code: str) -> Dict[str, Any]:
        """
        Extracts a curated set of metrics from a C/C++ code string.

        Args:
            code (str): The source code to analyze.

        Returns:
            A flat dictionary of calculated metrics.
        """
        if not isinstance(code, str) or not code.strip():
            return {}

        try:
            # Pre-processing: remove comments and string literals to not interfere with analysis
            code_no_comments = re.sub(r'//.*?$|/\*.*?\*/', '', code, flags=re.MULTILINE | re.DOTALL)
            code_no_strings = re.sub(r'"(\\.|[^"\\])*"', '""', code_no_comments)
            
            lines = code.split('\n')
            non_empty_lines = [line for line in lines if line.strip()]
            
            # Tokenization
            tokens = re.findall(r'\b\w+\b|[^\s\w]', code_no_strings)
            identifiers = [t for t in tokens if t.isidentifier() and t not in self.c_keywords]
            
            # --- Core Metric Calculations ---
            halstead_metrics = self._calculate_halstead(code_no_strings, identifiers)
            naming_metrics = self._analyze_naming(identifiers)
            
            metrics = {
                'loc': len(non_empty_lines),
                'cyclomatic_complexity': self._calculate_cyclomatic_complexity(code_no_strings),
                'max_nesting_depth': self._calculate_max_nesting_depth(code_no_strings),
                'num_functions': len(re.findall(r'\b\w+\s+\w+\s*\([^)]*\)\s*\{', code_no_strings)),
                'num_pointers': code_no_strings.count('*'),
                'num_macros': len(re.findall(r'^\s*#\s*define', code, flags=re.MULTILINE)),
                'control_flow_density': self._calculate_control_flow_density(tokens),
                'unique_tokens': len(set(tokens)),
            }
            
            metrics.update(halstead_metrics)
            metrics.update(naming_metrics)
            
            return metrics
        except Exception:
            # Return empty dict on any parsing failure
            return {}

    def _calculate_cyclomatic_complexity(self, code: str) -> int:
        """Calculates cyclomatic complexity."""
        decision_points = [
            'if', 'while', 'for', 'case', 'catch', '&&', '||', '?'
        ]
        complexity = 1
        for point in decision_points:
            complexity += code.count(point)
        return complexity

    def _calculate_max_nesting_depth(self, code: str) -> int:
        """Calculates the maximum nesting depth of curly braces."""
        max_depth = 0
        current_depth = 0
        for char in code:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)
        return max_depth
        
    def _calculate_halstead(self, code: str, identifiers: List[str]) -> Dict[str, float]:
        """Calculates Halstead complexity metrics."""
        operators = self.operator_pattern.findall(code)
        operands = identifiers + re.findall(r'\b\d+\b', code) # identifiers and numeric literals

        n1 = len(set(operators)) # Unique operators
        n2 = len(set(operands))  # Unique operands
        N1 = len(operators)     # Total operators
        N2 = len(operands)      # Total operands

        if n1 == 0 or n2 == 0:
            return {'halstead_volume': 0, 'halstead_difficulty': 0, 'halstead_effort': 0}

        vocabulary = n1 + n2
        length = N1 + N2
        
        volume = length * math.log2(vocabulary) if vocabulary > 1 else 0
        difficulty = (n1 / 2) * (N2 / n2)
        effort = volume * difficulty
        
        return {
            'halstead_volume': volume,
            'halstead_difficulty': difficulty,
            'halstead_effort': effort,
        }

    def _analyze_naming(self, identifiers: List[str]) -> Dict[str, float]:
        """Analyzes identifier naming conventions and entropy."""
        if not identifiers:
            return {'naming_len_mean': 0, 'naming_len_std': 0, 'naming_entropy': 0}
        
        lengths = [len(i) for i in identifiers]
        
        # Calculate entropy
        counts = Counter(identifiers)
        total = len(identifiers)
        entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
        
        return {
            'naming_len_mean': np.mean(lengths),
            'naming_len_std': np.std(lengths),
            'naming_entropy': entropy
        }

    def _calculate_control_flow_density(self, tokens: List[str]) -> float:
        """Calculates the density of control flow keywords."""
        if not tokens:
            return 0
        control_flow_keywords = {'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'goto', 'break', 'continue', 'return'}
        cf_count = sum(1 for token in tokens if token in control_flow_keywords)
        return cf_count / len(tokens)