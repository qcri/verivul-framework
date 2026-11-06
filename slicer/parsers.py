"""
Tree-sitter parser setup for C and C++.
"""
from functools import lru_cache
from tree_sitter import Language, Parser


@lru_cache(maxsize=None)
def _c_lang() -> Language:
    import tree_sitter_c as tsc
    return Language(tsc.language())


@lru_cache(maxsize=None)
def _cpp_lang() -> Language:
    import tree_sitter_cpp as tscpp
    return Language(tscpp.language())


def get_parser(language: str = "c") -> Parser:
    """Return a tree-sitter Parser for 'c' or 'cpp'."""
    lang = language.lower()
    if lang in ("c++", "cpp"):
        return Parser(_cpp_lang())
    return Parser(_c_lang())
