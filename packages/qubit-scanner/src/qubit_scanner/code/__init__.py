"""Source-code scanning: language detection, AST parsing, rule execution, semantic resolution."""

from .languages import language_for
from .scanner import CodeScanner

__all__ = ["CodeScanner", "language_for"]
