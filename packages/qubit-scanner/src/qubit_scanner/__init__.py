"""qubit-scanner — cryptographic asset discovery.

Phase 1: source-code scanning via tree-sitter AST + a data-driven ``qubit-rule/v1`` catalog.
Config / network / cert scanners land in later phases (see docs/design/01).
"""

from __future__ import annotations

from .api import scan_paths
from .catalog import RuleCatalog
from .code import CodeScanner
from .models import Detection, ScanError, ScanResult, ScanStats
from .normalize import normalize

__version__ = "0.1.0"

__all__ = [
    "CodeScanner",
    "Detection",
    "RuleCatalog",
    "ScanError",
    "ScanResult",
    "ScanStats",
    "__version__",
    "normalize",
    "scan_paths",
]
