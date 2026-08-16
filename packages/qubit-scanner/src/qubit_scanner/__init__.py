"""qubit-scanner — cryptographic asset discovery.

Phase 1: source-code scanning via tree-sitter AST + a data-driven ``qubit-rule/v1`` catalog.
Config / network / cert scanners land in later phases (see docs/design/01).
"""

from __future__ import annotations

from .api import SCANNER_NAMES, ScanAuthorizationError, scan_network, scan_paths, scan_vault
from .catalog import RuleCatalog
from .code import CodeScanner
from .models import Detection, ScanError, ScanResult, ScanStats
from .normalize import normalize

__version__ = "0.1.0"

__all__ = [
    "SCANNER_NAMES",
    "CodeScanner",
    "Detection",
    "RuleCatalog",
    "ScanAuthorizationError",
    "ScanError",
    "ScanResult",
    "ScanStats",
    "__version__",
    "normalize",
    "scan_network",
    "scan_paths",
    "scan_vault",
]
