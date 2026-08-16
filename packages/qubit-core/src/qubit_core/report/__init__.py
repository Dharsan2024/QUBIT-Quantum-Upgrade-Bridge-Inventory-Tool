"""Report outputs, one per audience — see each module for why it exists rather than the others.

* ``sarif``  — SARIF 2.1.0 (OASIS). The finding on the line of code, in the analyst's existing
  review surface: GitHub code-scanning alerts, VS Code, Azure DevOps.
* ``pdf``    — the paginated document a compliance submission or leadership review attaches, with
  posture stated against the EO 14412 / OMB M-26-15 deadlines.

The machine inventory those directives actually name is the CycloneDX 1.7 CBOM, which lives in
``qubit_core.cbom`` and predates this package.

``build_pdf_report`` is re-exported lazily: reportlab is an optional extra (``qubit-core[pdf]``),
and importing this package must not fail — or cost anything — when only SARIF is wanted.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .sarif import SARIF_SCHEMA, SARIF_VERSION, export_sarif, validate_sarif_structure

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .pdf import build_pdf_report

__all__ = [
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "build_pdf_report",
    "export_sarif",
    "validate_sarif_structure",
]


def __getattr__(name: str) -> Any:
    if name == "build_pdf_report":
        from .pdf import build_pdf_report

        return build_pdf_report
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
