"""PDF report generation — the artifact a compliance submission or a leadership review attaches.

Why a PDF at all, when the machine-readable formats already exist: US Executive Order 14412
("Securing the Nation Against Advanced Cryptographic Attacks", June 2026) and OMB M-26-15 make
cryptographic inventory a *reporting* obligation, not just an engineering one. Agencies and covered
contractors have to show an inventory and a migration posture against fixed dates — high-value
assets on post-quantum key establishment by 2030-12-31 — and the thing that gets filed, signed off
and archived is a paginated document, not a JSON file.

So the three outputs are deliberately different jobs and none replaces another:

* **CBOM** (CycloneDX 1.7 / ECMA-424, `qubit_core.cbom`) — the machine inventory the regulation
  actually names, for supply-chain tooling and a central agency CBOM.
* **SARIF** (`qubit_core.report.sarif`) — the finding on the line of code, inside the analyst's
  existing review surface (GitHub code scanning, VS Code).
* **PDF** (this module) — the human narrative: what was found, how urgent, against which deadline.

`reportlab` is imported lazily inside the one function that needs it. It is pure Python with no
system libraries, which is why it was chosen over WeasyPrint (Cairo/Pango) — QUBIT runs fully
offline and a report generator must not be the thing that drags in native dependencies.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from qubit_core.schemas import CryptoAsset

if TYPE_CHECKING:  # pragma: no cover - typing only
    pass

# Federal dates the report measures posture against, so the document says WHY something is urgent
# instead of only how bad it scores. Sources recorded in docs/design/02-risk-engine.md.
_CNSA2_FULL_TRANSITION = date(2035, 1, 1)
_FEDERAL_HVA_DEADLINE = date(2030, 12, 31)


def _fmt_years(value: float) -> str:
    return f"{value:+.1f} yr"


def _summarize(assets: list[CryptoAsset]) -> dict[str, Any]:
    vulnerable = [a for a in assets if a.quantum_vulnerable.vulnerable]
    shor = [a for a in vulnerable if a.quantum_vulnerable.attack.value == "shor"]
    scored = [a for a in assets if a.risk is not None]
    past_due = [a for a in scored if a.risk is not None and a.risk.mosca_margin_years < 0]
    return {
        "total": len(assets),
        "vulnerable": len(vulnerable),
        "shor": len(shor),
        "safe": len(assets) - len(vulnerable),
        "scored": len(scored),
        "past_due": len(past_due),
        "by_algorithm": Counter(a.algorithm for a in vulnerable).most_common(),
        "by_usage": Counter(a.usage_context.value for a in vulnerable).most_common(),
        "by_source": Counter(a.source_scanner.value for a in vulnerable).most_common(),
    }


def build_pdf_report(
    assets: list[CryptoAsset],
    out_path: Path,
    *,
    title: str = "QUBIT Cryptographic Inventory & HNDL Risk Report",
    target: str = "",
    tool_version: str = "0.1.0",
    max_findings: int = 60,
) -> Path:
    """Render a paginated PDF report for ``assets`` to ``out_path``.

    Ordered the way a reader consumes it rather than the way the data is stored: the verdict first,
    then what drives it, then the itemized findings. ``max_findings`` caps the detail table so a
    100k-asset monorepo produces a usable document instead of a thousand pages — the CBOM is the
    complete record and the report says so explicitly rather than truncating silently.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - exercised by the missing-dependency test
        raise RuntimeError(
            "PDF reports need reportlab. Install it with:  uv sync --extra pdf   "
            "(or pip install 'qubit-core[pdf]')"
        ) from exc

    out_path.parent.mkdir(parents=True, exist_ok=True)
    summary = _summarize(assets)
    now = datetime.now(UTC)

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("QubitH1", parent=styles["Heading1"], fontSize=17, spaceAfter=4)
    h2 = ParagraphStyle("QubitH2", parent=styles["Heading2"], fontSize=12, spaceBefore=12)
    body = ParagraphStyle("QubitBody", parent=styles["BodyText"], fontSize=9, leading=13)
    small = ParagraphStyle(
        "QubitSmall", parent=body, fontSize=7.5, textColor=colors.HexColor("#555")
    )
    cell = ParagraphStyle("QubitCell", parent=body, fontSize=7.5, leading=10, alignment=TA_LEFT)

    def table(  # type: ignore[no-untyped-def]
        data: list[list[Any]], widths: list[float], *, align_right: frozenset[int] = frozenset()
    ):
        t = Table(data, colWidths=widths, repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12161f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c9ced8")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f9")]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for col in align_right:
            style.append(("ALIGN", (col, 1), (col, -1), "RIGHT"))
        t.setStyle(TableStyle(style))
        return t

    story: list[Any] = [
        Paragraph(title, h1),
        Paragraph(
            f"Generated {now:%Y-%m-%d %H:%M UTC} by QUBIT {tool_version}"
            + (f" · target: {target}" if target else ""),
            small,
        ),
        Spacer(1, 6 * mm),
    ]

    # ---------------------------------------------------------------- verdict
    days_to_hva = (_FEDERAL_HVA_DEADLINE - now.date()).days
    verdict = (
        f"<b>{summary['vulnerable']} of {summary['total']}</b> discovered cryptographic assets are "
        f"quantum-vulnerable, of which <b>{summary['shor']}</b> are broken outright by Shor's "
        f"algorithm. Shor-breakable key establishment is the urgent class: traffic protected by it "
        f"and recorded today can be decrypted retroactively once a cryptographically relevant "
        f"quantum computer exists, so its exposure has already begun."
    )
    if summary["past_due"]:
        verdict += (
            f" <b>{summary['past_due']}</b> asset(s) have a negative Mosca margin — the time "
            f"needed to migrate them plus the time their data must stay secret already exceeds the "
            f"projected arrival of that machine."
        )
    story += [
        Paragraph("Executive summary", h2),
        Paragraph(verdict, body),
        Spacer(1, 3 * mm),
        Paragraph(
            f"Regulatory context: US Executive Order 14412 and OMB M-26-15 require a cryptographic "
            f"inventory and a migration plan; high-value assets must reach post-quantum key "
            f"establishment by {_FEDERAL_HVA_DEADLINE:%Y-%m-%d} "
            f"({days_to_hva:,} days from this report), with full CNSA 2.0 transition by "
            f"{_CNSA2_FULL_TRANSITION:%Y}. The machine-readable inventory accompanying this "
            f"report is a CycloneDX 1.7 CBOM (ECMA-424), the format those directives name.",
            body,
        ),
        Spacer(1, 4 * mm),
        table(
            [
                ["Metric", "Value"],
                ["Assets discovered", str(summary["total"])],
                ["Quantum-vulnerable", str(summary["vulnerable"])],
                ["— broken by Shor (public key)", str(summary["shor"])],
                ["Quantum-safe", str(summary["safe"])],
                ["Risk-scored", str(summary["scored"])],
                ["Past due (negative Mosca margin)", str(summary["past_due"])],
            ],
            [95 * mm, 40 * mm],
            align_right=frozenset({1}),
        ),
    ]

    # ------------------------------------------------------------- breakdowns
    if summary["by_algorithm"]:
        story += [
            Paragraph("Vulnerable assets by algorithm", h2),
            table(
                [["Algorithm", "Count"], *[[a, str(n)] for a, n in summary["by_algorithm"]]],
                [95 * mm, 40 * mm],
                align_right=frozenset({1}),
            ),
        ]
    if summary["by_usage"]:
        story += [
            Paragraph("Vulnerable assets by usage", h2),
            Paragraph(
                "Key exchange is listed first deliberately where present: it is the only usage "
                "whose compromise is retroactive, because recorded traffic becomes readable. A "
                "signature "
                "cannot be forged after the fact from a recording.",
                small,
            ),
            Spacer(1, 2 * mm),
            table(
                [["Usage context", "Count"], *[[u, str(n)] for u, n in summary["by_usage"]]],
                [95 * mm, 40 * mm],
                align_right=frozenset({1}),
            ),
        ]
    if summary["by_source"]:
        story += [
            Paragraph("Where the findings came from", h2),
            table(
                [["Discovery source", "Count"], *[[s, str(n)] for s, n in summary["by_source"]]],
                [95 * mm, 40 * mm],
                align_right=frozenset({1}),
            ),
        ]

    # ---------------------------------------------------------------- details
    ranked = sorted(
        (a for a in assets if a.quantum_vulnerable.vulnerable),
        key=lambda a: (-(a.risk.score if a.risk else 0.0), a.algorithm),
    )
    story += [PageBreak(), Paragraph("Findings, highest risk first", h2)]
    if len(ranked) > max_findings:
        story.append(
            Paragraph(
                f"Showing the {max_findings} highest-risk of {len(ranked)} vulnerable assets. The "
                f"accompanying CBOM contains all of them — this table is triage, not the record.",
                small,
            )
        )
    story.append(Spacer(1, 2 * mm))

    rows: list[list[Any]] = [
        ["Algorithm", "Usage", "Attack", "Risk", "Mosca", "Location"],
    ]
    for asset in ranked[:max_findings]:
        loc = asset.location
        where = getattr(loc, "file_path", None) or getattr(loc, "host", None) or ""
        line = getattr(loc, "line", None)
        if where and line:
            where = f"{Path(str(where)).name}:{line}"
        elif where:
            where = Path(str(where)).name
        rows.append(
            [
                Paragraph(asset.algorithm, cell),
                Paragraph(asset.usage_context.value, cell),
                asset.quantum_vulnerable.attack.value,
                f"{asset.risk.score:.2f}" if asset.risk else "—",
                _fmt_years(asset.risk.mosca_margin_years) if asset.risk else "—",
                Paragraph(str(where), cell),
            ]
        )
    story.append(
        table(
            rows,
            [30 * mm, 24 * mm, 16 * mm, 14 * mm, 18 * mm, 63 * mm],
            align_right=frozenset({3, 4}),
        )
    )

    # ------------------------------------------------------------ what to do
    story += [
        Paragraph("Recommended migration targets", h2),
        KeepTogether(
            [
                table(
                    [
                        ["Finding class", "Target", "Standard", "Data compatibility"],
                        [
                            Paragraph("RSA / ECDH / DH key establishment", cell),
                            Paragraph("ML-KEM-768 (hybrid X25519MLKEM768 on the wire)", cell),
                            "FIPS 203",
                            Paragraph("Re-encryption required", cell),
                        ],
                        [
                            Paragraph("RSA / ECDSA / Ed25519 signatures", cell),
                            Paragraph("ML-DSA-65", cell),
                            "FIPS 204",
                            Paragraph("Dual-verify rollout", cell),
                        ],
                        [
                            Paragraph("3DES / RC4 / AES-128 at rest", cell),
                            Paragraph("AES-256-GCM", cell),
                            "FIPS 197",
                            Paragraph("Re-encryption required", cell),
                        ],
                        [
                            Paragraph("MD5 / SHA-1 digests", cell),
                            Paragraph("SHA-256 (argon2id for passwords)", cell),
                            "FIPS 180-4",
                            Paragraph("Dual-read during rehash", cell),
                        ],
                        [
                            Paragraph("TLS 1.0/1.1, weak cipher lists, static curves", cell),
                            Paragraph("TLS 1.2+1.3, AEAD suites, X25519MLKEM768 group", cell),
                            "SP 800-52",
                            Paragraph("In place", cell),
                        ],
                    ],
                    [45 * mm, 55 * mm, 20 * mm, 45 * mm],
                )
            ]
        ),
        Spacer(1, 4 * mm),
        Paragraph(
            "Certificates, and keys held in an HSM or Vault, cannot be remediated by a code patch: "
            "they need reissue by a PQC-capable CA and key rotation respectively. QUBIT reports "
            "them and deliberately does not emit a patch that could not fix them.",
            small,
        ),
    ]

    def _footer(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawString(18 * mm, 12 * mm, f"QUBIT {tool_version} · generated {now:%Y-%m-%d}")
        canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, f"Page {doc.page}")
        canvas.restoreState()

    SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        title=title,
        author=f"QUBIT {tool_version}",
        subject="Post-quantum cryptographic inventory and HNDL risk",
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
    ).build(story, onFirstPage=_footer, onLaterPages=_footer)
    return out_path


__all__ = ["build_pdf_report"]
