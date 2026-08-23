"""Phase 6: assemble EVIDENCE_PACK.pdf from everything the other scripts produced.

Reads only generated artifacts — `tables/`, `figures/`, `cards/`, `data/`, `env/`, and the two
hand-written pages the spec calls for (`GAPS.md`, `QUESTIONS.md`). Nothing is authored here, so
re-running the extraction scripts and then this one produces a pack that matches the repository
rather than the last time somebody edited a document.

    uv run python paper_evidence/scripts/build_pack.py
"""

from __future__ import annotations

import csv
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "paper_evidence"
PDF = OUT / "EVIDENCE_PACK.pdf"

INK = colors.HexColor("#111418")
MUTED = colors.HexColor("#5b6470")
RULE = colors.HexColor("#c7cdd4")
BAND = colors.HexColor("#eef1f4")

_styles = getSampleStyleSheet()
S = {
    "h1": ParagraphStyle("h1", parent=_styles["Heading1"], fontSize=16, spaceBefore=14,
                         spaceAfter=8, textColor=INK),
    "h2": ParagraphStyle("h2", parent=_styles["Heading2"], fontSize=12, spaceBefore=11,
                         spaceAfter=5, textColor=INK),
    "h3": ParagraphStyle("h3", parent=_styles["Heading3"], fontSize=10.5, spaceBefore=8,
                         spaceAfter=3, textColor=INK),
    "body": ParagraphStyle("body", parent=_styles["BodyText"], fontSize=9, leading=12.6,
                           alignment=TA_LEFT, textColor=INK, spaceAfter=5),
    "small": ParagraphStyle("small", parent=_styles["BodyText"], fontSize=7.6, leading=10,
                            textColor=MUTED, spaceAfter=4),
    "code": ParagraphStyle("code", parent=_styles["BodyText"], fontName="Courier", fontSize=7,
                           leading=8.6, textColor=INK, spaceAfter=4),
    "cell": ParagraphStyle("cell", parent=_styles["BodyText"], fontSize=7.2, leading=9,
                           textColor=INK),
    "cellhead": ParagraphStyle("cellhead", parent=_styles["BodyText"], fontSize=7.2, leading=9,
                               textColor=INK, fontName="Helvetica-Bold"),
    "caption": ParagraphStyle("caption", parent=_styles["BodyText"], fontSize=7.8, leading=10.4,
                              textColor=MUTED, spaceBefore=3, spaceAfter=10),
}  # fmt: skip


def esc(text: str) -> str:
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"`([^`]+?)`", r'<font face="Courier">\1</font>', text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return text


def table_from_rows(rows: list[list[str]], widths: list[float] | None = None) -> Table:
    body = [
        [Paragraph(esc(c), S["cellhead"] if i == 0 else S["cell"]) for c in row]
        for i, row in enumerate(rows)
    ]
    table = Table(body, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BAND),
                ("GRID", (0, 0), (-1, -1), 0.25, RULE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]
        )
    )
    return table


def render_markdown(text: str, width: float) -> list:
    """A deliberately small markdown subset: headings, tables, fenced code, lists, paragraphs."""
    flow: list = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        if stripped.startswith("```"):
            index += 1
            block = []
            while index < len(lines) and not lines[index].strip().startswith("```"):
                block.append(lines[index][:110])
                index += 1
            index += 1
            for chunk in block:
                flow.append(Paragraph(esc(chunk) or "&nbsp;", S["code"]))
            flow.append(Spacer(1, 4))
            continue

        if (
            stripped.startswith("|")
            and index + 1 < len(lines)
            and set(lines[index + 1].strip()) <= set("|-: ")
        ):
            rows = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                cells = [c.strip() for c in lines[index].strip().strip("|").split("|")]
                if not set("".join(cells)) <= set("-: "):
                    rows.append(cells)
                index += 1
            if rows:
                columns = max(len(r) for r in rows)
                rows = [r + [""] * (columns - len(r)) for r in rows]
                flow.append(table_from_rows(rows, [width / columns] * columns))
                flow.append(Spacer(1, 6))
            continue

        if stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            flow.append(Paragraph(esc(stripped.lstrip("# ").strip()), S[f"h{min(level, 3)}"]))
        elif stripped.startswith(("* ", "- ")):
            flow.append(Paragraph("• " + esc(stripped[2:]), S["body"]))
        elif stripped.startswith("> "):
            flow.append(Paragraph(esc(stripped[2:]), S["small"]))
        elif stripped and not set(stripped) <= set("-="):
            flow.append(Paragraph(esc(stripped), S["body"]))
        index += 1
    return flow


def csv_table(path: Path, width: float, limit: int = 40) -> list:
    with path.open(encoding="utf-8", newline="") as fh:
        rows = [r for r in csv.reader(fh) if r]
    if not rows:
        return []
    shown = rows[: limit + 1]
    columns = max(len(r) for r in shown)
    shown = [r + [""] * (columns - len(r)) for r in shown]
    flow: list = [table_from_rows(shown, [width / columns] * columns)]
    if len(rows) - 1 > limit:
        flow.append(Paragraph(f"({len(rows) - 1 - limit} further rows in {path.name})", S["small"]))
    flow.append(Spacer(1, 6))
    return flow


def figure(name: str, width: float) -> list:
    png = OUT / "figures" / f"{name}.png"
    caption = OUT / "figures" / f"{name}_caption.txt"
    if not png.exists():
        return []
    from reportlab.lib.utils import ImageReader

    iw, ih = ImageReader(str(png)).getSize()
    shown = min(width, 150 * mm)
    flow: list = [Image(str(png), width=shown, height=shown * ih / iw)]
    if caption.exists():
        flow.append(
            Paragraph(
                f"<b>{name}.</b> " + esc(caption.read_text(encoding="utf-8").strip()), S["caption"]
            )
        )
    return [KeepTogether(flow)]


def _git(*args: str) -> str:
    try:
        return subprocess.run(  # noqa: S603
            ["git", *args],  # noqa: S607
            capture_output=True, text=True, cwd=ROOT, timeout=30, check=False,
        ).stdout.strip()  # fmt: skip
    except Exception:
        return "UNKNOWN"


def build() -> int:
    doc = SimpleDocTemplate(
        str(PDF), pagesize=A4,
        leftMargin=18 * mm, rightMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
        title="QUBIT — Paper Evidence Pack", author="QUBIT",
    )  # fmt: skip
    width = doc.width
    flow: list = []

    # 1. Cover
    flow += [
        Spacer(1, 40 * mm),
        Paragraph("QUBIT", ParagraphStyle("cover", parent=S["h1"], fontSize=30, spaceAfter=4)),
        Paragraph(
            "Quantum Upgrade Bridge &amp; Inventory Tool — Paper Evidence Pack",
            ParagraphStyle("sub", parent=S["h2"], fontSize=12, textColor=MUTED),
        ),
        Spacer(1, 10 * mm),
        table_from_rows(
            [
                ["field", "value"],
                ["commit", _git("rev-parse", "HEAD")[:12] or "UNKNOWN"],
                ["branch", _git("rev-parse", "--abbrev-ref", "HEAD") or "UNKNOWN"],
                ["uncommitted files", str(len(_git("status", "--porcelain").splitlines()))],
                ["built (UTC)", datetime.now(UTC).isoformat(timespec="seconds")],
                ["generated by", "paper_evidence/scripts/*.py"],
            ],
            [width * 0.3, width * 0.7],
        ),
        Spacer(1, 8 * mm),
        Paragraph(
            "Every number in this pack traces to a CSV in <font face='Courier'>tables/</font> or "
            "<font face='Courier'>data/</font>, or to the command logged beside it. Values that "
            "could not be measured are written UNKNOWN and listed in GAPS with the action that "
            "would resolve them. No figure in this document is an estimate.",
            S["small"],
        ),
        PageBreak(),
    ]

    # Architecture, workflow and data model come first: what the system *is*, before any claim
    # about how well it works. Everything that qualifies a result — limitations, open author
    # decisions, the manifest — is held back to the appendices so the body reads as one current,
    # working description rather than a mixture of the system and its caveats.
    sections: list[tuple[str, Path | str]] = [
        ("1. Architecture", "ARCH"),
        ("2. Workflow", "WORKFLOW"),
        ("3. Data model", "SCHEMA"),
        ("4. Module inventory and languages", "MODULES"),
        ("5. Public API and CLI surface", "API"),
        ("6. Decision logic — truth tables", "TRUTH"),
        ("7. Environment and dependencies", "ENV"),
        ("8. Model card", "CARDS"),
        ("9. Learned tiers and model cards", OUT / "MODELS.md"),
        ("10. Verification, security and accessibility", OUT / "VERIFICATION.md"),
        ("11. What was measured", OUT / "SUMMARY.md"),
        ("12. Results", "RESULTS"),
        ("13. Ground truth and ablation", "GROUNDTRUTH"),
        ("14. Figures", "FIGURES"),
        ("15. Statistical tests", "STATS"),
        ("Appendix A. Limitations", OUT / "GAPS.md"),
        ("Appendix B. Open author decisions", OUT / "QUESTIONS.md"),
        ("Appendix C. Manifest", OUT / "MANIFEST.md"),
    ]

    #: Placed by hand in their own sections above, so the figure gallery must not repeat them.
    PLACED = {"F02_architecture", "F03_workflow", "F05_data_model", "F16_ablation"}

    for title, source in sections:
        flow.append(Paragraph(title, S["h1"]))
        if isinstance(source, Path):
            if source.exists():
                flow += render_markdown(source.read_text(encoding="utf-8"), width)
            else:
                flow.append(Paragraph(f"MISSING: {source.name}", S["body"]))
        elif source == "ARCH":
            architecture = OUT / "ARCHITECTURE.md"
            if architecture.exists():
                flow += render_markdown(architecture.read_text(encoding="utf-8"), width)
            flow += figure("F02_architecture", width)
            stack = OUT / "tables" / "T03_tech_stack.csv"
            if stack.exists():
                flow.append(Paragraph("T03 — technology stack, with resolved versions", S["h2"]))
                flow += csv_table(stack, width, limit=30)
        elif source == "WORKFLOW":
            flow += figure("F03_workflow", width)
            flow.append(
                Paragraph(
                    "Each stage writes into the same inventory rather than into a private store, "
                    "so the artifact one stage produces is the input the next one reads. The "
                    "truth tables in section 6 give the exact decision rules for the two stages "
                    "that make a judgement call: screening a finding, and admitting a patch.",
                    S["body"],
                )
            )
        elif source == "SCHEMA":
            flow += figure("F05_data_model", width)
            schema = OUT / "tables" / "T_schema.csv"
            if schema.exists():
                flow.append(Paragraph("T_schema — every column, introspected", S["h2"]))
                flow += csv_table(schema, width, limit=45)
            imports = OUT / "tables" / "T_imports.csv"
            if imports.exists():
                flow.append(Paragraph("T_imports — the inter-package edges behind F02", S["h2"]))
                flow += csv_table(imports, width, limit=25)
        elif source == "MODULES":
            for name, caption in (
                ("T_modules.csv", "Lines of code per module."),
                ("T_languages.csv", "By language, source separated from config and docs."),
                ("T_tests.csv", "Declared test functions per area."),
                ("T_config.csv", "Every configuration setting and its default."),
            ):
                path = OUT / "tables" / name
                if path.exists():
                    flow.append(Paragraph(caption, S["body"]))
                    flow += csv_table(path, width, limit=25)
        elif source == "API":
            api = OUT / "tables" / "T_api.md"
            if api.exists():
                flow += render_markdown(api.read_text(encoding="utf-8"), width)
        elif source == "ENV":
            for name in ("hardware.txt", "versions.lock"):
                path = OUT / "env" / name
                if path.exists():
                    flow.append(Paragraph(name, S["h2"]))
                    for line in path.read_text(encoding="utf-8").splitlines()[:60]:
                        flow.append(Paragraph(esc(line[:110]) or "&nbsp;", S["code"]))
        elif source == "TRUTH":
            for path in sorted((OUT / "tables").glob("T12_*.md")):
                flow += render_markdown(path.read_text(encoding="utf-8"), width)
                flow.append(Spacer(1, 4))
        elif source == "CARDS":
            for path in sorted((OUT / "cards").glob("*.md")):
                flow += render_markdown(path.read_text(encoding="utf-8"), width)
                flow.append(PageBreak())
        elif source == "RESULTS":
            flow.append(
                Paragraph("T07 — per-class accuracy with Wilson and bootstrap intervals", S["h2"])
            )
            flow += csv_table(OUT / "tables" / "T07.csv", width)
            for path in sorted((OUT / "tables").glob("T_confusion_*.md")):
                flow += render_markdown(path.read_text(encoding="utf-8"), width)
        elif source == "GROUNDTRUTH":
            flow.append(
                Paragraph(
                    "Scored against CryptoAPI-Bench (Afrose et al., SecDev 2019), whose labels "
                    "were produced, published and peer-reviewed by other people. The construct "
                    "mapping was fixed in benchmarks/groundtruth/MAPPING.md before this ran, and "
                    "the categories it declares out of scope are excluded by that document rather "
                    "than by whatever improved the score.",
                    S["body"],
                )
            )
            flow += csv_table(OUT / "tables" / "T09_groundtruth.csv", width)
            flow.append(
                Paragraph("T08 — what intra-file constant folding bought, per dimension", S["h2"])
            )
            flow += csv_table(OUT / "tables" / "T08_ablation.csv", width)
            flow += figure("F16_ablation", width)
        elif source == "FIGURES":
            for path in sorted((OUT / "figures").glob("*.png")):
                if path.stem not in PLACED:
                    flow += figure(path.stem, width)
        elif source == "STATS":
            flow.append(
                Paragraph(
                    "Exact McNemar on paired classifiers over the same items, Holm-Bonferroni "
                    "adjusted across the family.",
                    S["body"],
                )
            )
            flow += csv_table(OUT / "tables" / "T11.csv", width)
            convergence = OUT / "data" / "convergence.csv"
            if convergence.exists():
                flow.append(Paragraph("Bootstrap convergence (B17)", S["h2"]))
                flow += csv_table(convergence, width)
        flow.append(PageBreak())

    def decorate(canvas, document) -> None:  # type: ignore[no-untyped-def]
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, "QUBIT — Paper Evidence Pack")
        canvas.drawRightString(A4[0] - 16 * mm, 10 * mm, f"page {document.page}")
        canvas.restoreState()

    doc.build(flow, onFirstPage=decorate, onLaterPages=decorate)
    print(f"wrote {PDF} ({PDF.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(build())
