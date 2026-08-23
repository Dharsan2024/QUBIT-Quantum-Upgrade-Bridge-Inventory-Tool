"""Phase 0: what the system *is*, before any claim about how well it works.

Architecture, workflow and data model — the three things a reader wants before a single number, and
the three the pack was missing. Everything here is derived from the code rather than drawn by hand:
the architecture edges come from the real `import qubit_*` graph, the workflow stages from the
modules that implement them, and the schema from SQLAlchemy's own metadata. A diagram that is drawn
by hand is a diagram that is wrong six commits later.

Covers A4, A5, A6, A7 / F02, F03, F05, T03 of PAPER_EVIDENCE_SPEC.md.

    uv run python paper_evidence/scripts/phase0_architecture.py
"""

from __future__ import annotations

import itertools
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _style import EDGE, FILL, INK, MUTED, OUT, PALETTE, ROOT, blank_axes, save_figure

PKG = ROOT / "packages"

#: The one import edge that is not a runtime dependency: Alembic must import every model module so a
#: single `target_metadata` sees all twelve tables. Rendering it as an ordinary edge would show a
#: dependency cycle that does not exist, which is exactly the kind of thing a reviewer notices.
METADATA_ONLY = "alembic/env.py"


# --------------------------------------------------------------------------------------- graph


def package_graph() -> tuple[Counter, Counter]:
    """Every `from qubit_x import ...` between packages, counted, runtime edges kept apart from
    the Alembic metadata registration."""
    runtime: Counter[tuple[str, str]] = Counter()
    metadata: Counter[tuple[str, str]] = Counter()
    for package in sorted(PKG.iterdir()):
        source = package / "src"
        if not source.is_dir():
            continue
        own = next(p.name for p in source.iterdir() if p.is_dir() and p.name.startswith("qubit_"))
        for path in source.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            bucket = metadata if path.as_posix().endswith(METADATA_ONLY) else runtime
            for imported in re.findall(r"^\s*(?:from|import)\s+(qubit_[a-z]+)", text, re.M):
                if imported != own:
                    bucket[(own, imported)] += 1
    return runtime, metadata


def write_import_table(runtime: Counter, metadata: Counter) -> None:
    rows = [(a, b, n, "runtime") for (a, b), n in runtime.items()]
    rows += [(a, b, n, "alembic metadata only") for (a, b), n in metadata.items()]
    with (OUT / "tables" / "T_imports.csv").open("w", encoding="utf-8", newline="") as fh:
        fh.write("from_package,to_package,import_statements,kind\n")
        for a, b, n, kind in sorted(rows):
            fh.write(f"{a},{b},{n},{kind}\n")


# ------------------------------------------------------------------------------------ drawing


def box(ax, x, y, w, h, label, *, sub="", colour=PALETTE[0], fontsize=8.2, subsize=6.4, text=INK):
    """A rounded box centred on (x, y), with an optional second line."""
    ax.add_patch(
        FancyBboxPatch(
            (x - w / 2, y - h / 2),
            w,
            h,
            boxstyle="round,pad=0.6,rounding_size=1.6",
            linewidth=1.1,
            edgecolor=colour,
            facecolor=FILL,
            zorder=2,
        )
    )
    offset = 1.6 if sub else 0
    ax.text(x, y + offset, label, ha="center", va="center", fontsize=fontsize,
            color=text, fontweight="bold", zorder=3)  # fmt: skip
    if sub:
        ax.text(x, y - 2.4, sub, ha="center", va="center", fontsize=subsize, color=MUTED, zorder=3)


def arrow(ax, start, end, *, colour=EDGE, style="-", width=0.9, label="", shrink=2.0):
    ax.add_patch(
        FancyArrowPatch(
            start,
            end,
            arrowstyle="-|>",
            mutation_scale=8,
            linewidth=width,
            color=colour,
            linestyle=style,
            shrinkA=shrink,
            shrinkB=shrink,
            zorder=1,
        )
    )
    if label:
        ax.text(
            (start[0] + end[0]) / 2, (start[1] + end[1]) / 2, label,
            ha="center", va="center", fontsize=5.8, color=MUTED,
            bbox={"facecolor": "white", "edgecolor": "none", "pad": 0.8}, zorder=4,
        )  # fmt: skip


def band(ax, y, h, label):
    ax.add_patch(
        FancyBboxPatch(
            (1, y - h / 2),
            98,
            h,
            boxstyle="round,pad=0,rounding_size=1.2",
            linewidth=0,
            facecolor="#f8fafc",
            zorder=0,
        )
    )
    ax.text(2.6, y + h / 2 - 2.6, label, ha="left", va="center", fontsize=6.2,
            color=MUTED, fontweight="bold")  # fmt: skip


# ---------------------------------------------------------------------------------------- F02


def f02_architecture(runtime: Counter, metadata: Counter) -> None:
    """A5/F02. Four layers, seven packages, edges weighted by real import count."""
    fig, ax = blank_axes(7.0, 5.2)

    band(ax, 86, 22, "INTERFACE")
    band(ax, 62, 16, "SERVICE")
    band(ax, 36, 22, "ENGINE")
    band(ax, 12, 15, "FOUNDATION")

    box(ax, 20, 87, 30, 11, "Tauri 2 desktop shell",
        sub="Rust · native Windows window", colour=PALETTE[4])  # fmt: skip
    box(ax, 55, 87, 32, 11, "React dashboard",
        sub="TypeScript · bundled, not served", colour=PALETTE[4])  # fmt: skip
    box(ax, 87, 87, 20, 11, "qubit-cli", sub="Typer", colour=PALETTE[4])

    box(ax, 50, 62, 46, 11, "qubit-api  ·  FastAPI",
        sub="bound to 127.0.0.1 · bearer auth · rate limited", colour=PALETTE[0])  # fmt: skip

    engines = [
        (14, "qubit-scanner", "6 discovery sources"),
        (38, "qubit-risk", "CRQC Monte-Carlo"),
        (62, "qubit-migrate", "plan · patch · verify"),
        (86, "qubit-bridge", "hybrid TLS proof"),
    ]
    for x, name, sub in engines:
        box(ax, x, 37, 21, 12, name, sub=sub, colour=PALETTE[2])

    box(ax, 50, 12, 54, 11, "qubit-core",
        sub="CryptoAsset schema · algorithm registry · SQLite/WAL · CBOM · reports",
        colour=PALETTE[1])  # fmt: skip

    arrow(ax, (20, 81.5), (44, 68))
    arrow(ax, (55, 81.5), (52, 68), label="HTTP (loopback)")
    for x, name, _ in engines:
        module = name.replace("-", "_")
        # Only edges that exist. qubit-api never imports qubit-bridge, and drawing an unlabelled
        # arrow there would put a dependency in the figure that is not in the code.
        if weight := runtime[("qubit_cli", module)]:
            arrow(ax, (87, 81.5), (x + 2, 43.4), colour="#c3cad3", width=0.7)
        if weight := runtime[("qubit_api", module)]:
            arrow(ax, (50 + (x - 50) * 0.32, 56.4), (x, 43.4), label=str(weight))
        if weight := runtime[(module, "qubit_core")]:
            arrow(ax, (x, 30.6), (50 + (x - 50) * 0.42, 17.6), label=str(weight))
    if weight := runtime[("qubit_risk", "qubit_scanner")]:
        arrow(ax, (27.4, 34.5), (24.5, 34.5), colour="#c3cad3", width=0.7)
        ax.text(26, 31.6, str(weight), ha="center", va="center", fontsize=5.8, color=MUTED)

    # The metadata edge is drawn to qubit-migrate because that is the one that resolves: env.py also
    # tries qubit_risk.db_models, which does not exist and is swallowed by contextlib.suppress.
    # Its label lives in the legend rather than beside it, so it cannot collide with the weight on
    # the qubit-migrate arrow it runs alongside.
    arrow(ax, (70, 17.6), (70, 30.6), colour="#b9c2cc", style=(0, (2, 2)), width=0.8)

    ax.text(50, 1.5,
            "numbers are import-statement counts  ·  dashed = Alembic metadata registration, not a "
            "runtime dependency  ·  every edge: tables/T_imports.csv",
            ha="center", va="center", fontsize=5.8, color=MUTED)  # fmt: skip

    total = sum(runtime.values())
    save_figure(
        fig,
        "F02_architecture",
        f"QUBIT is four layers over seven Python packages, drawn from the {total} real "
        f"inter-package import statements rather than from a design document. Every runtime edge "
        f"points downward; the {sum(metadata.values())} upward ones live in "
        f"qubit-core/alembic/env.py and exist so Alembic sees all twelve tables under one metadata "
        f"object, which is schema registration and not a runtime dependency. Note that qubit-cli "
        f"reaches the engine packages directly rather than through the API, so a scripted run and "
        f"a windowed run are not the same path. The desktop shell bundles the dashboard rather "
        f"than serving it, and the engine binds to 127.0.0.1 — which is what makes the offline "
        f"claim structural rather than a policy. Source: tables/T_imports.csv.",
    )


# ---------------------------------------------------------------------------------------- F03


def scanner_sources() -> list[tuple[str, str]]:
    """The discovery sources that actually exist as modules, so the figure cannot claim one that
    was planned and never built."""
    known = {
        "code": "tree-sitter AST",
        "config": "nginx/httpd/sshd",
        "network": "live TLS",
        "certs": "X.509",
        "deps": "10 ecosystems",
        "vault": "transit + pki",
    }
    root = PKG / "qubit-scanner" / "src" / "qubit_scanner"
    return [(name, sub) for name, sub in known.items() if (root / name).is_dir()]


def f03_workflow() -> None:
    """A6/F03. The five stages, what implements each, and what each one leaves behind."""
    fig, ax = blank_axes(7.6, 4.4)

    sources = scanner_sources()
    span = 100 / len(sources)
    for index, (name, sub) in enumerate(sources):
        x = span * (index + 0.5)
        box(ax, x, 88, span - 3.4, 12, name, sub=sub, colour=PALETTE[5],
            fontsize=7.4, subsize=5.6)  # fmt: skip
        arrow(ax, (x, 81.6), (10, 63.2), colour="#ccd3da", width=0.6)

    stages = [
        (10, "1 · Discover", "qubit-scanner", PALETTE[5]),
        (30, "2 · Inventory", "qubit-core", PALETTE[0]),
        (50, "3 · Quantify", "qubit-risk", PALETTE[4]),
        (70, "4 · Migrate", "qubit-migrate", PALETTE[2]),
        (90, "5 · Verify", "qubit-bridge", PALETTE[3]),
    ]
    artifacts = [
        "raw findings\n(6 sources)",
        "CryptoAsset rows\n+ CycloneDX 1.7 CBOM",
        "HNDL score, Mosca\nmargin, CNSA 2.0 phase",
        "patch behind a\n5-check validation gate",
        "hybrid handshake proof\n+ re-scan to zero",
    ]
    for (x, label, owner, colour), artifact in zip(stages, artifacts, strict=True):
        box(ax, x, 55, 16, 15, label, sub=owner, colour=colour, fontsize=8.4, subsize=6.0)
        ax.text(x, 31, artifact, ha="center", va="center", fontsize=6.0, color=INK,
                linespacing=1.5)  # fmt: skip
        arrow(ax, (x, 47.2), (x, 37), colour="#ccd3da", width=0.7)
    for left, right in itertools.pairwise(stages):
        arrow(ax, (left[0] + 8.3, 55), (right[0] - 8.3, 55), colour=EDGE, width=1.1, shrink=0.5)

    ax.add_patch(
        FancyArrowPatch(
            (90, 16),
            (10, 16),
            arrowstyle="-|>",
            mutation_scale=8,
            linewidth=0.9,
            color="#b9c2cc",
            linestyle=(0, (3, 2)),
            connectionstyle="arc3,rad=0.10",
            zorder=1,
        )
    )
    ax.text(50, 3, "re-scan closes the loop: a migration is not complete until discovery "
            "no longer finds it", ha="center", va="center", fontsize=6.2, color=MUTED)  # fmt: skip

    save_figure(
        fig,
        "F03_workflow",
        "The pipeline, with the module that implements each stage and the artifact it leaves "
        "behind. Six independent discovery sources feed one normalised inventory, so a finding "
        "from a TLS handshake and a finding from an AST are the same kind of object by the time "
        "risk is computed. The loop is closed rather than open: a migration counts as complete "
        "only when a fresh scan no longer reports the finding, which is what stage 5 verifies. "
        "Every stage is local — no step contacts a network service the user did not name.",
    )


# ---------------------------------------------------------------------------------------- F05


def load_metadata():
    """SQLAlchemy's own metadata, after importing every module that registers tables against it."""
    import qubit_core.db.models as core_models
    import qubit_migrate.state.models  # noqa: F401

    return core_models.Base.metadata


def f05_data_model() -> None:
    """A7/F05. Twelve tables, introspected — not transcribed."""
    metadata = load_metadata()
    tables = {t.name: t for t in metadata.sorted_tables}

    parents: dict[str, set[str]] = {
        name: {
            next(iter(column.foreign_keys)).column.table.name
            for column in table.columns
            if column.foreign_keys
        }
        - {name}
        for name, table in tables.items()
    }

    depth: dict[str, int] = {}
    for _ in range(len(tables)):
        for name in tables:
            depth[name] = 1 + max((depth.get(p, 0) for p in parents[name]), default=-1)

    rows: dict[int, list[str]] = defaultdict(list)
    for name in sorted(tables, key=lambda n: (depth[n], n)):
        rows[depth[name]].append(name)

    owner = {n: ("qubit-migrate" if n.startswith("migration_") else "qubit-core") for n in tables}
    colour = {"qubit-core": PALETTE[1], "qubit-migrate": PALETTE[2]}

    levels = max(rows) + 1
    fig, ax = blank_axes(7.4, 0.95 * levels + 1.0)

    position: dict[str, tuple[float, float]] = {}
    for level, names in rows.items():
        y = 92 - (level + 0.5) * (92 / levels)
        step = 100 / len(names)
        for index, name in enumerate(names):
            position[name] = (step * (index + 0.5), y)

    span = 92 / levels
    height = span * 0.46
    # Arrows are shrunk in points, so they stop at the box edge rather than the box centre; without
    # this the head is drawn underneath the box and the direction of the key is lost.
    for name, (x, y) in position.items():
        for parent in parents[name]:
            if parent in position:
                px, py = position[parent]
                ax.add_patch(
                    FancyArrowPatch(
                        (px, py - height / 2),
                        (x, y + height / 2),
                        arrowstyle="-|>",
                        mutation_scale=9,
                        linewidth=0.75,
                        color="#aab4bf",
                        shrinkA=1.0,
                        shrinkB=1.0,
                        zorder=1,
                        connectionstyle="arc3,rad=0.06",
                    )
                )

    for name, (x, y) in position.items():
        width = min(100 / len(rows[depth[name]]) - 3, 30)
        # Long table names get a smaller face rather than an overflowing box.
        size = 7.2 if len(name) <= 18 else 6.1
        box(ax, x, y, width, height, name, sub=f"{len(tables[name].columns)} columns",
            colour=colour[owner[name]], fontsize=size, subsize=5.9)  # fmt: skip

    for index, (package, shade) in enumerate(colour.items()):
        ax.add_patch(
            FancyBboxPatch(
                (2 + index * 26, 96),
                3,
                2.2,
                boxstyle="round,pad=0.3,rounding_size=0.8",
                linewidth=1.1,
                edgecolor=shade,
                facecolor=FILL,
                zorder=2,
            )
        )
        ax.text(6.5 + index * 26, 97.1, f"owned by {package}", ha="left", va="center",
                fontsize=6.0, color=MUTED)  # fmt: skip
    ax.text(98, 97.1, "arrows follow foreign keys", ha="right", va="center",
            fontsize=6.0, color=MUTED)  # fmt: skip

    total_columns = sum(len(t.columns) for t in tables.values())

    with (OUT / "tables" / "T_schema.csv").open("w", encoding="utf-8", newline="") as fh:
        fh.write("table,owner,column,type,nullable,primary_key,foreign_key\n")
        for name in sorted(tables):
            for column in tables[name].columns:
                target = (
                    next(iter(column.foreign_keys)).target_fullname if column.foreign_keys else ""
                )
                fh.write(
                    f"{name},{owner[name]},{column.name},{column.type!s:.40},"
                    f"{column.nullable},{column.primary_key},{target}\n"
                )

    save_figure(
        fig,
        "F05_data_model",
        f"The physical schema, introspected from SQLAlchemy metadata rather than transcribed: "
        f"{len(tables)} tables and {total_columns} columns, laid out by foreign-key depth. The "
        f"frozen CryptoAsset schema is flattened into the filterable columns of `assets`, with the "
        f"structured remainder in JSON, and risk and migration write their annotations back onto "
        f"the same row rather than forking a second copy of the truth. Migration owns six tables "
        f"of its own but reaches the inventory only through foreign keys. "
        f"Full column listing: tables/T_schema.csv.",
    )


# ---------------------------------------------------------------------------------------- T03


def t03_tech_stack() -> None:
    """A4/T03. Layer, component, technology, and the version resolved in this environment."""
    from importlib.metadata import PackageNotFoundError, version

    def resolved(dist: str) -> str:
        try:
            return version(dist)
        except PackageNotFoundError:
            return "UNKNOWN"

    stack = [
        ("Interface", "Desktop shell", "Tauri", "2.x", "native Windows window over a local engine"),
        ("Interface", "Dashboard", "React + TypeScript", "UNKNOWN",
         "bundled into the shell, not served over a network"),
        ("Interface", "Command line", "Typer", resolved("typer"), "scriptable entry point"),
        ("Service", "HTTP engine", "FastAPI", resolved("fastapi"),
         "bound to 127.0.0.1, bearer auth, rate limited"),
        ("Service", "ASGI server", "uvicorn", resolved("uvicorn"), "single local process"),
        ("Engine", "Source parsing", "tree-sitter", resolved("tree-sitter"),
         "AST queries over 19 grammars"),
        ("Engine", "Certificates / TLS", "cryptography", resolved("cryptography"),
         "X.509 parsing and handshake primitives"),
        ("Engine", "Transformation", "Ollama (qwen2.5-coder:7b)", "UNKNOWN",
         "local inference, greedy decoding, no network egress"),
        ("Engine", "Dependency graph", "networkx", resolved("networkx"),
         "migration ordering over unit dependencies"),
        ("Foundation", "ORM", "SQLAlchemy", resolved("sqlalchemy"), "12 tables, single metadata"),
        ("Foundation", "Migrations", "Alembic", resolved("alembic"), "versioned schema"),
        ("Foundation", "Storage", "SQLite (WAL)", "UNKNOWN", "one file, no server"),
        ("Foundation", "Validation", "Pydantic", resolved("pydantic"), "frozen CryptoAsset schema"),
        ("Foundation", "Reports", "reportlab", resolved("reportlab"),
         "pure Python, no system libraries"),
        ("Evidence", "Figures", "matplotlib", resolved("matplotlib"), "vector SVG, Okabe-Ito"),
        ("Evidence", "Statistics", "scipy", resolved("scipy"),
         "exact McNemar, Wilson, log-linear fits"),
    ]  # fmt: skip

    with (OUT / "tables" / "T03_tech_stack.csv").open("w", encoding="utf-8", newline="") as fh:
        fh.write("layer,component,technology,version,role\n")
        for row in stack:
            fh.write(",".join(f'"{cell}"' for cell in row) + "\n")
    print(f"T03: {len(stack)} stack entries")


# --------------------------------------------------------------------------------- narrative


def architecture_md(runtime: Counter) -> None:
    """The prose that goes with F02/F03/F05, with every count computed rather than remembered."""
    from qubit_core.algorithms import ALGORITHMS
    from qubit_scanner.catalog.loader import RuleCatalog

    catalog = RuleCatalog.load()
    grammars = sorted(catalog.languages())
    compiled = catalog.all_rules()
    unique_rules = len({r.rule.id for r in compiled})

    import yaml

    dep_map = yaml.safe_load(
        (
            PKG / "qubit-scanner" / "src" / "qubit_scanner" / "deps" / "crypto_library_map.yaml"
        ).read_text(encoding="utf-8")
    )
    packages_mapped = len(dep_map["packages"])

    metadata = load_metadata()
    tables = list(metadata.sorted_tables)

    text = f"""QUBIT is a native Windows desktop application over a local HTTP engine. Nothing
it does requires a network service the user did not name: discovery, risk, transformation and
verification all run on the machine, against a local model, writing to one SQLite file. That is
a structural property rather than a policy — the engine binds to `127.0.0.1`, and the shell
bundles the dashboard instead of serving it.

## Layers

**Interface.** A Tauri 2 shell hosts the React dashboard; `qubit-cli` offers the same operations
without a window, for scripting and for reproducing a run from a shell.

**Service.** `qubit-api` is a FastAPI application bound to loopback, with bearer-token
authentication and rate limiting. It is the only writer the interface layer talks to.

**Engine.** Four packages, none of which knows about the others except through the inventory:

* `qubit-scanner` — {len(scanner_sources())} independent discovery sources (AST, configuration,
  live TLS, certificates, dependency manifests, HashiCorp Vault), driven by a data-only rule
  catalog: **{unique_rules} rules compiled into {len(compiled)} language bindings across
  {len(grammars)} tree-sitter grammars**, plus a package→algorithm map covering
  **{packages_mapped} packages**.
* `qubit-risk` — CRQC Monte-Carlo, Mosca inequality, CNSA 2.0 milestone evaluation.
* `qubit-migrate` — plan, patch, and a validation gate that must pass before a patch is offered.
* `qubit-bridge` — hybrid TLS handshake verification.

**Foundation.** `qubit-core` owns the frozen `CryptoAsset` schema, the canonical registry of
**{len(ALGORITHMS)} algorithms**, the database, CycloneDX 1.7 CBOM export, and report rendering.
Every other package depends on it and it depends on none of them at run time.

## The one edge that looks like a cycle

`qubit-core/alembic/env.py` imports the migration models so a single Alembic `target_metadata` sees
all {len(tables)} tables. It is an import for schema registration, not a runtime dependency, and
F02 draws it dotted for that reason. The {sum(runtime.values())} runtime edges point strictly
downward.

## Rules are data, not code

The detection catalog is YAML validated against a `qubit-rule/v1` schema, not Python. A new rule is
a file, and every rule ships its own positive and negative fixtures which run as tests. This is why
the rule set can be counted, versioned and audited — and why the counts above are read from the
catalog at build time rather than typed into this document.

## Storage

One SQLite database in WAL mode, {len(tables)} tables (F05). The inventory is the single source of
truth: risk and migration annotate the same `assets` row rather than keeping a second copy, so a
finding cannot be current in one view and stale in another.
"""
    (OUT / "ARCHITECTURE.md").write_text(text, encoding="utf-8")
    print(f"A4: ARCHITECTURE.md ({unique_rules} rules, {len(grammars)} grammars, "
          f"{len(ALGORITHMS)} algorithms, {len(tables)} tables)")  # fmt: skip


def main() -> int:
    (OUT / "tables").mkdir(parents=True, exist_ok=True)
    runtime, metadata = package_graph()
    write_import_table(runtime, metadata)
    f02_architecture(runtime, metadata)
    f03_workflow()
    f05_data_model()
    t03_tech_stack()
    architecture_md(runtime)
    print("\nphase 0 complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
