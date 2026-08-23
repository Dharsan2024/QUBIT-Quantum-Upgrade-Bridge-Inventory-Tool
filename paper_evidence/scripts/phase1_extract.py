"""Phase 1: everything that can be read off the repository without running an experiment.

Re-runnable by design (`uv run python paper_evidence/scripts/phase1_extract.py`). Nothing here is
transcribed by hand, because a number typed into a table once is a number nobody can check later.
Anything that cannot be established from the repository is written as `UNKNOWN` and recorded in
`GAPS.md` with the action that would resolve it -- a gap is a valid output, a guess is not.

Covers A1, A2, A3, A8, A9, A10, A11 of PAPER_EVIDENCE_SPEC.md.
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
import tomllib
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "paper_evidence"

#: Extensions worth counting, mapped to the language label used throughout the pack.
LANGUAGES = {
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".rs": "Rust",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".sql": "SQL",
    ".md": "Markdown",
    ".html": "HTML",
    ".css": "CSS",
    ".sh": "Shell",
    ".toml": "TOML",
    ".json": "JSON",
}

#: Directories that are not this project's own source, however much of it they are by volume.
SKIP = {
    ".git", ".venv", "node_modules", "__pycache__", "dist", "build", "target",
    ".ruff_cache", ".pytest_cache", ".mypy_cache", "git help", "paper_evidence",
    "demo-lab", "unwanted", ".claude", "htmlcov", "coverage",
    "results", "vendor", ".obsidian", "gen", "models",
}  # fmt: skip

#: Generated or vendored data that would otherwise dominate a line count. A lockfile is not code, a
#: saved experiment result is not code, and a sampling frame is not code. Counting them makes the
#: project look half again its size, in the one direction a reader has no way to check.
SKIP_FILES = {
    "package-lock.json",
    "uv.lock",
    "corpus.lock.json",
    "labels.jsonl",
    "human_labels.jsonl",
    "frame.json",
    "sample.json",
    "worksheet.json",
    "key.json",
    "scores.json",
    "agreement.json",
    "human_worksheet.json",
    "human_strata.json",
}

#: Which languages are the project's own source, as opposed to configuration or generated data.
#: Reported separately so a sentence like "N lines of source" can be written without inflating it.
SOURCE_LANGUAGES = {"Python", "TypeScript", "JavaScript", "Rust", "Shell"}


def _iter_files() -> list[Path]:
    files = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        parts = set(path.relative_to(ROOT).parts)
        if parts & SKIP or path.name in SKIP_FILES:
            continue
        files.append(path)
    return files


def _count_lines(path: Path) -> tuple[int, int]:
    """Physical lines, and lines that are neither blank nor a whole-line comment."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0, 0
    physical = 0
    code = 0
    for raw in text.splitlines():
        physical += 1
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "//", "*", "/*", "<!--")):
            continue
        code += 1
    return physical, code


def modules_and_languages(files: list[Path]) -> None:
    """A1 + A2. A module is a top-level package or app directory: how the repo is organised."""
    by_module: dict[str, dict[str, int]] = defaultdict(lambda: {"files": 0, "lines": 0, "code": 0})
    by_language: dict[str, dict[str, int]] = defaultdict(
        lambda: {"files": 0, "lines": 0, "code": 0}
    )

    for path in files:
        language = LANGUAGES.get(path.suffix.lower())
        if language is None:
            continue
        relative = path.relative_to(ROOT)
        parts = relative.parts
        if parts[0] == "packages" and len(parts) > 1:
            module = f"packages/{parts[1]}"
        elif len(parts) > 1:
            module = parts[0]
        else:
            module = "(root)"
        physical, code = _count_lines(path)
        for bucket, key in ((by_module, module), (by_language, language)):
            bucket[key]["files"] += 1
            bucket[key]["lines"] += physical
            bucket[key]["code"] += code

    rows = sorted(by_module.items(), key=lambda kv: -kv[1]["code"])
    with (OUT / "tables" / "T_modules.csv").open("w", encoding="utf-8", newline="") as fh:
        fh.write("module,files,physical_lines,code_lines\n")
        for name, counts in rows:
            fh.write(f"{name},{counts['files']},{counts['lines']},{counts['code']}\n")

    lang_rows = sorted(by_language.items(), key=lambda kv: -kv[1]["code"])
    with (OUT / "tables" / "T_languages.csv").open("w", encoding="utf-8", newline="") as fh:
        fh.write("language,category,files,physical_lines,code_lines\n")
        for name, counts in lang_rows:
            category = "source" if name in SOURCE_LANGUAGES else "config/docs"
            fh.write(f"{name},{category},{counts['files']},{counts['lines']},{counts['code']}\n")

    total_code = sum(c["code"] for _, c in rows)
    source_code = sum(c["code"] for n, c in lang_rows if n in SOURCE_LANGUAGES)
    print(
        f"A1/A2: {len(rows)} modules, {len(lang_rows)} languages, "
        f"{source_code:,} source lines ({total_code:,} incl. config, rules and docs)"
    )


def dependencies() -> None:
    """A3. Pinned versions as actually resolved, not as requested."""
    lines = ["# Resolved environment", ""]
    lines.append(f"python: {platform.python_version()}")
    frozen = subprocess.run(
        [sys.executable, "-m", "pip", "freeze"],
        capture_output=True,
        text=True,
        check=False,
    )
    lines += ["", "## Python (pip freeze)", ""]
    lines += sorted(line for line in frozen.stdout.splitlines() if line.strip())

    declared: dict[str, list[str]] = {}
    for pyproject in sorted(ROOT.glob("packages/*/pyproject.toml")):
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        project = data.get("project", {})
        declared[project.get("name", pyproject.parent.name)] = list(project.get("dependencies", []))
    lines += ["", "## Declared per package", ""]
    for name, deps in sorted(declared.items()):
        lines.append(f"{name}:")
        lines += [f"  {d}" for d in deps] or ["  (none)"]

    lock = ROOT / "dashboard" / "package-lock.json"
    if lock.exists():
        payload = json.loads(lock.read_text(encoding="utf-8"))
        packages = payload.get("packages", {})
        direct = {
            k.removeprefix("node_modules/"): v.get("version", "?")
            for k, v in packages.items()
            if k.startswith("node_modules/") and k.count("node_modules") == 1
        }
        lines += ["", f"## npm (dashboard) — {len(direct)} packages", ""]
        lines += [f"{n}=={v}" for n, v in sorted(direct.items())]

    (OUT / "env" / "versions.lock").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"A3: versions.lock, {len(declared)} python packages declared")


def config_surface() -> None:
    """A8. Every tunable the code reads, with its default, found in the settings models."""
    rows: list[tuple[str, str, str, str]] = []
    found = sorted(
        {
            path
            for pattern in ("packages/*/src/**/settings.py", "packages/*/src/**/config.py")
            for path in ROOT.glob(pattern)
        }
    )
    for settings in found:
        module = settings.relative_to(ROOT).as_posix()
        for line in settings.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            if stripped.startswith(("class ", "def ", "@", "from ", "import ")):
                continue
            name, _, rest = stripped.partition(":")
            if not name.isidentifier() or name.startswith("_"):
                continue
            annotation, _, default = rest.partition("=")
            rows.append((module, name.strip(), annotation.strip(), default.strip() or "(required)"))
    with (OUT / "tables" / "T_config.csv").open("w", encoding="utf-8", newline="") as fh:
        fh.write("source,setting,type,default\n")
        for module, name, annotation, default in rows:
            safe = default.replace('"', "'").replace(",", ";")
            fh.write(f'{module},{name},"{annotation}","{safe}"\n')
    print(f"A8: {len(rows)} configuration settings")


def api_surface() -> None:
    """A9. The REST routes and the CLI commands, read from the code that defines them."""
    routes: list[tuple[str, str, str]] = []
    for router in sorted(ROOT.glob("packages/qubit-api/src/**/*.py")):
        text = router.read_text(encoding="utf-8")
        module = router.relative_to(ROOT).as_posix()
        for line in text.splitlines():
            stripped = line.strip()
            for verb in ("get", "post", "put", "patch", "delete"):
                marker = f'@router.{verb}("'
                if stripped.startswith(marker):
                    path = stripped[len(marker) :].split('"')[0]
                    routes.append((verb.upper(), path, module))
    commands: list[tuple[str, str]] = []
    cli = ROOT / "packages" / "qubit-cli" / "src" / "qubit_cli" / "main.py"
    if cli.exists():
        text = cli.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(text):
            if "@app.command(" in line:
                name = ""
                if 'name="' in line:
                    name = line.split('name="')[1].split('"')[0]
                else:
                    for follow in text[index : index + 6]:
                        if follow.strip().startswith("def "):
                            name = follow.strip()[4:].split("(")[0]
                            break
                if name:
                    commands.append((name, "qubit-cli"))

    lines = ["# A9 — Public API and CLI surface", "", f"## REST routes ({len(routes)})", ""]
    lines += ["| method | path | defined in |", "|---|---|---|"]
    lines += [f"| {v} | `{p}` | `{m}` |" for v, p, m in sorted(routes, key=lambda r: (r[1], r[0]))]
    lines += [
        "",
        f"## CLI commands ({len(commands)})",
        "",
        "| command | entry point |",
        "|---|---|",
    ]
    lines += [f"| `qubit {n}` | {e} |" for n, e in sorted(commands)]
    (OUT / "tables" / "T_api.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"A9: {len(routes)} REST routes, {len(commands)} CLI commands")


def test_inventory(files: list[Path]) -> None:
    """A10. Inventory from the test files themselves; coverage % from a real `pytest --cov` run.

    `paper_evidence/coverage.json` is produced separately (a quiet machine is not required for
    coverage, only for timing) via:
        uv run pytest packages benchmarks -q --cov=packages \
            --cov-report=json:paper_evidence/coverage.json
    and read here if present. Its absence is reported honestly rather than guessed.
    """
    counts: Counter[str] = Counter()
    total = 0
    for path in files:
        if path.suffix != ".py" or not path.name.startswith("test_"):
            continue
        parts = path.relative_to(ROOT).parts
        area = f"packages/{parts[1]}" if parts[0] == "packages" else parts[0]
        found = sum(
            1
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip().startswith("def test_")
        )
        counts[area] += found
        total += found
    with (OUT / "tables" / "T_tests.csv").open("w", encoding="utf-8", newline="") as fh:
        fh.write("area,test_functions\n")
        for area, n in counts.most_common():
            fh.write(f"{area},{n}\n")

    coverage_path = ROOT / "paper_evidence" / "coverage.json"
    coverage_note = "coverage.json not found; run pytest --cov to produce it"
    if coverage_path.exists():
        totals = json.loads(coverage_path.read_text(encoding="utf-8"))["totals"]
        pct = totals["percent_covered"]
        coverage_note = (
            f"{pct:.1f}% line+branch coverage, {totals['num_statements']} statements, "
            f"{totals['missing_lines']} missing, {totals['num_branches']} branches "
            f"(`uv run pytest packages benchmarks --cov=packages --cov-report=json`)"
        )
        (OUT / "tables" / "T_coverage.md").write_text(
            f"# A10 — Test coverage\n\n{coverage_note}\n", encoding="utf-8"
        )
    print(f"A10: {total} test functions across {len(counts)} areas (declared, not parametrised)")
    print(f"A10: {coverage_note}")


def environment() -> None:
    """A11. Hardware and container digests, so a timing number means something later."""
    lines = ["# A11 — Environment", ""]
    lines.append(f"captured_utc: {datetime.now(UTC).isoformat(timespec='seconds')}")
    lines.append(f"platform: {platform.platform()}")
    lines.append(f"machine: {platform.machine()}")
    lines.append(f"processor: {platform.processor() or 'UNKNOWN'}")
    lines.append(f"python: {platform.python_version()} ({platform.python_implementation()})")

    try:
        import os

        lines.append(f"logical_cpus: {os.cpu_count()}")
    except Exception:
        lines.append("logical_cpus: UNKNOWN")

    for label, command in (
        ("total_memory_bytes", ["powershell", "-NoProfile", "-Command",
                                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory"]),
        ("cpu_name", ["powershell", "-NoProfile", "-Command",
                      "(Get-CimInstance Win32_Processor).Name"]),
    ):  # fmt: skip
        try:
            result = subprocess.run(  # noqa: S603
                command, capture_output=True, text=True, timeout=60, check=False
            )
            lines.append(f"{label}: {result.stdout.strip() or 'UNKNOWN'}")
        except Exception:
            lines.append(f"{label}: UNKNOWN")

    lines += ["", "## Git", ""]
    for label, args in (
        ("commit", ["rev-parse", "HEAD"]),
        ("branch", ["rev-parse", "--abbrev-ref", "HEAD"]),
        ("dirty_files", ["status", "--porcelain"]),
    ):
        try:
            result = subprocess.run(  # noqa: S603
                ["git", *args],  # noqa: S607
                capture_output=True,
                text=True,
                cwd=ROOT,
                timeout=60,
                check=False,
            )
            value = result.stdout.strip()
            lines.append(f"{label}: {len(value.splitlines()) if label == 'dirty_files' else value}")
        except Exception:
            lines.append(f"{label}: UNKNOWN")

    lines += ["", "## Container image digests (benchmark oracles)", ""]
    for image in (
        "qubit-bench-cryptoscan:11f0e46",
        "semgrep/semgrep:latest",
        "sonarqube:community",
        "sonarsource/sonar-scanner-cli:latest",
        "hashicorp/vault:latest",
    ):
        try:
            result = subprocess.run(  # noqa: S603
                ["docker", "image", "inspect", image, "--format", "{{index .RepoDigests 0}}"],  # noqa: S607
                capture_output=True, text=True, timeout=60, check=False,
            )  # fmt: skip
            digest = result.stdout.strip() or result.stderr.strip()[:80] or "UNKNOWN"
            lines.append(f"{image}: {digest}")
        except Exception:
            lines.append(f"{image}: UNKNOWN")

    (OUT / "env" / "hardware.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("A11: hardware.txt written")


def main() -> int:
    files = _iter_files()
    print(f"scanning {len(files)} files under {ROOT}\n")
    modules_and_languages(files)
    dependencies()
    config_surface()
    api_surface()
    test_inventory(files)
    environment()
    print("\nphase 1 complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
