"""LLM patch generation via local Ollama (doc 03 §6.3.2).

The model receives the full source file plus the rule's semantic note and constraints,
and must return the complete rewritten file in a fenced code block. The result is never
trusted blindly: the normal validation pipeline (parse, rescan, git-apply check) gates
every LLM patch exactly like a template patch.
"""

from __future__ import annotations

import ast
import json
import re
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from qubit_core import CryptoAsset

    from .rules import MigrationRule

DEFAULT_BASE_URL = "http://127.0.0.1:11434"

_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.DOTALL)


class OllamaError(Exception):
    """Raised when the local Ollama server fails or returns unusable output."""


def _ollama_generate(
    prompt: str, *, model: str, base_url: str = DEFAULT_BASE_URL, timeout: float = 180.0
) -> str:
    """Single non-streaming completion against the local Ollama server."""
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.0, "num_predict": 4096},
        }
    ).encode("utf-8")
    if not base_url.startswith(("http://", "https://")):
        raise OllamaError(f"Invalid Ollama base URL scheme: {base_url}")
    req = urllib.request.Request(  # noqa: S310 — scheme validated above, local server
        f"{base_url}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            data: dict[str, Any] = json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise OllamaError(f"Ollama unreachable or invalid response: {exc}") from exc
    text = data.get("response", "")
    if not text:
        raise OllamaError("Ollama returned an empty response")
    return text


def _build_prompt(
    source: str, rule: MigrationRule, asset: CryptoAsset, feedback: str | None = None
) -> str:
    constraints = "\n".join(f"- {c}" for c in (rule.prompt_constraints or []))
    return (
        "You are a cryptographic migration codemod engine. Rewrite the file below to "
        "migrate the flagged weak cryptography. Output ONLY the complete rewritten file "
        "inside a single fenced code block. No explanations.\n\n"
        f"Flagged asset: algorithm={asset.algorithm}, usage_context={asset.usage_context.value}, "
        f"line={asset.location.line if asset.location else '?'}\n"
        f"Migration rule: {rule.title}\n"
        f"Guidance: {rule.semantic_note or ''}\n"
        f"Hard constraints:\n{constraints}\n\n"
        # A rule may describe more than one replacement path (py-weakhash-01 offers argon2id for
        # credential hashing and SHA-256 for generic digests). Nothing previously told the model to
        # BRANCH, so with usage_context="unknown" it hedged: qwen2.5-coder produced the correct
        # SHA-256 migration but also emitted a bare `import argon2`, adding an unused, undeclared
        # third-party dependency that raises ModuleNotFoundError wherever argon2-cffi is absent.
        # Making the branch explicit, and banning imports that are not actually used, removes the
        # hedge without constraining which path a rule offers.
        "If the guidance offers more than one replacement path, choose EXACTLY ONE: the path that "
        f"matches usage_context={asset.usage_context.value}. When usage_context is 'unknown', "
        "decide from the surrounding code (does it store or verify a credential, or merely digest "
        "data?) and prefer the general-purpose digest path unless the code clearly handles "
        "credentials.\n"
        "Do NOT add an import for a library you do not actually call in the rewritten file.\n\n"
        "Preserve all unrelated code, imports, comments, and formatting exactly.\n\n"
        f"{_worked_examples(rule)}"
        f"{_repair_feedback(feedback)}"
        f"```{rule.language or ''}\n{source}\n```\n"
    )


def _worked_examples(rule: MigrationRule) -> str:
    """Render the rule's before/after pairs as few-shot demonstrations.

    Every rule file already carries `example: {before, after}` (and some an `example_<path>` for a
    second branch), but none of it ever reached the model — it was documentation only. For a local
    7B-class model a concrete before/after pair is the single strongest signal available, far more
    reliable than prose constraints, so the examples are now part of the prompt.
    """
    pairs: list[tuple[str, dict[str, str]]] = []
    if rule.example:
        pairs.append(("example", rule.example))
    for name, value in sorted(rule.extra_examples.items()):
        pairs.append((name, value))

    rendered: list[str] = []
    for name, pair in pairs:
        before, after = pair.get("before"), pair.get("after")
        if not before or not after:
            continue
        label = name.replace("example_", "").replace("_", " ") or "example"
        lang = rule.language or ""
        rendered.append(
            f"Worked {label} — BEFORE:\n```{lang}\n{before.rstrip()}\n```\n"
            f"Worked {label} — AFTER:\n```{lang}\n{after.rstrip()}\n```\n"
        )
    if not rendered:
        return ""
    return (
        "Follow the transformation shown in these worked examples. They demonstrate the intended "
        "shape of the change, not the file you must edit:\n\n" + "\n".join(rendered) + "\n"
    )


def _repair_feedback(feedback: str | None) -> str:
    """Render the previous attempt's failure so the model can correct it.

    Without this the generator was strictly one-shot: a truncated or unparseable rewrite was simply
    a failed task, even though the specific defect is usually trivial for the model to fix when told
    what it was.
    """
    if not feedback:
        return ""
    return (
        "Your previous attempt was REJECTED for this reason:\n"
        f"  {feedback}\n"
        "Produce a corrected, complete file that does not repeat that mistake.\n\n"
    )


def extract_code_block(text: str) -> str:
    """Pull the rewritten file out of the model output (largest fenced block wins)."""
    blocks = _FENCE_RE.findall(text)
    if not blocks:
        raise OllamaError("Model output contained no fenced code block")
    return max(blocks, key=len)


# A rewrite that loses this much of the original file is treated as truncation/deletion rather than
# a migration. Patches legitimately shrink a little (dropping an import, collapsing a helper), but a
# whole-file rewrite that comes back at 60% of the original has almost certainly dropped code the
# prompt asked it to preserve — and the sandbox cannot catch that in a repo without tests.
_MIN_RETAINED_FRACTION = 0.7

# How many times to re-prompt with the rejection reason before giving up.
_MAX_ATTEMPTS = 3


def check_rewrite(source: str, new_source: str, language: str | None) -> str | None:
    """Return a rejection reason for an LLM rewrite, or None if it looks acceptable.

    These are the CHEAP local checks: they run before the patch is stored and cost nothing, so a
    truncated or unparseable rewrite is caught and re-prompted immediately instead of consuming a
    full sandbox validation run. The sandbox pipeline still gates the result afterwards — this only
    filters out the failures that are obvious without executing anything.
    """
    if not new_source.strip():
        return "the returned file was empty"
    if new_source.strip() == source.strip():
        return "the file came back unchanged — the flagged algorithm was not migrated"

    original_lines = [ln for ln in source.splitlines() if ln.strip()]
    new_lines = [ln for ln in new_source.splitlines() if ln.strip()]
    if original_lines:
        retained = len(new_lines) / len(original_lines)
        if retained < _MIN_RETAINED_FRACTION:
            return (
                f"the returned file has only {len(new_lines)} non-blank lines versus "
                f"{len(original_lines)} in the original, so code was dropped or the output was "
                "truncated; return the COMPLETE file"
            )

    # Python can be parsed for free with the stdlib, which catches truncation mid-statement.
    if (language or "").lower() == "python":
        try:
            ast.parse(new_source)
        except SyntaxError as exc:
            return f"the returned Python file does not parse: {exc.msg} at line {exc.lineno}"

    # Language-agnostic truncation signal: unbalanced brackets almost always means a cut-off file.
    for opener, closer in (("{", "}"), ("(", ")"), ("[", "]")):
        if new_source.count(opener) != new_source.count(closer):
            return (
                f"the returned file has unbalanced '{opener}{closer}' brackets, which means it was "
                "truncated; return the COMPLETE file"
            )
    return None


def generate_llm_source(
    source: str,
    rule: MigrationRule,
    asset: CryptoAsset,
    *,
    model: str,
    base_url: str = DEFAULT_BASE_URL,
    max_attempts: int = _MAX_ATTEMPTS,
) -> str:
    """Return the LLM-rewritten file content, or raise :class:`OllamaError`.

    Retries with the rejection reason fed back into the prompt (doc 03 §6.3's "repair loop", which
    the module previously described but did not implement — generation was strictly one-shot, so a
    truncated rewrite simply failed the task).
    """
    feedback: str | None = None
    last_reason = "unknown"
    for _attempt in range(max(1, max_attempts)):
        raw = _ollama_generate(
            _build_prompt(source, rule, asset, feedback), model=model, base_url=base_url
        )
        try:
            new_source = extract_code_block(raw)
        except OllamaError as exc:
            last_reason = str(exc)
            feedback = f"{last_reason}. Return the whole file inside ONE fenced code block."
            continue

        if not new_source.endswith("\n"):
            new_source += "\n"

        reason = check_rewrite(source, new_source, rule.language)
        if reason is None:
            return new_source
        last_reason = reason
        feedback = reason

    raise OllamaError(f"LLM rewrite rejected after {max_attempts} attempt(s): {last_reason}")


__all__ = [
    "DEFAULT_BASE_URL",
    "OllamaError",
    "check_rewrite",
    "extract_code_block",
    "generate_llm_source",
]
