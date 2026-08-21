"""LLM patch generation via local Ollama (doc 03 §6.3.2).

The model receives the full source file plus the rule's semantic note and constraints,
and must return the complete rewritten file in a fenced code block. The result is never
trusted blindly: the normal validation pipeline (parse, rescan, git-apply check) gates
every LLM patch exactly like a template patch.
"""

from __future__ import annotations

import ast
import json
import logging
import re
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .languages import SUFFIX_TO_LANGUAGE, parse_error
from .rules import MigrationRule

if TYPE_CHECKING:
    from qubit_core import CryptoAsset

logger = logging.getLogger(__name__)

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
    except urllib.error.HTTPError as exc:
        # Ollama answers 404 for a model it does not have pulled. Reporting that as "unreachable"
        # sends the user to check a server that is running perfectly well, so name the real problem
        # and the command that fixes it.
        if exc.code == 404:
            raise OllamaError(_model_missing_message(model, base_url)) from exc
        raise OllamaError(f"Ollama returned HTTP {exc.code}: {exc.reason}") from exc
    except TimeoutError as exc:
        # A timeout is NOT "unreachable", and telling the user to start a server that is already
        # running sends them the wrong way. Measured: gemma4:12b exceeded the 180 s default on this
        # machine for a two-line Rust file, while the 7B coder model answered the same prompt in
        # 7.5 s. Model size is the usual cause, so name it.
        raise OllamaError(
            f"the model {model!r} did not answer within {timeout:.0f}s. A larger model needs more "
            f"time on this machine — raise QUBIT_MIGRATE_LLM_TIMEOUT, or use a smaller one."
        ) from exc
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        # urllib wraps a socket timeout in URLError, so unwrap before blaming reachability.
        if isinstance(getattr(exc, "reason", None), (TimeoutError, socket.timeout)):
            raise OllamaError(
                f"the model {model!r} did not answer within {timeout:.0f}s. A larger model needs "
                "more time on this machine — raise QUBIT_MIGRATE_LLM_TIMEOUT, or use a smaller "
                "one."
            ) from exc
        raise OllamaError(
            f"Ollama is not reachable at {base_url}: {exc}. Start it with `ollama serve`."
        ) from exc
    text = data.get("response", "")
    if not text:
        raise OllamaError("Ollama returned an empty response")
    return text


def installed_models(base_url: str = DEFAULT_BASE_URL) -> list[str]:
    """Model tags the local Ollama server actually has pulled, or [] if it cannot be asked."""
    try:
        with urllib.request.urlopen(f"{base_url}/api/tags", timeout=5) as resp:  # noqa: S310
            payload: dict[str, Any] = json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return []
    return [str(m.get("name", "")) for m in payload.get("models", []) if m.get("name")]


def _model_missing_message(model: str, base_url: str) -> str:
    available = installed_models(base_url)
    if available:
        have = ", ".join(sorted(available))
        return (
            f"the model {model!r} is not installed in Ollama. Installed: {have}. "
            f"Pull it with: ollama pull {model}"
        )
    return (
        f"the model {model!r} is not installed in Ollama, and no models are. "
        f"Pull one with: ollama pull {model}"
    )


def _build_prompt(
    source: str, rule: MigrationRule, asset: CryptoAsset, feedback: str | None = None
) -> str:
    constraints = "\n".join(f"- {c}" for c in (rule.prompt_constraints or []))
    language = _prompt_language(rule, asset)
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
        f"{_worked_examples(rule, language)}"
        f"{_repair_feedback(feedback)}"
        f"```{language}\n{source}\n```\n"
    )


# Suffixes of `example_*` keys that name a LANGUAGE rather than a replacement branch. Derived from
# the shared table so a rule can carry `example_ruby` / `example_swift` and have it recognised —
# a hardcoded list would silently treat those as replacement branches and render them for every
# language at once.
_EXAMPLE_LANGUAGES = frozenset(SUFFIX_TO_LANGUAGE.values())


def _prompt_language(rule: MigrationRule, asset: CryptoAsset) -> str:
    """The language to label code fences with, and to pick worked examples for.

    A cross-language rule declares `language: multi`, so labelling the prompt's fences with
    `rule.language` told the model the file was written in "multi". The file's extension is the real
    answer.
    """
    path = asset.location.file_path if asset.location else None
    if path:
        derived = SUFFIX_TO_LANGUAGE.get(Path(path).suffix.lower())
        if derived is not None:
            return derived
    return rule.language or ""


def _primary_example_language(rule: MigrationRule) -> str:
    """The language the rule's unlabelled `example:` block is written in.

    A single-language rule (`language: python`) states it directly. A cross-language rule declares
    `multi`, and its primary example is written in whichever language the author reached for —
    recorded as `example_language:` in the rule so it is stated rather than guessed. Without that,
    the primary example was attached to files in every other language too.
    """
    declared = getattr(rule, "example_language", None)
    if declared:
        return str(declared).lower()
    if rule.language and rule.language.lower() != "multi":
        return rule.language.lower()
    return ""


def _worked_examples(rule: MigrationRule, language: str = "") -> str:
    """Render the rule's before/after pairs as few-shot demonstrations.

    Every rule file already carries `example: {before, after}` (and some an `example_<path>` for a
    second branch), but none of it ever reached the model — it was documentation only. For a local
    7B-class model a concrete before/after pair is the single strongest signal available, far more
    reliable than prose constraints, so the examples are now part of the prompt.

    Cross-language rules carry one example PER LANGUAGE (`example_java`, `example_c`, …). Rendering
    all of them meant a Go file arrived with Java, JavaScript and C demonstrations attached — three
    quarters of the prompt's strongest signal pointing at the wrong language, which invites a 7B
    model to mix idioms. Only the matching language's example is included.

    An `example_*` key whose suffix is NOT a language names a replacement BRANCH instead
    (`example_generic_digest` on py-weakhash-01) and is always kept: those demonstrate a choice the
    rule offers rather than a language.
    """
    lang = (language or rule.language or "").lower()
    language_specific = {
        name.replace("example_", "").lower(): (name, value)
        for name, value in rule.extra_examples.items()
        if name.replace("example_", "").lower() in _EXAMPLE_LANGUAGES
    }

    pairs: list[tuple[str, dict[str, str]]] = []
    match = language_specific.get(lang)
    if match is not None:
        # This language has its own example, so the primary belongs to a different one — drop it.
        pairs.append(match)
    elif rule.example and _primary_example_language(rule) == lang:
        pairs.append(("example", rule.example))
    # Otherwise: NO example. Attaching one written in another language is worse than attaching
    # none — measured, the 7B model returned the example's language verbatim for 3 of 4 files.
    # The prose constraints and the target algorithm still reach the model.

    for name, value in sorted(rule.extra_examples.items()):
        if name.replace("example_", "").lower() in _EXAMPLE_LANGUAGES:
            continue  # handled above; other languages are noise
        pairs.append((name, value))

    rendered: list[str] = []
    for name, pair in pairs:
        before, after = pair.get("before"), pair.get("after")
        if not before or not after:
            continue
        label = name.replace("example_", "").replace("_", " ") or "example"
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

    # Did it come back in the RIGHT LANGUAGE? Measured against the real 7B model, the most common
    # failure was not truncation but the model returning the worked example's language: a Ruby file
    # came back as Go, a Kotlin file as Python. Parsing the result under the file's own grammar
    # catches that in the repair loop, where the reason can be fed back, instead of letting it reach
    # the sandbox as a wasted attempt.
    lang = (language or "").lower()
    if lang and lang != "multi":
        problem = parse_error(new_source, lang)
        # Only blame the rewrite for an error the ORIGINAL did not already have. A file the grammar
        # cannot fully parse (SQL with `:name` bind parameters) would otherwise burn every repair
        # attempt on a defect the model did not introduce and cannot remove.
        if problem is not None and parse_error(source, lang) is None:
            return (
                f"the returned file {problem}. The file you must edit is written in {lang} — "
                f"return {lang}, not any other language, and change only the flagged algorithm"
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
    fallback_model: str | None = None,
    timeout: float = 180.0,
) -> str:
    """Return the LLM-rewritten file content, or raise :class:`OllamaError`.

    Retries with the rejection reason fed back into the prompt (doc 03 §6.3's "repair loop", which
    the module previously described but did not implement — generation was strictly one-shot, so a
    truncated rewrite simply failed the task).
    """
    # `fallback_model` was configured and referenced by nothing, so a machine without the primary
    # model pulled had no safety net at all — just a 404 reported as "Ollama unreachable". It is
    # only used when the primary is genuinely absent, never to silently downgrade a working setup.
    available = installed_models(base_url)
    if available and model not in available:
        if fallback_model and fallback_model in available:
            logger.warning(
                "Ollama model %r is not installed; falling back to %r", model, fallback_model
            )
            model = fallback_model
        else:
            raise OllamaError(_model_missing_message(model, base_url))

    feedback: str | None = None
    last_reason = "unknown"
    for _attempt in range(max(1, max_attempts)):
        raw = _ollama_generate(
            _build_prompt(source, rule, asset, feedback),
            model=model,
            base_url=base_url,
            timeout=timeout,
        )
        try:
            new_source = extract_code_block(raw)
        except OllamaError as exc:
            last_reason = str(exc)
            feedback = f"{last_reason}. Return the whole file inside ONE fenced code block."
            continue

        if not new_source.endswith("\n"):
            new_source += "\n"

        # The FILE's language, not the rule's: a cross-language rule says "multi", which
        # matches no grammar and skipped every language-aware check in the guard.
        reason = check_rewrite(source, new_source, _prompt_language(rule, asset))
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
    "installed_models",
]
