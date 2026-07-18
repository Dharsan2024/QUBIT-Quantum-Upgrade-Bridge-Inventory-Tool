"""LLM patch generation via local Ollama (doc 03 §6.3.2).

The model receives the full source file plus the rule's semantic note and constraints,
and must return the complete rewritten file in a fenced code block. The result is never
trusted blindly: the normal validation pipeline (parse, rescan, git-apply check) gates
every LLM patch exactly like a template patch.
"""

from __future__ import annotations

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


def _build_prompt(source: str, rule: MigrationRule, asset: CryptoAsset) -> str:
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
        "Preserve all unrelated code, imports, comments, and formatting exactly.\n\n"
        f"```{rule.language or ''}\n{source}\n```\n"
    )


def extract_code_block(text: str) -> str:
    """Pull the rewritten file out of the model output (largest fenced block wins)."""
    blocks = _FENCE_RE.findall(text)
    if not blocks:
        raise OllamaError("Model output contained no fenced code block")
    return max(blocks, key=len)


def generate_llm_source(
    source: str,
    rule: MigrationRule,
    asset: CryptoAsset,
    *,
    model: str,
    base_url: str = DEFAULT_BASE_URL,
) -> str:
    """Return the LLM-rewritten file content, or raise :class:`OllamaError`."""
    raw = _ollama_generate(_build_prompt(source, rule, asset), model=model, base_url=base_url)
    new_source = extract_code_block(raw)
    if not new_source.endswith("\n"):
        new_source += "\n"
    if new_source.strip() == source.strip():
        raise OllamaError("Model returned the file unchanged")
    return new_source


__all__ = ["DEFAULT_BASE_URL", "OllamaError", "extract_code_block", "generate_llm_source"]
