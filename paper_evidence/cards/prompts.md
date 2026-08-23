# A13 - Prompt templates, verbatim

QUBIT holds no prompt string constants. The prompt is assembled per task by
`packages/qubit-migrate/src/qubit_migrate/transform/llm.py::_build_prompt`, which is reproduced below exactly as the code holds
it. Reproducing the builder rather than a rendered example is deliberate: what a reviewer needs
to check is what is *always* sent, and a single rendered instance would hide the branches.

```python
def _build_prompt(
    source: str, rule: MigrationRule, asset: CryptoAsset, feedback: str | None = None
) -> str:
    language = _prompt_language(rule, asset)
    target_shape = _target_shape_block(rule, language)
    constraints = _scoped_constraints(rule, language, have_target_shape=bool(target_shape))
    return (
        "You are a cryptographic migration codemod engine. Rewrite the file below to "
        "migrate the flagged weak cryptography. Output ONLY the complete rewritten file "
        "inside a single fenced code block. No explanations.\n\n"
        f"Flagged asset: algorithm={asset.algorithm}, usage_context={asset.usage_context.value}, "
        f"line={asset.location.line if asset.location else '?'}\n"
        f"{_attack_note(asset)}"
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
        "Do NOT add an import for a library you do not actually call in the rewritten file.\n"
        # An import left behind for an algorithm no longer called is dead code, and in a language
        # whose rules match import statements it is also still a finding. Measured in Rust it is
        # not: `use rsa::RsaPrivateKey;` alone produces no detection, because the rule matches the
        # keygen call. So this instruction is hygiene, not the fix it was once described as — the
        # rewrites that were failing had removed the old algorithm entirely and were rejected for
        # the opposite reason, that the NEW one could not be found. See `_target_shape_block`.
        "REMOVE any import, use-statement or include that your rewritten file no longer "
        "references. An import for the algorithm you just migrated leaves that algorithm present "
        "in the file, which means the migration did not happen.\n\n"
        "Preserve all unrelated code, comments, and formatting exactly.\n"
        # A file of unrelated crypto calls reads like a list of examples, and the model answered
        # one of them: asked to migrate 3DES in this 15-line file it returned a clean 6-line
        # AES-GCM module and dropped the other nine calls. The truncation guard caught it, but
        # "return the COMPLETE file" as retry feedback did not fix it three attempts running.
        # Stating the size up front makes the requirement one the model can check as it writes,
        # rather than one only the guard can check afterwards.
        f"The file below has {len(source.splitlines())} lines. Your output must contain all of "
        "them, in order, changing only what this migration requires. Do not summarise, "
        "reorganise, or drop code unrelated to the flagged algorithm.\n\n"
        f"{target_shape}"
        f"{_worked_examples(rule, language)}"
        f"{_repair_feedback(feedback)}"
        f"```{language}\n{source}\n```\n"
    )


# Suffixes of `example_*` keys that name a LANGUAGE rather than a replacement branch. Derived from
# the shared table so a rule can carry `example_ruby` / `example_swift` and have it recognised —
# a hardcoded list would silently treat those as replacement branches and render them for every
# language at once.
_EXAMPLE_LANGUAGES = frozenset(SUFFIX_TO_LANGUAGE.values())

# Every name any supported language answers to. Derived from the shared suffix map and the
# alias table rather than listed here, so a language added to the scanner is recognised in
# rule guidance without a second edit — the drift that put Go's API into a Rust prompt.
_ALL_LANGUAGE_NAMES = frozenset(
    name for lang in _EXAMPLE_LANGUAGES for name in language_aliases(lang)
)
```

## Decoding parameters

| parameter | value |
|---|---|
| temperature | 0.0 |
| num_predict | computed per call by `_output_budget(prompt)` |
| top_p, stop | not set (server defaults) |
| seed | not pinned - see GAPS |

