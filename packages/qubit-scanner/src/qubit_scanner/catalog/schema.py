"""The ``qubit-rule/v1`` catalog format — detection rules are DATA, not code.

A new "detect RSA keygen in Go" rule is a YAML file plus embedded test snippets; zero Python
changes. This module is the Pydantic contract those YAML files must satisfy (``qubit rules lint``
validates against it).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class WhereFilter(BaseModel):
    """A cheap post-filter on a captured node's text."""

    model_config = ConfigDict(populate_by_name=True)

    capture: str
    equals: str | None = None
    in_: list[str] | None = Field(default=None, alias="in")
    regex: str | None = None


class Extractor(BaseModel):
    """How to pull a value (algorithm / key_size) out of the match.

    ``literal``: fixed value from the rule. Otherwise ``from`` names a capture and ``resolve`` says
    how to read it: ``capture-text`` (the node's text), ``string-literal`` (strip quotes),
    ``string-constant`` (fold a local string assignment), ``int-literal`` (parse an int).
    """

    model_config = ConfigDict(populate_by_name=True)

    literal: str | None = None
    from_: str | None = Field(default=None, alias="from")
    resolve: str = "literal"


class RuleMatch(BaseModel):
    query: str  # verbatim tree-sitter S-expression query for the grammar
    where: list[WhereFilter] = Field(default_factory=list)


class RuleAsset(BaseModel):
    asset_type: str = "algorithm-use"
    usage_context: str = "unknown"


class RuleExamples(BaseModel):
    positive: list[str] = Field(default_factory=list)
    negative: list[str] = Field(default_factory=list)


class Rule(BaseModel):
    id: str
    title: str = ""
    match: RuleMatch
    extract: dict[str, Extractor]  # must contain "algorithm"; may contain "key_size"
    asset: RuleAsset = Field(default_factory=RuleAsset)
    confidence: str = "high"
    examples: RuleExamples = Field(default_factory=RuleExamples)


class LibrarySpec(BaseModel):
    name: str
    detect_imports: list[str] = Field(default_factory=list)


class RuleFile(BaseModel):
    """One YAML file = one (language, library) rule pack."""

    model_config = ConfigDict(populate_by_name=True)

    schema_: str = Field(default="qubit-rule/v1", alias="schema")
    language: str
    library: LibrarySpec
    rules: list[Rule]


__all__ = [
    "Extractor",
    "LibrarySpec",
    "Rule",
    "RuleAsset",
    "RuleExamples",
    "RuleFile",
    "RuleMatch",
    "WhereFilter",
]
