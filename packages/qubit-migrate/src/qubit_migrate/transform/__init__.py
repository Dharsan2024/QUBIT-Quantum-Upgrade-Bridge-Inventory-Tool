"""qubit-migrate transform subpackage."""

from .codemods import file_sha256, run_codemod
from .diffing import (
    EditApplyError,
    apply_edits,
    detect_line_ending,
    git_apply_check,
    old_new_to_diff,
    restore_incidental_blank_lines,
    sha256_of,
)
from .rules import MigrationRule, load_rules, match_rule
from .validate import StageResult, ValidationReport, validate_patch

__all__ = [
    "EditApplyError",
    "MigrationRule",
    "StageResult",
    "ValidationReport",
    "apply_edits",
    "detect_line_ending",
    "file_sha256",
    "git_apply_check",
    "load_rules",
    "match_rule",
    "old_new_to_diff",
    "restore_incidental_blank_lines",
    "run_codemod",
    "sha256_of",
    "validate_patch",
]
