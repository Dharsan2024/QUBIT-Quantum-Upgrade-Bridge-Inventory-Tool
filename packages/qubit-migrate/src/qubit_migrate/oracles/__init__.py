"""Behavioural oracles for migrated cryptography — the `behaves` validation stage.

Every gate before this one asks a question about the *text* of a patch. `applies`
asks whether the diff is well formed, `parses` whether the result is syntactically
valid, `symbols` whether names resolve, `compiles` whether the module loads, and
`rescan` whether the scanner's opinion of the file changed. A patch can satisfy
all five while having reused a nonce, dropped an authentication tag, or replaced a
signature check with something that returns ``True``.

This module asks a different question: **does the cryptography the patch installed
actually work, and does it fail when it should?**

The technique is metamorphic testing, which exists precisely for the oracle
problem -- validating software when the correct output for a given input cannot be
known in advance. It is established for testing a single static cryptographic
*implementation*. Using metamorphic relations as the **acceptance oracle for an
automated migration** is, across two independent literature surveys, unoccupied.

The move is to treat the primitive itself as the transformation variable: if a
workflow authenticated a payload under ECDSA, then rewriting it to ML-DSA must
preserve the authentication outcome, even though every intermediate byte, buffer
size and API signature has changed.

Why this earns its place over the project's own test suite: it needs no project
dependencies, no coverage, and no maintainer-written tests. It is therefore
available for EVERY finding rather than the subset a maintainer happened to
exercise -- which is what makes it the strongest claim that is universally
obtainable, and why the evidence ladder puts it at L3 below the project suite at
L4 while building it first.

Specification: ``qubit-v2/02-verification/``.
"""

from __future__ import annotations

from .relations import Relation, RelationSet, relations_for

__all__ = ["Relation", "RelationSet", "relations_for"]
