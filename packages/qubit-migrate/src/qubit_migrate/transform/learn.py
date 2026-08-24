"""Learned patches management (M3)"""

from qubit_core.db.models import LearnedPatch
from sqlalchemy.orm import Session


def record_learned_patch(
    session: Session,
    rule_id: str,
    language: str,
    source_pattern: str,
    replacement: str,
    validation_score: float = 1.0,
) -> LearnedPatch:
    patch = LearnedPatch(
        rule_id=rule_id,
        language=language,
        source_pattern=source_pattern,
        replacement=replacement,
        validation_score=validation_score,
    )
    session.add(patch)
    session.commit()
    return patch

def get_experience_for_rule(
    session: Session, rule_id: str, language: str, limit: int = 3
) -> list[tuple[str, str]]:
    patches = (
        session.query(LearnedPatch)
        .filter_by(rule_id=rule_id, language=language)
        .order_by(LearnedPatch.validation_score.desc(), LearnedPatch.created_at.desc())
        .limit(limit)
        .all()
    )
    return [(p.source_pattern, p.replacement) for p in patches]
