"""Overlapping-span resolution (deterministic, before thresholding).

Presidio returns overlapping spans (allow_overlap=True). Rules:

1. Same entity type overlapping -> keep the highest-score span.
   (Two same-type predictions over one ground-truth span would
   otherwise produce one TP and one FP — BENCHMARK.md §4.3 greedy
   matching.)
2. Same semantic family, different types -> keep the more specific:
   - COMPANY_NAME (suffix pattern) beats ORGANIZATION (NER ORG);
   - ADDRESS (skeleton pattern) beats LOCATION (NER GPE/LOC) and
     PERSON (the zh NER mislabels address components such as 羅東鎮 /
     員林鎮 as PERSON — benchmark-measured, docs/DECISIONS.md);
   - PHONE (format pattern) beats BANK_ACCOUNT (a bare digit run in
     a phone cell is a phone number, not an account — measured);
   - TOKEN_PATTERN beats CUSTOMER_ID / EMPLOYEE_ID (the reserved
     token format is more specific than a generic ID prefix).
3. Different families overlapping -> both kept (e.g. a PERSON inside
   a COMPANY_NAME span).
"""

from __future__ import annotations

from secure_ai_gateway.models import DetectionSpan, EntityType

# Semantic families: more specific type listed first wins.
_FAMILIES: dict[EntityType, tuple[EntityType, ...]] = {
    EntityType.COMPANY_NAME: (EntityType.COMPANY_NAME, EntityType.ORGANIZATION),
    EntityType.ADDRESS: (
        EntityType.ADDRESS,
        EntityType.LOCATION,
        EntityType.PERSON,
    ),
    EntityType.PHONE: (EntityType.PHONE, EntityType.BANK_ACCOUNT),
    EntityType.TOKEN_PATTERN: (
        EntityType.TOKEN_PATTERN,
        EntityType.CUSTOMER_ID,
        EntityType.EMPLOYEE_ID,
    ),
}


def _overlaps(a: DetectionSpan, b: DetectionSpan) -> bool:
    return a.start < b.end and b.start < a.end


def _family_priority(a: DetectionSpan, b: DetectionSpan) -> DetectionSpan:
    """Pick the winner when two overlapping spans are in one family."""
    for leader, members in _FAMILIES.items():
        if a.entity_type in members and b.entity_type in members:
            if a.entity_type is leader and b.entity_type is not leader:
                return a
            if b.entity_type is leader and a.entity_type is not leader:
                return b
            return a if a.score >= b.score else b
    return a  # different families: keep both (handled by caller)


def resolve_overlaps(spans: tuple[DetectionSpan, ...]) -> tuple[DetectionSpan, ...]:
    """Resolve overlapping spans into a non-ambiguous prediction set."""
    kept: list[DetectionSpan] = []
    for candidate in sorted(spans, key=lambda s: (s.start, -s.end, -s.score)):
        absorbed = False
        for i, existing in enumerate(kept):
            if not _overlaps(existing, candidate):
                continue
            if existing.entity_type == candidate.entity_type:
                # same type: keep the higher score, drop the other
                if candidate.score > existing.score:
                    kept[i] = candidate
                absorbed = True
                break
            family_of_candidate = next(
                (
                    members
                    for members in _FAMILIES.values()
                    if candidate.entity_type in members
                    and existing.entity_type in members
                ),
                None,
            )
            if family_of_candidate is not None:
                kept[i] = _family_priority(existing, candidate)
                absorbed = True
                break
            # different families: keep both (no absorb)
        if not absorbed:
            kept.append(candidate)
    return tuple(sorted(kept, key=lambda s: (s.start, s.end, s.entity_type.value)))
