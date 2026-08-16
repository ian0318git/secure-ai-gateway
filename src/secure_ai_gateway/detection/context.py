"""Column-header context boost (replaces presidio's lemma enhancer).

spaCy Chinese has no lemmas, so presidio's LemmaContextAwareEnhancer
cannot boost scores by context words (docs/DECISIONS.md). Instead,
deterministic column-header keywords raise the score of
pattern/fallback spans that landed in that column.

Boosts apply ONLY to pattern and fallback spans (NER spans are already
confident). Cap at 0.95 so no span can reach certainty by context
alone.
"""

from __future__ import annotations

from secure_ai_gateway.models import DetectionSpan, EntityType, SpanSource

BOOST = 0.2
CAP = 0.95

_COLUMN_CONTEXT: dict[EntityType, tuple[str, ...]] = {
    EntityType.PERSON: (
        "客戶", "姓名", "名字", "負責人", "聯絡人", "員工", "業務", "會計",
        "出納", "人員", "name", "customer", "contact",
    ),
    EntityType.ADDRESS: ("地址", "住址", "通訊", "address", "addr"),
    EntityType.PHONE: ("電話", "手機", "phone", "tel", "mobile"),
    EntityType.EMAIL: ("email", "mail", "信箱", "電子郵件"),
    EntityType.TW_ID: ("身份證", "身分證", "id", "證號", "idnumber"),
    EntityType.BANK_ACCOUNT: ("帳號", "帳戶", "戶號", "銀行", "account"),
    EntityType.CUSTOMER_ID: ("客戶編號", "客戶id", "客戶號", "customer"),
    EntityType.EMPLOYEE_ID: ("員工編號", "員工id", "employee"),
    EntityType.COMPANY_NAME: ("公司", "客戶", "廠商", "供應商", "company", "vendor"),
}


def boosted_spans(
    column: str,
    spans: tuple[DetectionSpan, ...],
    boost: float = BOOST,
    cap: float = CAP,
) -> tuple[DetectionSpan, ...]:
    """Return spans with a score boost when their type matches the
    column-header keywords. Keyword matching is NFKC-normalised
    lowercase substring search on the column label."""
    if not column:
        return spans
    lowered = column.lower()
    result: list[DetectionSpan] = []
    for span in spans:
        if span.source is SpanSource.NER:
            result.append(span)
            continue
        keywords = _COLUMN_CONTEXT.get(span.entity_type, ())
        if any(kw in lowered for kw in keywords):
            result.append(
                DetectionSpan(
                    entity_type=span.entity_type,
                    start=span.start,
                    end=span.end,
                    score=min(cap, span.score + boost),
                    source=span.source,
                    raw_value=span.raw_value,
                    checksum_valid=span.checksum_valid,
                )
            )
        else:
            result.append(span)
    return tuple(result)
