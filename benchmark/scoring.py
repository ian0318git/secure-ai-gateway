"""Greedy one-to-one span scoring (BENCHMARK.md §4, normative).

- Format entities: TP requires the SAME type and an EXACT span match.
- NER entities: TP requires the SAME type and >= 1 char overlap;
  IoU >= 0.5 is reported as a secondary metric (never affects
  acceptance).
- Predictions are processed in descending confidence order; each
  prediction matches at most one ground-truth span and vice versa.
  A prediction matching no same-type span is an FP; an unmatched
  ground-truth span is an FN (cross-type matches get NO credit —
  BENCHMARK.md §4.3).
- A prediction on a negative record (no ground truth) is an FP.
- Aggregate = micro sum over all classes (§4.5).
"""

from __future__ import annotations

from collections import defaultdict

from benchmark.generate import GroundTruthSpan
from secure_ai_gateway.models import DetectionSpan, EntityType

# BENCHMARK.md §4.1
FORMAT_TYPES = frozenset(
    {
        EntityType.EMAIL,
        EntityType.PHONE,
        EntityType.TW_ID,
        EntityType.CREDIT_CARD,
        EntityType.API_KEY,
        EntityType.JWT,
        EntityType.PRIVATE_KEY,
        EntityType.PASSWORD,
        EntityType.SECRET,
        EntityType.BANK_ACCOUNT,
        EntityType.CUSTOMER_ID,
        EntityType.EMPLOYEE_ID,
        EntityType.TOKEN_PATTERN,
    }
)
NER_TYPES = frozenset(
    {
        EntityType.PERSON,
        EntityType.ADDRESS,
        EntityType.LOCATION,
        EntityType.ORGANIZATION,
        EntityType.COMPANY_NAME,
    }
)


class EntityScores:
    """Mutable per-entity counters (TP / FP / FN + IoU pairs)."""

    def __init__(self) -> None:
        self.tp = 0
        self.fp = 0
        self.fn = 0
        self.iou_pairs: list[tuple[float, float, float, float]] = []

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        if p + r == 0.0:
            return 0.0
        return 2 * p * r / (p + r)

    def ioU_ge_0_5(self) -> float:
        if not self.iou_pairs:
            return 0.0
        hits = sum(1 for _, _, iou, _ in self.iou_pairs if iou >= 0.5)
        return hits / len(self.iou_pairs)

    def merge(self, other: "EntityScores") -> None:
        self.tp += other.tp
        self.fp += other.fp
        self.fn += other.fn
        self.iou_pairs.extend(other.iou_pairs)


def _matches(
    pred: DetectionSpan, gt: GroundTruthSpan
) -> tuple[bool, tuple[float, float, float]]:
    """(matches, quality) — quality is a deterministically ordered tuple:
    (exactness class, IoU). Format entities must be exact; NER entities
    need >= 1 char overlap."""
    if pred.entity_type is not gt.entity_type:
        return False, (0.0, 0.0, 0.0)
    if pred.entity_type in FORMAT_TYPES:
        if pred.start != gt.start or pred.end != gt.end:
            return False, (0.0, 0.0, 0.0)
        return True, (3.0, 1.0, 0.0)
    inter = min(pred.end, gt.end) - max(pred.start, gt.start)
    if inter <= 0:
        return False, (0.0, 0.0, 0.0)
    union = max(pred.end, gt.end) - min(pred.start, gt.start)
    iou = inter / union if union else 0.0
    exact = pred.start == gt.start and pred.end == gt.end
    return True, (2.0 if exact else 1.0, iou, -abs(pred.start - gt.start))


def score_cell(
    gt_spans: tuple[GroundTruthSpan, ...],
    pred_spans: tuple[DetectionSpan, ...],
    out: dict[EntityType, EntityScores],
) -> None:
    """Score one cell's predictions against its ground truth in place."""
    gt_sorted = sorted(
        gt_spans, key=lambda g: (g.start, g.end, g.entity_type.value)
    )
    pred_sorted = sorted(
        pred_spans,
        key=lambda p: (-p.score, p.start, p.end, p.entity_type.value),
    )
    used = [False] * len(gt_sorted)
    for pred in pred_sorted:
        best_index = None
        best_quality: tuple[float, float, float] | None = None
        for i, gt in enumerate(gt_sorted):
            if used[i]:
                continue
            matched, quality = _matches(pred, gt)
            if matched and (best_quality is None or quality > best_quality):
                best_quality = quality
                best_index = i
        entity = pred.entity_type
        if best_index is not None:
            used[best_index] = True
            out[entity].tp += 1
            if entity in NER_TYPES:
                gt = gt_sorted[best_index]
                inter = min(pred.end, gt.end) - max(pred.start, gt.start)
                union = max(pred.end, gt.end) - min(pred.start, gt.start)
                iou = inter / union if union else 0.0
                out[entity].iou_pairs.append(
                    (pred.start, pred.end, iou, iou >= 0.5)
                )
        else:
            out[entity].fp += 1
    for i, gt in enumerate(gt_sorted):
        if not used[i]:
            out[gt.entity_type].fn += 1


def aggregate(
    scores: dict[EntityType, EntityScores],
) -> EntityScores:
    """Micro-aggregate across all entity types (§4.5)."""
    total = EntityScores()
    for entity_scores in scores.values():
        total.merge(entity_scores)
    return total
