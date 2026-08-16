"""Scoring rules (BENCHMARK.md §4) on hand-crafted mini-cases."""

from __future__ import annotations

from collections import defaultdict

from benchmark.generate import GroundTruthSpan
from benchmark.scoring import EntityScores, aggregate, score_cell
from secure_ai_gateway.models import DetectionSpan, EntityType, SpanSource

PERSON = EntityType.PERSON
PHONE = EntityType.PHONE
TW_ID = EntityType.TW_ID
LOCATION = EntityType.LOCATION


def _gt(start: int, end: int, entity: EntityType) -> GroundTruthSpan:
    return GroundTruthSpan(start, end, entity)


def _pred(
    start: int, end: int, entity: EntityType, score: float = 0.9
) -> DetectionSpan:
    return DetectionSpan(entity, start, end, score, SpanSource.PATTERN, "x")


def _score(
    gt_spans: tuple[GroundTruthSpan, ...], preds: tuple[DetectionSpan, ...]
) -> tuple[EntityScores, dict[EntityType, EntityScores]]:
    per: dict[EntityType, EntityScores] = defaultdict(EntityScores)
    score_cell(gt_spans, preds, per)
    return aggregate(per), per


class TestFormatEntities:
    def test_exact_match_is_tp(self) -> None:
        agg, _ = _score((_gt(0, 10, PHONE),), (_pred(0, 10, PHONE),))
        assert (agg.tp, agg.fp, agg.fn) == (1, 0, 0)

    def test_offset_span_is_fp_and_fn(self) -> None:
        """Format entities require an EXACT span (§4.2)."""
        agg, _ = _score((_gt(0, 10, PHONE),), (_pred(1, 11, PHONE),))
        assert (agg.tp, agg.fp, agg.fn) == (0, 1, 1)

    def test_wrong_type_is_fp_and_fn(self) -> None:
        """No cross-type credit (§4.3)."""
        agg, _ = _score((_gt(0, 10, PHONE),), (_pred(0, 10, TW_ID),))
        assert (agg.tp, agg.fp, agg.fn) == (0, 1, 1)

    def test_negative_cell_prediction_is_fp(self) -> None:
        """Any prediction on a negative record is an FP (§4.4)."""
        agg, _ = _score((), (_pred(0, 3, PERSON),))
        assert (agg.tp, agg.fp, agg.fn) == (0, 1, 0)


class TestNerEntities:
    def test_overlap_is_tp(self) -> None:
        """NER entities: >= 1 char overlap suffices (§4.2)."""
        agg, _ = _score((_gt(2, 5, PERSON),), (_pred(3, 6, PERSON),))
        assert (agg.tp, agg.fp, agg.fn) == (1, 0, 0)

    def test_contained_prediction_is_tp(self) -> None:
        agg, _ = _score((_gt(0, 5, PERSON),), (_pred(1, 4, PERSON),))
        assert (agg.tp, agg.fp, agg.fn) == (1, 0, 0)

    def test_non_overlapping_is_fp_and_fn(self) -> None:
        agg, _ = _score((_gt(0, 2, PERSON),), (_pred(5, 8, PERSON),))
        assert (agg.tp, agg.fp, agg.fn) == (0, 1, 1)

    def test_iou_reported_but_acceptance_irrelevant(self) -> None:
        """IoU >= 0.5 is a secondary metric (§4.2)."""
        _, per = _score((_gt(0, 10, PERSON),), (_pred(3, 13, PERSON),))
        # IoU = 7/13 ≈ 0.54 >= 0.5
        assert per[PERSON].ioU_ge_0_5() == 1.0

        _, per2 = _score((_gt(0, 10, PERSON),), (_pred(8, 18, PERSON),))
        # IoU = 2/18 ≈ 0.11 — still a TP, but IoU metric < 0.5
        assert per2[PERSON].tp == 1
        assert per2[PERSON].ioU_ge_0_5() == 0.0


class TestMatchingProcedure:
    def test_greedy_one_to_one_highest_confidence_first(self) -> None:
        """Two predictions, one ground truth: only the best matches (§4.3)."""
        agg, _ = _score(
            (_gt(0, 3, PERSON),),
            (_pred(0, 3, PERSON, score=0.5), _pred(0, 3, PERSON, score=0.9)),
        )
        assert (agg.tp, agg.fp, agg.fn) == (1, 1, 0)

    def test_each_gt_matches_at_most_one_prediction(self) -> None:
        agg, _ = _score(
            (_gt(0, 3, PERSON),),
            (_pred(0, 3, PERSON, score=0.9), _pred(0, 3, PERSON, score=0.8)),
        )
        assert (agg.tp, agg.fp, agg.fn) == (1, 1, 0)

    def test_two_entities_one_cell(self) -> None:
        """PERSON + PHONE in one cell: both score independently."""
        agg, _ = _score(
            (_gt(0, 3, PERSON), _gt(5, 15, PHONE)),
            (_pred(0, 3, PERSON), _pred(5, 15, PHONE)),
        )
        assert (agg.tp, agg.fp, agg.fn) == (2, 0, 0)

    def test_family_type_mismatch_gets_no_credit(self) -> None:
        """LOCATION vs ADDRESS are different types for scoring."""
        agg, _ = _score(
            (_gt(0, 9, EntityType.ADDRESS),), (_pred(0, 9, LOCATION),)
        )
        assert (agg.tp, agg.fp, agg.fn) == (0, 1, 1)


class TestAggregate:
    def test_micro_sum_across_types(self) -> None:
        """§4.5: micro-aggregate sums TP/FP/FN across classes."""
        per: dict[EntityType, EntityScores] = defaultdict(EntityScores)
        score_cell((_gt(0, 3, PERSON),), (_pred(0, 3, PERSON),), per)
        score_cell((), (_pred(0, 3, PERSON),), per)  # negative -> FP
        agg = aggregate(per)
        assert (agg.tp, agg.fp, agg.fn) == (1, 1, 0)
        assert agg.precision == 0.5
        assert agg.recall == 1.0

    def test_f1_harmonic_mean(self) -> None:
        scores = EntityScores()
        scores.tp = 90
        scores.fp = 10
        scores.fn = 10
        assert scores.precision == 0.9
        assert scores.recall == 0.9
        assert abs(scores.f1 - 0.9) < 1e-9
