"""Detection engine tests: stub analyzer, thresholds, resolution,
context boost, TW_ID checksum flag, zh-only guard (T-I01).

The real zh AnalyzerEngine (575MB model) is NOT loaded here; the stub
answers ``analyze()`` with canned presidio ``RecognizerResult``s, so
engine behaviour is tested without the model (benchmark exercises the
real engine).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from presidio_analyzer.recognizer_result import RecognizerResult

from secure_ai_gateway.detection.context import boosted_spans
from secure_ai_gateway.detection.engine import DetectionEngine
from secure_ai_gateway.detection.resolution import resolve_overlaps
from secure_ai_gateway.errors import DetectionError
from secure_ai_gateway.models import (
    DetectionSpan,
    DocumentCell,
    EntityType,
    SpanSource,
)

# A known checksum-VALID ROC ID (weights 8..1,1 over digits
# 1..9 with letter A=10): 1 + (1*8+2*7+...+8*1+9*1) = 130 % 10 == 0.
VALID_TW_ID = "A123456789"
INVALID_TW_ID = "A123456780"  # same, check digit 0 instead of 9


class _RegistryStub:
    def __init__(
        self, recognizers: tuple[tuple[str, str], ...]
    ) -> None:
        self.recognizers = [
            SimpleNamespace(name=name, supported_language=language)
            for name, language in recognizers
        ]

    def get_recognizers(self, language: str, all_fields: bool = False):
        assert language == "zh" and all_fields is True
        return self.recognizers


class StubAnalyzer:
    """Fake AnalyzerEngine: zh-only, canned results."""

    def __init__(
        self,
        results: tuple[RecognizerResult, ...] = (),
        *,
        languages: list[str] | None = None,
        recognizers: tuple[tuple[str, str], ...] = (("SpacyRecognizer", "zh"),),
    ) -> None:
        self._results = results
        self.supported_languages = languages if languages is not None else ["zh"]
        self.registry = _RegistryStub(recognizers)

    def analyze(self, text, language, ad_hoc_recognizers, score_threshold,
                return_decision_process):
        assert language == "zh"
        assert score_threshold == 0.0
        assert return_decision_process is True
        return self._results


def _result(
    entity: EntityType,
    start: int,
    end: int,
    score: float,
    recognizer: str = "some_pattern_zh",
) -> RecognizerResult:
    return RecognizerResult(
        entity_type=entity.value,
        start=start,
        end=end,
        score=score,
        recognition_metadata={RecognizerResult.RECOGNIZER_NAME_KEY: recognizer},
    )


def _span(
    entity: EntityType,
    start: int,
    end: int,
    score: float = 0.5,
    source: SpanSource = SpanSource.PATTERN,
) -> DetectionSpan:
    return DetectionSpan(
        entity_type=entity,
        start=start,
        end=end,
        score=score,
        source=source,
        raw_value="x" * (end - start),
    )


def _cell(value: str, column: str = "") -> DocumentCell:
    return DocumentCell(cell_id="r1_c0", column=column, value=value, row=1)


class TestSourceLabelling:
    def test_ner_source_from_spacy_recognizer(self) -> None:
        engine = DetectionEngine(analyzer=StubAnalyzer((
            _result(EntityType.PERSON, 0, 3, 0.85, recognizer="SpacyRecognizer"),
        )))
        spans = engine.analyze_text("王小明")
        assert spans[0].source is SpanSource.NER

    def test_fallback_source(self) -> None:
        engine = DetectionEngine(analyzer=StubAnalyzer((
            _result(EntityType.PERSON, 0, 3, 0.55,
                    recognizer="person_fallback_zh"),
        )))
        spans = engine.analyze_text("王小明")
        assert spans[0].source is SpanSource.FALLBACK

    def test_pattern_source_default(self) -> None:
        engine = DetectionEngine(analyzer=StubAnalyzer((
            _result(EntityType.PHONE, 0, 10, 0.8),
        )))
        spans = engine.analyze_text("0912345678")
        assert spans[0].source is SpanSource.PATTERN

    def test_unknown_entity_type_fails_closed(self) -> None:
        # A recogniser emitting a type outside EntityType is a bug:
        # fail closed instead of silently passing data through.
        bad = RecognizerResult(
            entity_type="ALIEN", start=0, end=3, score=0.9,
            recognition_metadata={RecognizerResult.RECOGNIZER_NAME_KEY: "x"},
        )
        engine = DetectionEngine(analyzer=StubAnalyzer((bad,)))
        with pytest.raises(DetectionError):
            engine.analyze_text("abc")

    @pytest.mark.parametrize(
        ("raw_label", "expected"),
        [
            ("GPE", EntityType.LOCATION),
            ("LOC", EntityType.LOCATION),
            ("ORG", EntityType.ORGANIZATION),
            ("PERSON", EntityType.PERSON),
        ],
    )
    def test_raw_spacy_label_mapped_to_gateway_type(
        self, raw_label: str, expected: EntityType
    ) -> None:
        # SpacyRecognizer emits the RAW spaCy label (ner_entity.label_);
        # the engine must translate GPE/LOC/ORG -> gateway types
        # (regression: benchmark run failed closed on 'GPE').
        raw = RecognizerResult(
            entity_type=raw_label, start=0, end=3, score=0.85,
            recognition_metadata={
                RecognizerResult.RECOGNIZER_NAME_KEY: "SpacyRecognizer"
            },
        )
        engine = DetectionEngine(analyzer=StubAnalyzer((raw,)))
        spans = engine.analyze_text("台北市")
        assert spans[0].entity_type is expected
        assert spans[0].source is SpanSource.NER


class TestNerNoiseFilter:
    def test_context_word_person_dropped(self) -> None:
        # The zh NER labels 業務員/客戶/付款人 … as PERSON; these are
        # role words, not names (benchmark-measured).
        engine = DetectionEngine(analyzer=StubAnalyzer((
            _result(EntityType.PERSON, 0, 3, 0.85, recognizer="SpacyRecognizer"),
        )))
        assert engine.analyze_text("業務員") == ()

    def test_deny_word_person_dropped(self) -> None:
        engine = DetectionEngine(analyzer=StubAnalyzer((
            _result(EntityType.PERSON, 0, 2, 0.85, recognizer="SpacyRecognizer"),
        )))
        assert engine.analyze_text("金額") == ()

    def test_real_person_kept(self) -> None:
        engine = DetectionEngine(analyzer=StubAnalyzer((
            _result(EntityType.PERSON, 0, 3, 0.85, recognizer="SpacyRecognizer"),
        )))
        assert len(engine.analyze_text("王小明")) == 1


class TestThresholds:
    def test_below_threshold_dropped(self) -> None:
        engine = DetectionEngine(analyzer=StubAnalyzer((
            _result(EntityType.PERSON, 0, 3, 0.4),
            _result(EntityType.PERSON, 0, 3, 0.6),
        )))
        spans = engine.analyze_text("王小明")
        assert [s.score for s in spans] == [0.6]

    def test_at_threshold_kept(self) -> None:
        engine = DetectionEngine(analyzer=StubAnalyzer((
            _result(EntityType.PERSON, 0, 3, 0.5),
        )))
        assert len(engine.analyze_text("王小明")) == 1

    def test_custom_threshold(self) -> None:
        engine = DetectionEngine(
            analyzer=StubAnalyzer((
                _result(EntityType.PERSON, 0, 3, 0.85),
                _result(EntityType.PERSON, 0, 3, 0.95),
            )),
            thresholds={EntityType.PERSON: 0.9},
        )
        assert [s.score for s in engine.analyze_text("王小明")] == [0.95]

    def test_boost_can_cross_threshold(self) -> None:
        # 0.3 + 0.2 (電話 column) = 0.5 -> kept at the default 0.5.
        engine = DetectionEngine(analyzer=StubAnalyzer((
            _result(EntityType.PHONE, 0, 10, 0.3),
        )))
        spans = engine.analyze_cell(_cell("0912345678", column="電話")).spans
        assert [(s.score, s.source) for s in spans] == [(0.5, SpanSource.PATTERN)]

    def test_threshold_range_validated(self) -> None:
        with pytest.raises(ValueError):
            DetectionEngine(
                analyzer=StubAnalyzer(),
                thresholds={EntityType.PERSON: 1.5},
            )


class TestResolution:
    def test_address_beats_location(self) -> None:
        spans = resolve_overlaps((
            _span(EntityType.LOCATION, 0, 12, 0.7, SpanSource.NER),
            _span(EntityType.ADDRESS, 0, 12, 0.65),
        ))
        assert [s.entity_type for s in spans] == [EntityType.ADDRESS]

    def test_company_beats_organization(self) -> None:
        spans = resolve_overlaps((
            _span(EntityType.ORGANIZATION, 0, 8, 0.85, SpanSource.NER),
            _span(EntityType.COMPANY_NAME, 0, 10, 0.65),
        ))
        assert [s.entity_type for s in spans] == [EntityType.COMPANY_NAME]

    def test_token_pattern_beats_customer_id(self) -> None:
        spans = resolve_overlaps((
            _span(EntityType.CUSTOMER_ID, 0, 12, 0.8),
            _span(EntityType.TOKEN_PATTERN, 2, 14, 0.6),
        ))
        assert [s.entity_type for s in spans] == [EntityType.TOKEN_PATTERN]

    def test_same_type_keeps_highest_score(self) -> None:
        spans = resolve_overlaps((
            _span(EntityType.PHONE, 0, 10, 0.6),
            _span(EntityType.PHONE, 0, 10, 0.9),
        ))
        assert len(spans) == 1 and spans[0].score == 0.9

    def test_different_families_both_kept(self) -> None:
        # A PERSON inside a COMPANY_NAME span is not ambiguous.
        spans = resolve_overlaps((
            _span(EntityType.COMPANY_NAME, 0, 10),
            _span(EntityType.PERSON, 3, 6, source=SpanSource.NER),
        ))
        assert {s.entity_type for s in spans} == {
            EntityType.COMPANY_NAME, EntityType.PERSON,
        }

    def test_address_absorbs_contained_person(self) -> None:
        # The zh NER labels address components (羅東鎮/員林鎮 …) as
        # PERSON; the ADDRESS skeleton is the more specific signal.
        spans = resolve_overlaps((
            _span(EntityType.ADDRESS, 0, 12, 0.65),
            _span(EntityType.PERSON, 3, 6, 0.85, SpanSource.NER),
        ))
        assert [s.entity_type for s in spans] == [EntityType.ADDRESS]

    def test_phone_beats_bank_account(self) -> None:
        # A bare digit run inside a phone cell is a phone number, not
        # an account (benchmark-measured: BANK_ACCOUNT tp=0 fp=226).
        spans = resolve_overlaps((
            _span(EntityType.BANK_ACCOUNT, 0, 10, 0.55),
            _span(EntityType.PHONE, 0, 10, 0.7),
        ))
        assert [s.entity_type for s in spans] == [EntityType.PHONE]

    def test_non_overlapping_same_type_kept(self) -> None:
        spans = resolve_overlaps((
            _span(EntityType.EMAIL, 0, 8),
            _span(EntityType.EMAIL, 12, 20),
        ))
        assert len(spans) == 2

    def test_deterministic_order(self) -> None:
        spans = resolve_overlaps((
            _span(EntityType.EMAIL, 12, 20),
            _span(EntityType.PHONE, 0, 10),
        ))
        assert [s.entity_type for s in spans] == [EntityType.PHONE, EntityType.EMAIL]


class TestContextBoost:
    def test_pattern_boosted_by_matching_column(self) -> None:
        spans = boosted_spans("客戶電話", (_span(EntityType.PHONE, 0, 10, 0.55),))
        assert spans[0].score == pytest.approx(0.75)

    def test_ner_not_boosted(self) -> None:
        spans = boosted_spans(
            "客戶", (_span(EntityType.PERSON, 0, 3, 0.85, SpanSource.NER),)
        )
        assert spans[0].score == pytest.approx(0.85)

    def test_fallback_boosted(self) -> None:
        spans = boosted_spans(
            "客戶", (_span(EntityType.PERSON, 0, 3, 0.55, SpanSource.FALLBACK),)
        )
        assert spans[0].score == pytest.approx(0.75)

    def test_boost_capped(self) -> None:
        spans = boosted_spans("電話", (_span(EntityType.PHONE, 0, 10, 0.9),))
        assert spans[0].score == pytest.approx(0.95)

    def test_unrelated_column_unchanged(self) -> None:
        spans = boosted_spans("金額", (_span(EntityType.PHONE, 0, 10, 0.55),))
        assert spans[0].score == pytest.approx(0.55)

    def test_empty_column_unchanged(self) -> None:
        spans = boosted_spans("", (_span(EntityType.PHONE, 0, 10, 0.55),))
        assert spans[0].score == pytest.approx(0.55)

    def test_case_insensitive_keyword(self) -> None:
        spans = boosted_spans("Customer Name", (_span(EntityType.PERSON, 0, 3, 0.55),))
        assert spans[0].score == pytest.approx(0.75)


class TestTwIdChecksumFlag:
    def test_valid_checksum_reported(self) -> None:
        engine = DetectionEngine(analyzer=StubAnalyzer((
            _result(EntityType.TW_ID, 0, 10, 0.8, recognizer="tw_id_zh"),
        )))
        spans = engine.analyze_text(VALID_TW_ID)
        assert spans[0].checksum_valid is True

    def test_invalid_checksum_reported(self) -> None:
        engine = DetectionEngine(analyzer=StubAnalyzer((
            _result(EntityType.TW_ID, 0, 10, 0.8, recognizer="tw_id_zh"),
        )))
        spans = engine.analyze_text(INVALID_TW_ID)
        assert spans[0].checksum_valid is False

    def test_non_tw_id_no_flag(self) -> None:
        engine = DetectionEngine(analyzer=StubAnalyzer((
            _result(EntityType.PHONE, 0, 10, 0.8),
        )))
        assert engine.analyze_text("0912345678")[0].checksum_valid is None


class TestZhOnlyGuard:
    def test_english_language_rejected(self) -> None:
        with pytest.raises(RuntimeError):
            DetectionEngine(analyzer=StubAnalyzer(languages=["en"]))

    def test_non_zh_recognizer_rejected(self) -> None:
        with pytest.raises(RuntimeError):
            DetectionEngine(analyzer=StubAnalyzer(
                recognizers=(("SpacyRecognizer", "zh"), ("NlpEngine", "en")),
            ))

    def test_missing_spacy_recognizer_rejected(self) -> None:
        with pytest.raises(RuntimeError):
            DetectionEngine(analyzer=StubAnalyzer(
                recognizers=(("other_zh", "zh"),),
            ))

    def test_valid_stub_accepted(self) -> None:
        engine = DetectionEngine(analyzer=StubAnalyzer())
        assert engine.supported_languages == ["zh"]
