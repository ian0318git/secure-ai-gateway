"""Detection engine: zh NER + deterministic recognisers + resolution.

Pipeline per cell: presidio analysis (allow_overlap) -> source
labelling -> column-header context boost -> overlap resolution ->
per-entity calibrated thresholds.

Fail-closed behaviour: an unrecognised entity type from presidio is a
bug in our recogniser set and raises ``DetectionError`` rather than
silently passing data through.
"""

from __future__ import annotations

from typing import Mapping, Optional

from presidio_analyzer.recognizer_result import RecognizerResult

from secure_ai_gateway.detection.context import boosted_spans
from secure_ai_gateway.detection.ner import (
    NER_ENTITY_TYPES,
    NER_LABEL_MAP,
    NER_RECOGNIZER_NAME,
    assert_zh_only,
    build_analyzer,
)
from secure_ai_gateway.detection.recognizers import (
    _PERSON_NOISE_WORDS,
    _tw_id_checksum,
    build_pattern_recognizers,
)
from secure_ai_gateway.detection.resolution import resolve_overlaps
from secure_ai_gateway.errors import DetectionError
from secure_ai_gateway.models import (
    CellDetection,
    DetectionSpan,
    DocumentCell,
    EntityType,
    SpanSource,
)

DEFAULT_THRESHOLD = 0.5


class DetectionEngine:
    """One engine per process; model loaded lazily on first use."""

    def __init__(
        self,
        thresholds: Optional[Mapping[EntityType, float]] = None,
        boost: float = 0.2,
        cap: float = 0.95,
        analyzer=None,
    ) -> None:
        self._analyzer = analyzer if analyzer is not None else build_analyzer()
        assert_zh_only(self._analyzer)
        self._recognizers = build_pattern_recognizers()
        self._boost = boost
        self._cap = cap
        self._thresholds: dict[EntityType, float] = {
            etype: DEFAULT_THRESHOLD for etype in EntityType
        }
        if thresholds:
            for etype, value in thresholds.items():
                if value < 0.0 or value > 1.0:
                    raise ValueError(f"threshold out of range: {etype}={value}")
                self._thresholds[etype] = value

    @property
    def supported_languages(self) -> list[str]:
        # presidio 2.2.364: attribute; older API: method. Duck-typed
        # stub analyzers in tests may expose either.
        attr = getattr(self._analyzer, "supported_languages", None)
        if attr is not None:
            return list(attr)
        method = getattr(self._analyzer, "get_supported_languages", None)
        if method is not None:
            return list(method())
        raise RuntimeError("analyzer exposes no supported_languages")

    def _source_for(self, entity_type: EntityType, recognizer_name: str | None) -> SpanSource:
        if entity_type in NER_ENTITY_TYPES and recognizer_name == NER_RECOGNIZER_NAME:
            return SpanSource.NER
        if recognizer_name == "person_fallback_zh":
            return SpanSource.FALLBACK
        return SpanSource.PATTERN

    def _to_spans(
        self, text: str, results
    ) -> tuple[DetectionSpan, ...]:
        spans: list[DetectionSpan] = []
        for result in results:
            # presidio 2.2.364: recogniser name lives in the recognition
            # metadata (``decision_process`` no longer exists).
            metadata = result.recognition_metadata or {}
            recognizer_name = metadata.get(RecognizerResult.RECOGNIZER_NAME_KEY)
            # NER spans carry the RAW spaCy label (SpacyRecognizer emits
            # ner_entity.label_); translate before the EntityType check.
            entity_type = NER_LABEL_MAP.get(result.entity_type)
            if entity_type is None:
                try:
                    entity_type = EntityType(result.entity_type)
                except ValueError:
                    raise DetectionError(
                        f"recogniser emitted unknown entity type "
                        f"{result.entity_type!r}"
                    ) from None
            source = self._source_for(entity_type, recognizer_name)
            if (
                entity_type is EntityType.PERSON
                and source is SpanSource.NER
                and text[result.start : result.end] in _PERSON_NOISE_WORDS
            ):
                # The zh NER labels person-context role words (業務員 /
                # 客戶 / 付款人 …) as PERSON (spike + benchmark measured,
                # docs/DECISIONS.md): these are not names.
                continue
            checksum_valid = None
            if entity_type is EntityType.TW_ID:
                raw = text[result.start : result.end]
                checksum_valid = _tw_id_checksum(raw[0], raw[1:])
            spans.append(
                DetectionSpan(
                    entity_type=entity_type,
                    start=result.start,
                    end=result.end,
                    score=result.score,
                    source=source,
                    raw_value=text[result.start : result.end],
                    checksum_valid=checksum_valid,
                )
            )
        return tuple(spans)

    def _analyze(self, text: str) -> tuple[DetectionSpan, ...]:
        results = self._analyzer.analyze(
            text=text,
            language="zh",
            ad_hoc_recognizers=self._recognizers,
            score_threshold=0.0,  # calibrated per-entity below
            # presidio 2.2.364 keeps overlapping spans of different
            # types by default; resolution happens below.
            return_decision_process=True,
        )
        return self._to_spans(text, results)

    def _apply_thresholds(
        self, spans: tuple[DetectionSpan, ...]
    ) -> tuple[DetectionSpan, ...]:
        return tuple(
            span
            for span in spans
            if span.score >= self._thresholds[span.entity_type]
        )

    def analyze_cell_raw(self, cell: DocumentCell) -> CellDetection:
        """Analyse without the per-entity threshold filter.

        Used by the benchmark to calibrate thresholds on the train
        split without re-running the NLP model (BENCHMARK.md §5.2).
        """
        spans = self._analyze(cell.value)
        spans = boosted_spans(cell.column, spans, self._boost, self._cap)
        spans = resolve_overlaps(spans)
        return CellDetection(cell_id=cell.cell_id, spans=spans)

    def analyze_cell(self, cell: DocumentCell) -> CellDetection:
        """Analyse one document cell (boosted by its column header)."""
        raw = self.analyze_cell_raw(cell)
        return CellDetection(
            cell_id=raw.cell_id,
            spans=self._apply_thresholds(raw.spans),
        )

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]:
        """Analyse arbitrary text (e.g. the user instruction)."""
        spans = self._analyze(text)
        spans = resolve_overlaps(spans)
        return self._apply_thresholds(spans)
