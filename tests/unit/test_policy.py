"""Policy engine: three-layer default-deny (SR-024)."""

from __future__ import annotations

import pytest

from secure_ai_gateway.models import (
    DetectionResult,
    DetectionSpan,
    Disposition,
    DocumentCell,
    EntityType,
    ParsedDocument,
    ParseStats,
    SpanSource,
)
from secure_ai_gateway.policy.engine import evaluate
from secure_ai_gateway.policy.templates import TASK_TEMPLATES, resolve_template

TEMPLATE = TASK_TEMPLATES["gross_margin"]


def _doc(*cells: tuple[str, str, str]) -> ParsedDocument:
    """Build a ParsedDocument from (cell_id, column, value) triples."""
    parsed_cells = tuple(
        DocumentCell(cell_id=c, column=col, value=v, row=i)
        for i, (c, col, v) in enumerate(cells)
    )
    stats = ParseStats(
        file_name="t.csv",
        file_size_bytes=10,
        encoding="utf-8",
        format="csv",
        row_count=len(parsed_cells),
        cell_count=len(parsed_cells),
        column_count=1,
        estimated_tokens=1,
    )
    return ParsedDocument(stats=stats, cells=parsed_cells, headers=())


def _result(*cells: tuple[str, EntityType]) -> DetectionResult:
    from secure_ai_gateway.models import CellDetection

    return DetectionResult(
        cells=tuple(
            CellDetection(
                cell_id=cell_id,
                spans=(
                    DetectionSpan(
                        entity, 0, 1, 0.9, SpanSource.PATTERN, "x"
                    ),
                ),
            )
            for cell_id, entity in cells
        )
    )


class TestPolicyEngine:
    def test_injection_finding_drops_cell(self) -> None:
        from secure_ai_gateway.models import (
            CellDetection,
            InjectionCategory,
            InjectionFinding,
        )

        doc = _doc(("c0", "金額", "<|im_start|>"))
        detection = DetectionResult(
            cells=(
                CellDetection(
                    cell_id="c0",
                    injection_findings=(
                        InjectionFinding(
                            category=InjectionCategory.DELIMITER,
                            severity=2,
                            location="c0",
                            pattern_id="dl01",
                            matched_text="<|im_start|>",
                        ),
                    ),
                ),
            )
        )
        decision = evaluate(doc, detection, TEMPLATE)
        assert not decision.is_blocked()
        assert decision.disposition_for("c0") is Disposition.DROP
        assert decision.dropped_cell_ids == ("c0",)


    def test_no_template_blocks(self) -> None:
        doc = _doc(("c0", "客戶", "王小明"))
        decision = evaluate(doc, _result(("c0", EntityType.PERSON)), None)
        assert decision.is_blocked()
        assert decision.reason == "error:no_template"

    def test_unknown_template_blocks(self) -> None:
        assert resolve_template("nonexistent") is None
        assert resolve_template(None) is None
        assert resolve_template("gross_margin") is TEMPLATE

    def test_secret_span_blocks_request(self) -> None:
        doc = _doc(("c0", "備註", "sk-abcdefghijklmnop1234"))
        decision = evaluate(doc, _result(("c0", EntityType.API_KEY)), TEMPLATE)
        assert decision.is_blocked()
        assert decision.reason == "secret:API_KEY"
        assert decision.blocked_cell_ids == ("c0",)

    def test_credential_span_blocks(self) -> None:
        doc = _doc(("c0", "備註", "password=abc12345"))
        decision = evaluate(doc, _result(("c0", EntityType.SECRET)), TEMPLATE)
        assert decision.is_blocked()
        assert decision.reason == "secret:SECRET"

    def test_secret_column_blocks_even_without_spans(self) -> None:
        doc = _doc(("c0", "api_key", "abcd1234"))
        decision = evaluate(doc, DetectionResult(), TEMPLATE)
        assert decision.is_blocked()
        assert decision.reason == "secret_column"

    def test_pii_span_tokenises(self) -> None:
        doc = _doc(("c0", "客戶", "王小明"))
        decision = evaluate(doc, _result(("c0", EntityType.PERSON)), TEMPLATE)
        assert not decision.is_blocked()
        assert decision.disposition_for("c0") is Disposition.TOKENISE

    def test_non_allowlist_column_dropped(self) -> None:
        doc = _doc(("c0", "員工手機號碼", "0912345678"))
        decision = evaluate(doc, DetectionResult(), TEMPLATE)
        assert not decision.is_blocked()
        assert decision.disposition_for("c0") is Disposition.DROP
        assert decision.dropped_cell_ids == ("c0",)

    def test_allowed_column_allows(self) -> None:
        doc = _doc(("c0", "客戶", "Aurora Motors AU"))
        decision = evaluate(doc, DetectionResult(), TEMPLATE)
        assert not decision.is_blocked()
        assert decision.disposition_for("c0") is Disposition.ALLOW

    def test_unknown_entity_type_blocks(self) -> None:
        # a type outside both tables is treated as default-deny
        doc = _doc(("c0", "客戶", "x"))
        decision = evaluate(doc, _result(("c0", EntityType.BANK_ACCOUNT)), TEMPLATE)
        # BANK_ACCOUNT IS in the tokenise set, so it must NOT block:
        assert not decision.is_blocked()
        assert decision.disposition_for("c0") is Disposition.TOKENISE

    def test_mixed_cells(self) -> None:
        doc = _doc(
            ("c0", "客戶", "王小明"),
            ("c1", "手機", "0912345678"),
            ("c2", "內部代碼", "EMP-8823"),
        )
        decision = evaluate(
            doc,
            _result(("c0", EntityType.PERSON), ("c1", EntityType.PHONE)),
            TEMPLATE,
        )
        assert not decision.is_blocked()
        assert decision.disposition_for("c0") is Disposition.TOKENISE
        assert decision.disposition_for("c1") is Disposition.TOKENISE
        assert decision.disposition_for("c2") is Disposition.DROP
