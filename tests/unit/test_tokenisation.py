"""Span substitution and restore tests: real cell offsets, no NLP.

Spans use REAL (start, end) offsets into the cell text (unlike the
(0, 1) shorthand in test_policy.py) so substitution correctness is
pinned at the character level.
"""

from __future__ import annotations

import pytest

from secure_ai_gateway.models import (
    CellDecision,
    CellDetection,
    DetectionResult,
    DetectionSpan,
    Disposition,
    DocumentCell,
    EntityType,
    PolicyDecision,
    SpanSource,
)
from secure_ai_gateway.tokenisation.substitution import (
    restore_text,
    tokenise_cells,
)
from secure_ai_gateway.tokenisation.vault import SessionTokenVault


def _span(
    entity: EntityType, start: int, end: int,
    raw: str | None = None,
) -> DetectionSpan:
    return DetectionSpan(
        entity_type=entity,
        start=start,
        end=end,
        score=0.9,
        source=SpanSource.PATTERN,
        raw_value=raw if raw is not None else "x" * (end - start),
    )


def _cell(cell_id: str, value: str, column: str = "客戶") -> DocumentCell:
    return DocumentCell(cell_id=cell_id, column=column, value=value, row=1)


def _detection(*cell_spans: tuple[str, tuple[DetectionSpan, ...]]) -> DetectionResult:
    return DetectionResult(
        cells=tuple(
            CellDetection(cell_id=cell_id, spans=spans)
            for cell_id, spans in cell_spans
        )
    )


def _decision(*cell_decision: tuple[str, Disposition]) -> PolicyDecision:
    return PolicyDecision(
        disposition=Disposition.ALLOW,
        reason="ok",
        cell_decisions=tuple(
            CellDecision(cell_id=c, disposition=d, reason="r")
            for c, d in cell_decision
        ),
    )


class TestTokeniseCells:
    def test_single_span_mid_cell(self) -> None:
        cell = _cell("c0", "客戶名稱：王小明，聯絡人")
        vault = SessionTokenVault()
        cells, count = tokenise_cells(
            (cell,),
            _detection(("c0", (_span(EntityType.PERSON, 5, 8, "王小明"),))),
            _decision(("c0", Disposition.TOKENISE)),
            vault,
        )
        (protected,) = cells
        assert count == 1
        assert "王小明" not in protected.value
        assert protected.value.startswith("客戶名稱：")
        assert protected.value.endswith("，聯絡人")
        assert "PERSON_" in protected.value

    def test_multi_span_preserves_text_between(self) -> None:
        cell = _cell("c0", "王小明 email bob@x.com 電話 0912345678")
        vault = SessionTokenVault()
        cells, count = tokenise_cells(
            (cell,),
            _detection((
                "c0",
                (
                    _span(EntityType.PERSON, 0, 3, "王小明"),
                    _span(EntityType.EMAIL, 10, 19, "bob@x.com"),
                    _span(EntityType.PHONE, 23, 33, "0912345678"),
                ),
            )),
            _decision(("c0", Disposition.TOKENISE)),
            vault,
        )
        (protected,) = cells
        assert count == 3
        # The separators between spans survive substitution.
        parts = protected.value.split(" ")
        raw_parts = [vault.restore(p) if "_" in p else p for p in parts]
        assert raw_parts == ["王小明", "email", "bob@x.com", "電話", "0912345678"]
        assert restore_text(protected.value, vault) == cell.value

    def test_leading_trailing_text_preserved(self) -> None:
        cell = _cell("c0", "前綴王小明後綴")
        vault = SessionTokenVault()
        cells, count = tokenise_cells(
            (cell,),
            _detection(("c0", (_span(EntityType.PERSON, 2, 5, "王小明"),))),
            _decision(("c0", Disposition.TOKENISE)),
            vault,
        )
        (protected,) = cells
        assert count == 1
        assert protected.value.startswith("前綴") and protected.value.endswith("後綴")

    def test_cjk_offsets_are_code_points(self) -> None:
        cell = _cell("c0", "客戶梁涵")
        vault = SessionTokenVault()
        cells, _ = tokenise_cells(
            (cell,),
            _detection(("c0", (_span(EntityType.PERSON, 2, 4, "梁涵"),))),
            _decision(("c0", Disposition.TOKENISE)),
            vault,
        )
        (protected,) = cells
        assert protected.value.startswith("客戶")
        assert vault.restore(protected.value[2:]) == "梁涵"
        assert "梁涵" not in protected.value

    def test_allow_cell_kept_same_instance(self) -> None:
        cell = _cell("c0", "8.4M")
        vault = SessionTokenVault()
        cells, count = tokenise_cells(
            (cell,),
            _detection(),
            _decision(("c0", Disposition.ALLOW)),
            vault,
        )
        assert cells[0] is cell
        assert count == 0

    def test_tokenise_cell_without_spans_unchanged(self) -> None:
        cell = _cell("c0", "無感測內容")
        vault = SessionTokenVault()
        cells, count = tokenise_cells(
            (cell,),
            _detection(("c0", ())),
            _decision(("c0", Disposition.TOKENISE)),
            vault,
        )
        assert cells[0] is cell
        assert count == 0

    def test_repeated_value_same_token_across_cells(self) -> None:
        c1 = _cell("c0", "王小明 甲")
        c2 = _cell("c1", "王小明 乙")
        vault = SessionTokenVault()
        cells, count = tokenise_cells(
            (c1, c2),
            _detection(
                ("c0", (_span(EntityType.PERSON, 0, 3, "王小明"),)),
                ("c1", (_span(EntityType.PERSON, 0, 3, "王小明"),)),
            ),
            _decision(("c0", Disposition.TOKENISE), ("c1", Disposition.TOKENISE)),
            vault,
        )
        assert count == 2
        p0, p1 = cells
        assert p0.value[0:3] != "王小明" and p1.value[0:3] != "王小明"
        assert p0.value[0:3] == p1.value[0:3]  # same raw -> same token
        assert "王小明" not in p0.value and "王小明" not in p1.value

    def test_degenerate_span_skipped(self) -> None:
        cell = _cell("c0", "王小明")
        vault = SessionTokenVault()
        cells, count = tokenise_cells(
            (cell,),
            _detection(("c0", (_span(EntityType.PERSON, 2, 2, ""),))),
            _decision(("c0", Disposition.TOKENISE)),
            vault,
        )
        assert cells[0] is cell
        assert count == 0

    def test_count_matches_substituted_spans(self) -> None:
        cell = _cell("c0", "王小明 李大同")
        vault = SessionTokenVault()
        cells, count = tokenise_cells(
            (cell,),
            _detection((
                "c0",
                (
                    _span(EntityType.PERSON, 0, 3, "王小明"),
                    _span(EntityType.PERSON, 4, 7, "李大同"),
                ),
            )),
            _decision(("c0", Disposition.TOKENISE)),
            vault,
        )
        assert count == 2
        (protected,) = cells
        assert "王小明" not in protected.value and "李大同" not in protected.value

    def test_tokenised_cell_has_no_raw_span_text(self) -> None:
        cell = _cell("c0", "Aurora Motors AU")
        vault = SessionTokenVault()
        cells, _ = tokenise_cells(
            (cell,),
            _detection(("c0", (_span(EntityType.COMPANY_NAME, 0, 16, "Aurora Motors AU"),))),
            _decision(("c0", Disposition.TOKENISE)),
            vault,
        )
        (protected,) = cells
        assert "Aurora" not in protected.value
        assert "COMPANY_" in protected.value


class TestRestoreText:
    def test_round_trip_full_text(self) -> None:
        original = "王小明 email bob@x.com 電話 0912345678"
        cell = _cell("c0", original)
        vault = SessionTokenVault()
        (protected,), _ = tokenise_cells(
            (cell,),
            _detection((
                "c0",
                (
                    _span(EntityType.PERSON, 0, 3, "王小明"),
                    _span(EntityType.EMAIL, 10, 19, "bob@x.com"),
                    _span(EntityType.PHONE, 23, 33, "0912345678"),
                ),
            )),
            _decision(("c0", Disposition.TOKENISE)),
            vault,
        )
        assert restore_text(protected.value, vault) == original

    def test_multiple_tokens_one_text(self) -> None:
        vault = SessionTokenVault()
        t1 = vault.token_for(EntityType.PERSON, "王小明")
        t2 = vault.token_for(EntityType.PERSON, "李大同")
        text = f"{t1} 和 {t2} 簽約"
        assert restore_text(text, vault) == "王小明 和 李大同 簽約"

    def test_unknown_token_like_string_untouched(self) -> None:
        vault = SessionTokenVault()
        vault.token_for(EntityType.PERSON, "王小明")
        assert restore_text("CUSTOMER_deadbeef 未知", vault) == \
            "CUSTOMER_deadbeef 未知"

    def test_token_at_start_and_end(self) -> None:
        vault = SessionTokenVault()
        t = vault.token_for(EntityType.PERSON, "王小明")
        assert restore_text(f"{t}：報告", vault) == "王小明：報告"
        assert restore_text(f"報告：{t}", vault) == "報告：王小明"

    def test_empty_text(self) -> None:
        vault = SessionTokenVault()
        assert restore_text("", vault) == ""

    def test_empty_vault_passthrough(self) -> None:
        assert restore_text("王小明", SessionTokenVault()) == "王小明"
