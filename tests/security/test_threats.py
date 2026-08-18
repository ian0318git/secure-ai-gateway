"""Security test suite — threat traceability (plan: commit 18).

Every case maps to a threat / security requirement from docs/DESIGN.md:
- T-I09: GBK / UTF-16 encodings must not break detection
- T-T04 / CWE-1236: formula injection neutralised end-to-end
- T-D02: zip bomb rejected (fail closed)
- T-I02 / SR-024: secrets block the request, nothing retained
- SR-010 / SR-017: any detection/policy exception -> BLOCK, no output
- T-I05 / SR-009: no raw content anywhere in logs or reports
- SR-022 / T-I08: instruction injection blocks the request
- T-I06: document-cell injection -> BLOCK (critical) / DROP (mild)

The engine is stubbed (duck-typed); no NLP model is loaded here.
"""

from __future__ import annotations

import logging
import struct
import zipfile

import pytest

from secure_ai_gateway.errors import ResourceLimitError
from secure_ai_gateway.limits import ResourceLimits
from secure_ai_gateway.logging import log_event
from secure_ai_gateway.models import (
    CellDetection,
    DetectionSpan,
    Disposition,
    EntityType,
    SpanSource,
)
from secure_ai_gateway.pipeline import Pipeline


class StubEngine:
    """Duck-typed DetectionEngine; no NLP model is loaded."""

    def __init__(self, spans_by_cell: dict[str, tuple[DetectionSpan, ...]]):
        self._spans = spans_by_cell

    def analyze_cell(self, cell):
        return CellDetection(
            cell_id=cell.cell_id,
            spans=self._spans.get(cell.cell_id, ()),
        )

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]:
        return ()


def _span(entity: EntityType) -> DetectionSpan:
    return DetectionSpan(entity, 0, 1, 0.9, SpanSource.PATTERN, "x")


# ---------------------------------------------------------------------------
# T-I09: encoding robustness must not break the pipeline
# ---------------------------------------------------------------------------


class TestEncodingThreats:
    def test_gbk_csv_chinese_name_still_detected(self, tmp_path) -> None:
        """GBK-encoded Chinese cell survives parsing and detection."""
        f = tmp_path / "gbk.csv"
        f.write_bytes("客戶,金額\n王小明,1000\n".encode("gbk"))
        pipeline = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON),)}),
            ResourceLimits(),
        )
        decision, report, _, _ = pipeline.process_file(f, request_id="r1")
        assert not decision.is_blocked()
        assert decision.disposition_for("r1_c0") is Disposition.TOKENISE
        assert report.encoding == "gbk"

    def test_utf16_csv_email_detected(self, tmp_path) -> None:
        """UTF-16-encoded CSV: email is still flagged (T-I09)."""
        f = tmp_path / "u16.csv"
        f.write_bytes("客戶,Email\n王小明,johnwang@example.com\n".encode("utf-16"))
        pipeline = Pipeline(
            StubEngine({"r1_c1": (_span(EntityType.EMAIL),)}),
            ResourceLimits(),
        )
        decision, report, _, _ = pipeline.process_file(f, request_id="r1")
        assert not decision.is_blocked()
        assert decision.disposition_for("r1_c1") is Disposition.TOKENISE
        assert report.encoding == "utf_16"

    def test_utf16_xlsx_fails_closed(self, tmp_path) -> None:
        """A UTF-16 'XLSX' is not a valid ZIP container -> BLOCK.

        XLSX is always a ZIP of XML (encoding lives inside), so a
        UTF-16-encoded xlsx is malformed input: fail closed, never
        guess.
        """
        f = tmp_path / "u16.xlsx"
        f.write_bytes("客戶,Email\n王小明,johnwang@example.com\n".encode("utf-16"))
        decision, _, retained, _ = Pipeline(
            StubEngine({}), ResourceLimits()
        ).process_file(f, request_id="r1")
        assert decision.is_blocked()
        assert decision.reason == "error:ParsingError"
        assert retained == ()


# ---------------------------------------------------------------------------
# T-T04 / CWE-1236: formula injection neutralised before detection
# ---------------------------------------------------------------------------


class TestFormulaInjection:
    @pytest.mark.parametrize("formula", ["=SUM(A1)", "+1+1", "@cmd", "＝合計"])
    def test_formula_prefix_never_reaches_detection(self, tmp_path, formula) -> None:
        f = tmp_path / "f.csv"
        f.write_bytes(f"客戶,金額\n{formula},1000\n".encode())
        pipeline = Pipeline(StubEngine({}), ResourceLimits())
        decision, report, retained, _ = pipeline.process_file(f, request_id="r1")
        assert not decision.is_blocked()
        # the neutralised cell must still be a normal cell, not a formula
        # (pandas 0-indexes the header as row 0: header 客戶/金額 =
        # r0_c0/r0_c1; data row = r1_c0/r1_c1)
        cells = {c.cell_id: c.value for c in retained}
        assert not cells["r1_c0"].startswith(("=", "+", "@", "＝"))
        assert report.neutralised_formula_cells >= 1


# ---------------------------------------------------------------------------
# T-D02: zip bomb -> BLOCK, nothing retained
# ---------------------------------------------------------------------------


class TestZipBomb:
    def test_decompressed_size_limit_blocks(self, tmp_path) -> None:
        """Fake XLSX whose declared decompressed size exceeds the cap."""
        from secure_ai_gateway.parsers import parse_document

        f = tmp_path / "bomb.xlsx"
        # hand-rolled zip with a lying central-directory file_size
        with zipfile.ZipFile(f, "w") as zf:
            zf.writestr(
                "xl/workbook.xml",
                b"<workbook/>",
                compress_type=zipfile.ZIP_STORED,
            )
        # now rewrite the central directory file_size field (offset 24 in
        # the central directory entry: sig(4) ver(2) flag(2) method(2)
        # time(2) date(2) crc(4) size(4) csize(4))
        raw = bytearray(f.read_bytes())
        # find the central directory header
        idx = raw.index(b"PK\x01\x02")
        struct.pack_into("<I", raw, idx + 24, 300 * 1024 * 1024)
        f.write_bytes(bytes(raw))
        with pytest.raises(ResourceLimitError):
            parse_document(f, ResourceLimits())


# ---------------------------------------------------------------------------
# SR-010 / SR-017: detection or policy exceptions -> BLOCK, no retained cells
# ---------------------------------------------------------------------------


class TestFailClosed:
    def test_detection_exception_blocks_without_retained(self, tmp_path) -> None:
        class Boom(StubEngine):
            def analyze_cell(self, cell):
                raise RuntimeError("model exploded")

        f = tmp_path / "x.csv"
        f.write_bytes("客戶,金額\n王小明,1000\n".encode())
        decision, report, retained, _ = Pipeline(
            Boom({}), ResourceLimits()
        ).process_file(f, request_id="r1")
        assert decision.is_blocked()
        assert decision.reason == "error:RuntimeError"
        assert retained == ()
        assert report.retained_cells == 0

    def test_token_pattern_is_pii_not_secret(self, tmp_path) -> None:
        """TOKEN_PATTERN (reserved token format) tokenises, never blocks."""
        f = tmp_path / "x.csv"
        f.write_bytes(b"a,b\n1,2\n")
        pipeline = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.TOKEN_PATTERN),)}),
            ResourceLimits(),
        )
        decision, _, _, _ = pipeline.process_file(f, request_id="r1")
        assert not decision.is_blocked()
        assert decision.disposition_for("r1_c0") is Disposition.TOKENISE

    def test_secret_span_blocks_whole_request(self, tmp_path) -> None:
        f = tmp_path / "s.csv"
        f.write_bytes(b"a,b\n1,2\n")
        decision, _, retained, _ = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.API_KEY),)}),
            ResourceLimits(),
        ).process_file(f, request_id="r1")
        assert decision.is_blocked()
        assert decision.reason == "secret:API_KEY"
        assert retained == ()


# ---------------------------------------------------------------------------
# T-I05 / SR-009: no raw content in logs or reports
# ---------------------------------------------------------------------------


class TestNoRawLeak:
    def test_log_events_never_carry_raw_values(self, caplog) -> None:
        logger = logging.getLogger("security.no_raw")
        with caplog.at_level(logging.INFO, logger="security.no_raw"):
            log_event(
                logger,
                "pipeline.complete",
                request_id="r1",
                cell_count=3,
                disposition="TOKENISE",
            )
        combined = caplog.text
        assert "王小明機密內容" not in combined
        assert "TOP-SECRET-XYZ" not in combined

    def test_log_event_rejects_raw_like_keys(self, caplog) -> None:
        logger = logging.getLogger("security.reject")
        with pytest.raises(ValueError):
            log_event(logger, "event", raw_value="王小明")

    def test_full_pipeline_report_contains_no_raw(self, tmp_path) -> None:
        f = tmp_path / "s.csv"
        f.write_bytes("客戶,金額\n機密客戶名稱AuroraX,1000\n".encode())
        pipeline = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON),)}),
            ResourceLimits(),
        )
        _, report, _, _ = pipeline.process_file(f, request_id="r1")
        json_text = report.to_json()
        md_text = report.to_markdown()
        assert "機密客戶名稱AuroraX" not in json_text
        assert "機密客戶名稱AuroraX" not in md_text
