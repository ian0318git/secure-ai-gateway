"""Parser unit tests: CSV / XLSX / text + formula neutralisation."""

from __future__ import annotations

import io
import struct
import zipfile

import openpyxl
import pytest

from secure_ai_gateway.errors import ParsingError, ResourceLimitError
from secure_ai_gateway.limits import ResourceLimits
from secure_ai_gateway.parsers.csv_parser import parse_csv_bytes


class TestCsvParser:
    def test_basic_parse_with_headers(self) -> None:
        data = "客戶,金額\n陳曉明,1000\n".encode("utf-8")
        doc = parse_csv_bytes(data, "t.csv", ResourceLimits())
        assert doc.stats.format == "csv"
        assert doc.stats.encoding == "utf_8"
        assert doc.stats.row_count == 2
        assert doc.headers == ("客戶", "金額")
        cells = {c.cell_id: c for c in doc.cells}
        assert cells["r1_c0"].value == "陳曉明"
        assert cells["r1_c0"].column == "客戶"
        assert cells["r1_c1"].value == "1000"

    def test_gbk_encoded_chinese(self) -> None:
        data = "客戶,金額\n陳曉明,1000\n".encode("gbk")
        doc = parse_csv_bytes(data, "t.csv", ResourceLimits())
        assert doc.stats.encoding == "gbk"
        values = [c.value for c in doc.cells]
        assert "陳曉明" in values

    def test_leading_zeros_preserved(self) -> None:
        data = "id,name\n00123,abc\n".encode("utf-8")
        doc = parse_csv_bytes(data, "t.csv", ResourceLimits())
        assert [c.value for c in doc.cells if c.cell_id == "r1_c0"] == ["00123"]

    def test_quoted_newline_survives(self) -> None:
        data = 'a,b\n"line1\nline2",x\n'.encode("utf-8")
        doc = parse_csv_bytes(data, "t.csv", ResourceLimits())
        values = [c.value for c in doc.cells]
        assert "line1 line2" in values  # newline neutralised to space

    def test_formula_cell_neutralised(self) -> None:
        data = "a,b\n=SUM(A1),x\n".encode("utf-8")
        doc = parse_csv_bytes(data, "t.csv", ResourceLimits())
        values = [c.value for c in doc.cells]
        assert "'=SUM(A1)" in values
        assert doc.stats.neutralised_formula_cells == 1

    def test_na_string_not_treated_as_nan(self) -> None:
        data = "a\nNA\n".encode("utf-8")
        doc = parse_csv_bytes(data, "t.csv", ResourceLimits())
        assert [c.value for c in doc.cells if c.cell_id == "r1_c0"] == ["NA"]

    def test_null_byte_handled(self) -> None:
        data = b"a,b\nfoo\x00bar,x\n"
        doc = parse_csv_bytes(data, "t.csv", ResourceLimits())
        assert "foo bar" in [c.value for c in doc.cells]

    def test_row_limit_enforced(self) -> None:
        data = "a\n" + "1\n" * 1000
        limits = ResourceLimits(max_rows=100)
        with pytest.raises(ResourceLimitError):
            parse_csv_bytes(data.encode("utf-8"), "t.csv", limits)

    def test_bad_csv_fails_closed(self) -> None:
        data = b'"unterminated\n'  # unterminated quote
        with pytest.raises(ParsingError):
            parse_csv_bytes(data, "t.csv", ResourceLimits())


