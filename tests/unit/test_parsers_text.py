"""Parser unit tests: CSV / XLSX / text + formula neutralisation."""

from __future__ import annotations

import io

import openpyxl
import pytest

from secure_ai_gateway.errors import ParsingError, ResourceLimitError
from secure_ai_gateway.limits import ResourceLimits
from secure_ai_gateway.parsers import parse_document
from secure_ai_gateway.parsers.text_parser import parse_text_bytes


class TestTextParser:
    def test_lines_become_cells(self) -> None:
        doc = parse_text_bytes("客戶\n陳曉明\n".encode(), "t.txt", ResourceLimits())
        assert [c.value for c in doc.cells] == ["客戶", "陳曉明"]

    def test_empty_lines_skipped(self) -> None:
        doc = parse_text_bytes(b"a\n\nb\n", "t.txt", ResourceLimits())
        assert [c.value for c in doc.cells] == ["a", "b"]
        assert doc.stats.skipped_empty_cells == 1

    def test_formula_line_neutralised(self) -> None:
        doc = parse_text_bytes(b"=cmd\n", "t.txt", ResourceLimits())
        assert [c.value for c in doc.cells] == ["'=cmd"]





class TestParseDocumentDispatch:
    def test_unsupported_extension(self, tmp_path) -> None:
        bad = tmp_path / "notes.docx"
        bad.write_bytes(b"x")
        with pytest.raises(ParsingError):
            parse_document(bad, ResourceLimits())

    def test_file_size_limit(self, tmp_path) -> None:
        big = tmp_path / "big.csv"
        big.write_bytes(b"a\n" + b"1\n" * 1000)
        with pytest.raises(ResourceLimitError):
            parse_document(big, ResourceLimits(max_file_bytes=100))

    def test_csv_dispatch(self, tmp_path) -> None:
        f = tmp_path / "t.csv"
        f.write_bytes(b"a,b\n1,2\n")
        doc = parse_document(f, ResourceLimits())
        assert doc.stats.format == "csv"

    def test_xlsx_dispatch(self, tmp_path) -> None:
        wb = openpyxl.Workbook()
        wb.active.append(["a", "b"])
        wb.active.append(["1", "2"])
        buf = io.BytesIO()
        wb.save(buf)
        f = tmp_path / "t.xlsx"
        f.write_bytes(buf.getvalue())
        doc = parse_document(f, ResourceLimits())
        assert doc.stats.format == "xlsx"
