"""Parser unit tests: CSV / XLSX / text + formula neutralisation."""

from __future__ import annotations

import io
import struct
import zipfile

import openpyxl
import pytest

from secure_ai_gateway.errors import ParsingError, ResourceLimitError
from secure_ai_gateway.limits import ResourceLimits
from secure_ai_gateway.parsers.xlsx_parser import parse_xlsx_bytes


class TestXlsxParser:
    @staticmethod
    def _make_xlsx() -> bytes:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["客戶", "金額", "日期", "啟用"])
        ws.append(["王大明", 123.5, "2026-01-15", True])
        ws["A3"] = "=SUM(B2)"  # formula cell (no cached value)
        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()

    def test_basic_parse(self) -> None:
        doc = parse_xlsx_bytes(self._make_xlsx(), "t.xlsx", ResourceLimits())
        assert doc.stats.format == "xlsx"
        assert doc.stats.row_count == 3
        values = {c.cell_id: c.value for c in doc.cells}
        assert values["r1_c0"] == "王大明"
        assert values["r1_c1"] == "123.5"
        assert values["r1_c2"] == "2026-01-15"
        assert values["r1_c3"] == "TRUE"

    def test_formula_cell_never_enters_pipeline(self) -> None:
        doc = parse_xlsx_bytes(self._make_xlsx(), "t.xlsx", ResourceLimits())
        assert "=SUM(B2)" not in [c.value for c in doc.cells]
        assert doc.stats.neutralised_formula_cells == 1

    def test_not_a_zip_fails_closed(self) -> None:
        with pytest.raises(ParsingError):
            parse_xlsx_bytes(b"not a zip at all", "t.xlsx", ResourceLimits())

    def test_member_count_limit(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(12):
                zf.writestr(f"m{i}", b"x")
        with pytest.raises(ResourceLimitError):
            parse_xlsx_bytes(buf.getvalue(), "t.xlsx", ResourceLimits(max_archive_members=10))

    def test_decompressed_size_limit(self) -> None:
        # Craft a zip whose local/central headers declare a 300MB member
        # while the actual payload is tiny — zip-bomb style.
        def entry(offset: int, declared: int) -> bytes:
            local = struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50, 20, 0, 8, 0, 0, 0, declared, declared, 1, 0,
            ) + b"x"
            central = struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50, 20, 20, 0, 8, 0, 0, 0, declared, declared,
                1, 0, 0, 0, 0, 0, offset,
            ) + b"x"
            return local, central

        local, central = entry(0, 300 * 1024 * 1024)
        eocd = struct.pack(
            "<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0
        )
        payload = local + central + eocd
        with pytest.raises(ResourceLimitError):
            parse_xlsx_bytes(payload, "t.xlsx", ResourceLimits())


