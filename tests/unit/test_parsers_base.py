"""Parser unit tests: CSV / XLSX / text + formula neutralisation."""

from __future__ import annotations

import io
import struct
import zipfile

import openpyxl
import pytest

from secure_ai_gateway.errors import ParsingError, ResourceLimitError
from secure_ai_gateway.limits import ResourceLimits
from secure_ai_gateway.parsers import parse_document
from secure_ai_gateway.parsers.base import neutralise_formula_prefix
from secure_ai_gateway.parsers.csv_parser import parse_csv_bytes
from secure_ai_gateway.parsers.text_parser import parse_text_bytes
from secure_ai_gateway.parsers.xlsx_parser import parse_xlsx_bytes


class TestNeutraliseFormulaPrefix:
    @pytest.mark.parametrize(
        "value",
        ["=SUM(A1)", "@cmd", "＝SUM(A1)", "＋SUM(A1)", "−SUM(A1)"],
    )
    def test_formula_prefixes_neutralised(self, value: str) -> None:
        result, changed = neutralise_formula_prefix(value)
        assert changed
        assert result.startswith("'")

    def test_negative_number_preserved(self) -> None:
        result, changed = neutralise_formula_prefix("-5.7M")
        assert not changed
        assert result == "-5.7M"

    def test_plus_always_neutralised(self) -> None:
        """CWE-1236: a leading '+' is a formula signal in spreadsheet
        software, never a legitimate financial value notation."""
        result, changed = neutralise_formula_prefix("+3.2")
        assert changed
        assert result.startswith("'")

    def test_math_minus_neutralised_when_not_number(self) -> None:
        result, changed = neutralise_formula_prefix("−SUM(A1)")
        assert changed
        assert result.startswith("'")

    def test_internal_tab_replaced(self) -> None:
        result, changed = neutralise_formula_prefix("a\tb")
        assert changed
        assert result == "a b"

    def test_null_byte_replaced(self) -> None:
        result, changed = neutralise_formula_prefix("a\x00b")
        assert changed
        assert result == "a b"

    def test_plain_text_untouched(self) -> None:
        result, changed = neutralise_formula_prefix("營業收入")
        assert not changed
        assert result == "營業收入"


