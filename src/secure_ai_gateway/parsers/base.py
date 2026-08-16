"""Shared parser helpers.

Formula-prefix neutralisation implements SR-025 / T-T04 (CWE-1236):
cells beginning with a formula prefix are neutralised so downstream
tooling can never interpret them as executable content.
"""

from __future__ import annotations

import unicodedata

from secure_ai_gateway.encoding import decode_document, detect_encoding
from secure_ai_gateway.errors import ResourceLimitError
from secure_ai_gateway.limits import ResourceLimits, estimate_tokens
from secure_ai_gateway.models import DocumentCell, ParsedDocument, ParseStats

# "+" is never a legitimate leading character of a financial VALUE
# (spreadsheets treat it as a formula, CWE-1236); "-" is a legitimate
# negative-number sign, so it is only neutralised when NOT followed by
# a digit or "." — "-5.7M" survives, "-SUM(A1)" is neutralised.
_ALWAYS_FORMULA = ("+", "=", "@", "＋", "＝", "＠")
_CONDITIONAL_FORMULA = ("-", "－", "−")  # U+2212: math minus (NFKC -> "-")
_NUMBERISH = set("0123456789.")

_NFKC = unicodedata.normalize


def neutralise_formula_prefix(value: str) -> tuple[str, bool]:
    """Neutralise formula-injection prefixes in a cell value.

    Returns ``(value, neutralised)``.

    Rules (deterministic):
    - internal tab/CR/LF and null bytes are replaced with spaces
      (they break tabular structure downstream — CWE-1236);
    - leading ``=`` / ``@`` (ASCII or full-width): always neutralised
      (no legitimate financial value starts with them);
    - leading ``+`` / ``-`` (ASCII or full-width): neutralised only
      when the next character is not a digit or ``.`` — so a negative
      number like ``-5.7M`` is preserved while ``-SUM(A1)`` is not;
    - neutralisation = prefix a single quote ``'``.
    """
    neutralised = False
    if "\x00" in value:
        value = value.replace("\x00", " ")
        neutralised = True
    for ch in ("\t", "\r", "\n"):
        if ch in value:
            value = value.replace(ch, " ")
            neutralised = True
    if value:
        head = value[0]
        if head in _ALWAYS_FORMULA:
            return "'" + value, True
        if head in _CONDITIONAL_FORMULA:
            if len(value) == 1 or value[1] not in _NUMBERISH:
                return "'" + value, True
    return value, neutralised


def normalise(value: str) -> str:
    """NFKC normalisation — applied exactly once, at parse time.

    The whole pipeline and the benchmark share this coordinate space
    (docs/BENCHMARK.md §3).
    """
    return _NFKC("NFKC", value)


def make_column_labels(headers: tuple[str, ...]) -> tuple[str, ...]:
    """Resolve per-column labels.

    Empty or duplicated header text falls back to a positional
    ``col_<i>`` label so policy column matching stays deterministic.
    """
    seen: set[str] = set()
    labels: list[str] = []
    for i, header in enumerate(headers):
        base = header.strip() if header.strip() else f"col_{i}"
        if base in seen:
            base = f"{base}_{i}"
        seen.add(base)
        labels.append(base)
    return tuple(labels)


# BOMs of the encodings we support: data that starts with one of these
# is a genuine UTF-16/32 stream; anything else with null bytes is text
# with embedded NULs (which would mislead charset-normalizer into a
# UTF-16 guess and produce mojibake — T-I09).
_BOMS = (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff", b"\xff\xfe", b"\xfe\xff")


def decode_text_bytes(data: bytes) -> tuple[str, str]:
    """Detect encoding and strictly decode (T-I09 / SR-025).

    Returns ``(text, encoding)`` so stats can report the real codec.

    Embedded NUL bytes are replaced with spaces at the BYTE level
    BEFORE detection: charset-normalizer reads ``\\x00`` as a UTF-16
    signal and would otherwise decode plain text into mojibake that
    hides PII from the detectors. Genuine BOM-led UTF-16/32 files pass
    through untouched.
    """
    if b"\x00" in data and not data.startswith(_BOMS):
        data = data.replace(b"\x00", b" ")
    encoding = detect_encoding(data)
    return decode_document(data, encoding), encoding


class CellBuilder:
    """Enforces per-cell limits and builds DocumentCells."""

    def __init__(self, limits: ResourceLimits) -> None:
        self._limits = limits
        self._cells: list[DocumentCell] = []
        self._skipped_empty = 0
        self._neutralised = 0

    def add(
        self,
        row: int,
        col_index: int,
        column: str,
        raw_value: str | None,
    ) -> None:
        if raw_value is None or raw_value == "":
            self._skipped_empty += 1
            return
        if len(raw_value) > self._limits.max_cell_chars:
            raise ResourceLimitError(
                f"cell r{row}_c{col_index} exceeds "
                f"max_cell_chars={self._limits.max_cell_chars}"
            )
        value, changed = neutralise_formula_prefix(raw_value)
        if changed:
            self._neutralised += 1
        cell_id = f"r{row}_c{col_index}"
        self._cells.append(
            DocumentCell(
                cell_id=cell_id,
                column=column,
                value=normalise(value),
                row=row,
            )
        )

    def mark_formula_cell(self) -> None:
        """Count a formula cell whose text was kept out of the pipeline."""
        self._neutralised += 1

    @property
    def cells(self) -> tuple[DocumentCell, ...]:
        return tuple(self._cells)

    @property
    def skipped_empty(self) -> int:
        return self._skipped_empty

    @property
    def neutralised(self) -> int:
        return self._neutralised


def build_stats(
    file_name: str,
    file_size_bytes: int,
    encoding: str,
    format_: str,
    row_count: int,
    builder: CellBuilder,
    column_count: int,
) -> ParseStats:
    total_chars = sum(len(c.value) for c in builder.cells)
    return ParseStats(
        file_name=file_name,
        file_size_bytes=file_size_bytes,
        encoding=encoding,
        format=format_,
        row_count=row_count,
        cell_count=len(builder.cells),
        column_count=column_count,
        estimated_tokens=estimate_tokens(total_chars),
        neutralised_formula_cells=builder.neutralised,
        skipped_empty_cells=builder.skipped_empty,
    )


def finish_parsed(
    file_name: str,
    file_size_bytes: int,
    encoding: str,
    format_: str,
    row_count: int,
    builder: CellBuilder,
    headers: tuple[str, ...],
) -> ParsedDocument:
    stats = build_stats(
        file_name,
        file_size_bytes,
        encoding,
        format_,
        row_count,
        builder,
        len(headers),
    )
    return ParsedDocument(stats=stats, cells=builder.cells, headers=headers)
