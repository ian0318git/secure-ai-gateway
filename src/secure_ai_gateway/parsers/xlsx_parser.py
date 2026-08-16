"""XLSX parser with zip-bomb preflight (T-D02) and formula control.

Security controls:
- zip preflight BEFORE any decompression: member count and total
  declared uncompressed size are checked against limits
  (max_archive_members / max_decompressed_bytes). A crafted zip whose
  declared sizes lie is still bounded by the 10MB file limit and
  defusedxml hardens the XML parsing.
- two-parse formula control: the VALUES parse (``data_only=True``)
  never loads formula text — only cached values (or None when the
  formula was never calculated). A second parse (``data_only=False``)
  supplies formula COORDINATES only; openpyxl reports formula cells
  there even when the value parse loses them (uncached formulas read
  back as empty 'n' cells). Every formula cell is counted in
  ``neutralised_formula_cells``.
- non-``read_only`` mode so ``cell.data_type`` is available to
  detect formula cells; acceptable because the file-size limit bounds
  the workbook.
"""

from __future__ import annotations

import datetime
import io
import zipfile

from openpyxl import load_workbook
from openpyxl.utils.exceptions import InvalidFileException

from secure_ai_gateway.errors import ParsingError, ResourceLimitError
from secure_ai_gateway.limits import ResourceLimits
from secure_ai_gateway.parsers.base import (
    CellBuilder,
    finish_parsed,
    make_column_labels,
)


def _preflight(data: bytes, limits: ResourceLimits) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
    except zipfile.BadZipFile as exc:
        raise ParsingError(f"not a valid xlsx archive: {exc}") from exc
    if len(infos) > limits.max_archive_members:
        raise ResourceLimitError(
            f"archive member count {len(infos)} exceeds "
            f"max_archive_members={limits.max_archive_members}"
        )
    total = sum(info.file_size for info in infos)
    if total > limits.max_decompressed_bytes:
        raise ResourceLimitError(
            f"declared uncompressed size {total} exceeds "
            f"max_decompressed_bytes={limits.max_decompressed_bytes}"
        )


def _to_text(value) -> str:
    """Deterministic text conversion of a cached cell value."""
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    return str(value)


def parse_xlsx_bytes(data: bytes, file_name: str, limits: ResourceLimits):
    _preflight(data, limits)
    try:
        # values only: cached cell values, formula TEXT never loaded
        workbook = load_workbook(io.BytesIO(data), data_only=True)
        # formula coordinates: data_only=True loses the formula-ness of
        # uncached formulas (they read back as empty 'n' cells), so a
        # second parse with data_only=False identifies them. Only the
        # COORDINATES are taken from this parse — never the values.
        formula_workbook = load_workbook(io.BytesIO(data), data_only=False)
    except InvalidFileException as exc:
        raise ParsingError(f"cannot open xlsx workbook: {exc}") from exc
    except KeyError as exc:
        raise ParsingError(f"malformed xlsx workbook: {exc}") from exc

    sheet = workbook[workbook.sheetnames[0]]
    formula_sheet = formula_workbook[formula_workbook.sheetnames[0]]
    max_row = sheet.max_row or 0
    max_col = sheet.max_column or 0
    if max_row > limits.max_rows:
        raise ResourceLimitError(
            f"row count {max_row} exceeds max_rows={limits.max_rows}"
        )
    if max_row * max_col > limits.max_cells:
        raise ResourceLimitError(
            f"cell count {max_row * max_col} exceeds "
            f"max_cells={limits.max_cells}"
        )

    builder = CellBuilder(limits)
    headers: tuple[str, ...] = ()
    labels: tuple[str, ...] = ()

    for row_index, row in enumerate(sheet.iter_rows()):
        if row_index == 0:
            headers = tuple(
                _to_text(cell.value) if cell.value is not None else ""
                for cell in row
            )
            labels = make_column_labels(headers)

        for col_index, cell in enumerate(row):
            label = labels[col_index] if col_index < len(labels) else f"col_{col_index}"
            if (
                formula_sheet.cell(row=cell.row, column=cell.column).data_type
                == "f"
            ):
                # formula text is blocked from the pipeline (SR-025);
                # keep the cached value when one exists
                builder.mark_formula_cell()
                if cell.value is not None:
                    builder.add(
                        row=row_index,
                        col_index=col_index,
                        column=label,
                        raw_value=_to_text(cell.value),
                    )
            elif cell.value is not None:
                builder.add(
                    row=row_index,
                    col_index=col_index,
                    column=label,
                    raw_value=_to_text(cell.value),
                )

    return finish_parsed(
        file_name,
        len(data),
        "xlsx-binary",
        "xlsx",
        max_row,
        builder,
        headers,
    )
