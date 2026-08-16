"""CSV parser: encoding detection -> pandas text parse -> cells.

Design notes:
- ``dtype=str`` + ``keep_default_na=False`` + ``na_filter=False``:
  no type coercion (leading zeros survive), no NaN/NA magic.
- null bytes are replaced before parsing (pandas C engine rejects
  them); they are never legitimate CSV content.
- the first row is the header row; header cells are parsed as cells
  too so detection covers them (column = their own header text).
"""

from __future__ import annotations

import io

import pandas as pd

from secure_ai_gateway.errors import ParsingError, ResourceLimitError
from secure_ai_gateway.limits import ResourceLimits
from secure_ai_gateway.parsers.base import (
    CellBuilder,
    decode_text_bytes,
    finish_parsed,
    make_column_labels,
)


def parse_csv_bytes(data: bytes, file_name: str, limits: ResourceLimits):
    text, encoding = decode_text_bytes(data)
    if "\x00" in text:
        text = text.replace("\x00", " ")
    try:
        frame = pd.read_csv(
            io.StringIO(text),
            dtype=str,
            keep_default_na=False,
            na_filter=False,
            on_bad_lines="error",
        )
    except pd.errors.ParserError as exc:
        raise ParsingError(f"csv parse failed: {exc}") from exc

    data_rows = len(frame)
    if data_rows + 1 > limits.max_rows:
        raise ResourceLimitError(
            f"row count {data_rows + 1} exceeds max_rows={limits.max_rows}"
        )
    col_count = max(1, frame.shape[1])
    if (data_rows + 1) * col_count > limits.max_cells:
        raise ResourceLimitError(
            f"cell count exceeds max_cells={limits.max_cells}"
        )

    headers = tuple(str(h) for h in frame.columns)
    labels = make_column_labels(headers)

    builder = CellBuilder(limits)
    for i, header in enumerate(headers):
        builder.add(
            row=0, col_index=i, column=labels[i], raw_value=header
        )
    for row_index, (_, row) in enumerate(frame.iterrows(), start=1):
        for col_index, value in enumerate(row):
            builder.add(
                row=row_index,
                col_index=col_index,
                column=labels[col_index],
                raw_value=str(value) if value != "" else None,
            )
    return finish_parsed(
        file_name,
        len(data),
        encoding,
        "csv",
        data_rows + 1,
        builder,
        headers,
    )
