"""Plain-text parser: one non-empty line = one cell."""

from __future__ import annotations

from secure_ai_gateway.errors import ResourceLimitError
from secure_ai_gateway.limits import ResourceLimits
from secure_ai_gateway.parsers.base import (
    CellBuilder,
    decode_text_bytes,
    finish_parsed,
)


def parse_text_bytes(data: bytes, file_name: str, limits: ResourceLimits):
    text, encoding = decode_text_bytes(data)
    lines = text.splitlines()
    if len(lines) > limits.max_rows:
        raise ResourceLimitError(
            f"line count {len(lines)} exceeds max_rows={limits.max_rows}"
        )

    builder = CellBuilder(limits)
    for index, line in enumerate(lines):
        builder.add(
            row=index,
            col_index=0,
            column="col_0",
            raw_value=line if line != "" else None,
        )
    return finish_parsed(
        file_name,
        len(data),
        encoding,
        "text",
        len(lines),
        builder,
        (),
    )
