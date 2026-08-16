"""Document parsers (CSV / XLSX / plain text) with fail-closed limits."""

from __future__ import annotations

from pathlib import Path

from secure_ai_gateway.errors import ParsingError, ResourceLimitError
from secure_ai_gateway.limits import ResourceLimits
from secure_ai_gateway.models import ParsedDocument


def parse_document(path: str | Path, limits: ResourceLimits) -> ParsedDocument:
    """Parse a document file into a ParsedDocument (fail closed)."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix not in {".csv", ".xlsx", ".txt", ".text"}:
        raise ParsingError(f"unsupported file type: {suffix!r}")

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ParsingError(f"cannot stat file: {exc}") from exc
    if size > limits.max_file_bytes:
        raise ResourceLimitError(
            f"file size {size} exceeds max_file_bytes={limits.max_file_bytes}"
        )
    data = path.read_bytes()

    if suffix == ".xlsx":
        from secure_ai_gateway.parsers.xlsx_parser import parse_xlsx_bytes

        return parse_xlsx_bytes(data, path.name, limits)
    if suffix == ".csv":
        from secure_ai_gateway.parsers.csv_parser import parse_csv_bytes

        return parse_csv_bytes(data, path.name, limits)
    from secure_ai_gateway.parsers.text_parser import parse_text_bytes

    return parse_text_bytes(data, path.name, limits)
