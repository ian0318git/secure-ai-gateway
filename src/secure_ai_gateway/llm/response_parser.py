"""Anthropic Messages response parser (M3 + stop_reason plumbing, M4).

Extracts plain text and the ``stop_reason`` from a provider response.
Response protection (scanning, token leakage detection, restoration)
is milestone M4 — this module only parses. Fail closed: anything
malformed raises ResponseParseError, and the payload is never retained.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from secure_ai_gateway.errors import ResponseParseError


@dataclass(frozen=True, slots=True)
class ParsedResponse:
    """Parsed provider response: text plus completion metadata.

    ``stop_reason`` is used by the M4 response guard (``max_tokens``
    truncation is a violation by decision). ``text`` is repr-hidden.
    """

    text: str = field(repr=False)
    stop_reason: str | None = None


def parse_response(payload: dict[str, Any]) -> ParsedResponse:
    """Parse a response payload into text + stop_reason (fail closed).

    Reuses every check in ``parse_response_text``; a malformed
    ``stop_reason`` (present but not a string) is also a parse error.
    """
    text = parse_response_text(payload)
    stop_reason = payload.get("stop_reason")
    if stop_reason is not None and not isinstance(stop_reason, str):
        raise ResponseParseError("stop_reason must be a string")
    return ParsedResponse(text=text, stop_reason=stop_reason)


def parse_response_text(payload: dict[str, Any]) -> str:
    """Extract plain text from an Anthropic Messages response payload.

    ``content`` is a list of blocks; text blocks are joined in order
    with ``\\n``, non-text blocks (tool_use, thinking) are skipped.

    Raises ResponseParseError on: a non-object payload, an error
    envelope (``{"type": "error", ...}``), missing or non-list
    ``content``, a malformed block, or zero text blocks — which
    includes 200-with-refusal responses (Opus 5 safety refusals return
    200 with empty content). The payload is never copied into the
    exception and never retained.
    """
    if not isinstance(payload, dict):
        raise ResponseParseError("provider response is not an object")
    if payload.get("type") == "error":
        raise ResponseParseError("provider returned an error envelope")
    content = payload.get("content")
    if not isinstance(content, list):
        raise ResponseParseError("provider response has no content list")
    parts: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            raise ResponseParseError("provider response block is malformed")
        if block.get("type") != "text":
            continue  # tool_use / thinking blocks are not response text
        text = block.get("text")
        if not isinstance(text, str):
            raise ResponseParseError("provider text block is malformed")
        parts.append(text)
    if not parts:
        raise ResponseParseError("provider response contains no text")
    return "\n".join(parts)
