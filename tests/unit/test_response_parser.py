"""Unit tests for the M3 Anthropic response parser.

Fail-closed philosophy (DESIGN §17): anything malformed is a
ResponseParseError, and the payload is never copied into the
exception.
"""

from __future__ import annotations

import pytest

from secure_ai_gateway.errors import ResponseParseError
from secure_ai_gateway.llm.response_parser import parse_response_text


def _text_payload(*blocks: str) -> dict:
    return {
        "id": "msg_x",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": b} for b in blocks],
    }


class TestParseResponseText:
    def test_single_text_block(self) -> None:
        assert parse_response_text(_text_payload("毛利 34.2%")) == "毛利 34.2%"

    def test_multiple_text_blocks_joined_in_order(self) -> None:
        assert parse_response_text(_text_payload("first", "second")) == (
            "first\nsecond"
        )

    def test_non_text_blocks_skipped(self) -> None:
        payload = {
            "type": "message",
            "content": [
                {"type": "thinking", "thinking": "internal reasoning"},
                {"type": "text", "text": "answer"},
                {"type": "tool_use", "id": "t1", "name": "x", "input": {}},
            ],
        }
        assert parse_response_text(payload) == "answer"

    def test_empty_content_fails_closed(self) -> None:
        # 200-with-refusal responses have empty content
        with pytest.raises(ResponseParseError):
            parse_response_text({"type": "message", "content": []})

    def test_missing_content_fails_closed(self) -> None:
        with pytest.raises(ResponseParseError):
            parse_response_text({"type": "message"})

    def test_non_list_content_fails_closed(self) -> None:
        with pytest.raises(ResponseParseError):
            parse_response_text({"type": "message", "content": "text"})

    def test_error_envelope_fails_closed(self) -> None:
        with pytest.raises(ResponseParseError):
            parse_response_text(
                {"type": "error", "error": {"type": "overloaded_error"}}
            )

    def test_non_dict_payload_fails_closed(self) -> None:
        with pytest.raises(ResponseParseError):
            parse_response_text(["not", "a", "dict"])

    def test_malformed_block_fails_closed(self) -> None:
        with pytest.raises(ResponseParseError):
            parse_response_text({"type": "message", "content": ["junk"]})

    def test_text_block_without_text_field_fails_closed(self) -> None:
        with pytest.raises(ResponseParseError):
            parse_response_text(
                {"type": "message", "content": [{"type": "text"}]}
            )

    def test_error_message_never_carries_payload(self) -> None:
        secret = "TOP-SECRET-response-body"
        with pytest.raises(ResponseParseError) as exc:
            parse_response_text({"type": "error", "error": {"msg": secret}})
        assert secret not in str(exc.value)
