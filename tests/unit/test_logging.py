"""Sanitised logging: forbidden field keys are rejected."""

from __future__ import annotations

import logging

import pytest

from secure_ai_gateway.logging import is_sanitised_fields, log_event


@pytest.fixture
def logger() -> logging.Logger:
    return logging.getLogger("test.sanitised")


class TestIsSanitisedFields:
    def test_clean_fields_pass(self) -> None:
        assert is_sanitised_fields({"request_id": "r1", "cell_count": 3})

    def test_raw_key_rejected(self) -> None:
        assert not is_sanitised_fields({"raw_value": "sensitive"})

    @pytest.mark.parametrize(
        "key",
        ["payload", "content", "body", "snippet", "secret", "api_key",
         "token_value", "mapping", "credential"],
    )
    def test_forbidden_keys_rejected(self, key: str) -> None:
        assert not is_sanitised_fields({key: "x"})


class TestLogEvent:
    def test_clean_event_logged(self, logger: logging.Logger, caplog) -> None:
        with caplog.at_level(logging.INFO, logger="test.sanitised"):
            log_event(logger, "parsed", request_id="r1", cell_count=3)
        assert any("parsed" in r.message and "cell_count=3" in r.message
                   for r in caplog.records)

    def test_forbidden_key_raises(self, logger: logging.Logger) -> None:
        with pytest.raises(ValueError, match="refusing to log"):
            log_event(logger, "parsed", raw_value="王大明")

    def test_forbidden_key_never_reaches_logger(
        self, logger: logging.Logger, caplog
    ) -> None:
        with (
            caplog.at_level(logging.INFO, logger="test.sanitised"),
            pytest.raises(ValueError),
        ):
            log_event(logger, "parsed", payload="secret")
        assert caplog.records == []
