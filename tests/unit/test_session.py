"""Unit tests for the M3 session orchestrator.

The session owns the vault and clears it on every path (SR-019);
provider failures fail closed with ``error:<ClassName>`` and never
leak raw content into logs.
"""

from __future__ import annotations

import logging
import re

import pytest

from secure_ai_gateway.errors import ProviderHTTPError, ResponseParseError
from secure_ai_gateway.llm.request_builder import LLMRequest
from secure_ai_gateway.llm.response_parser import ParsedResponse
from secure_ai_gateway.models import (
    CellDetection,
    DetectionSpan,
    Disposition,
    EntityType,
    SpanSource,
)
from secure_ai_gateway.pipeline import Pipeline
from secure_ai_gateway.session import Session

_TOKEN_RE = re.compile(r"[A-Z][A-Z0-9]*_[0-9a-f]{8}")


class StubEngine:
    """Duck-typed DetectionEngine; instruction-aware."""

    def __init__(
        self,
        spans_by_cell: dict[str, tuple[DetectionSpan, ...]],
        instruction_spans: tuple[DetectionSpan, ...] = (),
    ):
        self._spans = spans_by_cell
        self._instruction_spans = instruction_spans

    def analyze_cell(self, cell):
        return CellDetection(
            cell_id=cell.cell_id,
            spans=self._spans.get(cell.cell_id, ()),
        )

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]:
        return self._instruction_spans


def _span(
    entity: EntityType,
    start: int,
    end: int,
    raw: str,
) -> DetectionSpan:
    return DetectionSpan(entity, start, end, 0.9, SpanSource.PATTERN, raw)


class CapturingPipeline(Pipeline):
    """Pipeline that keeps the session vault for post-run assertions."""

    def __init__(self, engine):
        super().__init__(engine)
        self.last_vault = None

    def process_file(self, *args, **kwargs):
        result = super().process_file(*args, **kwargs)
        self.last_vault = result[3]
        return result


class FakeProvider:
    """Duck-typed LLMProvider; records requests, can raise on demand."""

    def __init__(self, text: str = "mock answer") -> None:
        self._text = text
        self.requests: list[LLMRequest] = []
        self.raise_exc: Exception | None = None

    def complete(self, request: LLMRequest) -> ParsedResponse:
        self.requests.append(request)
        if self.raise_exc is not None:
            raise self.raise_exc
        return ParsedResponse(text=self._text, stop_reason="end_turn")


@pytest.fixture
def pii_csv(tmp_path):
    f = tmp_path / "pii.csv"
    f.write_bytes("客戶,營業收入\n王小明,8.4M\n".encode())
    return f


class TestSessionFlow:
    def test_delivered_session(self, pii_csv) -> None:
        pipe = CapturingPipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)})
        )
        provider = FakeProvider(text="毛利 34.2%")
        result = Session(pipe, provider).run(
            pii_csv, instruction="請分析", request_id="r1"
        )
        assert result.delivered
        assert result.response_text == "毛利 34.2%"
        assert result.request_id == "r1"
        assert result.decision.disposition_for("r1_c0") is Disposition.TOKENISE
        assert len(pipe.last_vault) == 0  # destroyed at session end

    def test_m2_mode_no_provider_still_clears_vault(self, pii_csv) -> None:
        pipe = CapturingPipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)})
        )
        result = Session(pipe).run(pii_csv, request_id="r1")
        assert not result.delivered
        assert result.response_text == ""
        assert len(pipe.last_vault) == 0

    def test_blocked_session_never_calls_provider(self, tmp_path) -> None:
        f = tmp_path / "s.csv"
        f.write_bytes("客戶,收入\nsk-live-abc,8.4M\n".encode())
        provider = FakeProvider()
        pipe = CapturingPipeline(
            StubEngine({"r1_c0": (_span(EntityType.API_KEY, 0, 11, "sk-live-abc"),)})
        )
        result = Session(pipe, provider).run(f, request_id="r1")
        assert result.decision.is_blocked()
        assert result.decision.reason == "secret:API_KEY"
        assert not result.delivered
        assert provider.requests == []
        assert len(pipe.last_vault) == 0


class TestFailClosed:
    def test_provider_error_blocks(self, pii_csv, caplog) -> None:
        pipe = CapturingPipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)})
        )
        provider = FakeProvider()
        provider.raise_exc = ProviderHTTPError(429)
        with caplog.at_level(logging.ERROR, logger="secure_ai_gateway"):
            result = Session(pipe, provider).run(pii_csv, request_id="r1")
        assert result.decision.is_blocked()
        assert result.decision.reason == "error:ProviderHTTPError"
        assert not result.delivered
        assert len(pipe.last_vault) == 0

    def test_parse_error_blocks(self, pii_csv) -> None:
        pipe = CapturingPipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)})
        )
        provider = FakeProvider()
        provider.raise_exc = ResponseParseError("no text")
        result = Session(pipe, provider).run(pii_csv, request_id="r1")
        assert result.decision.reason == "error:ResponseParseError"

    def test_unexpected_error_blocks(self, pii_csv) -> None:
        pipe = CapturingPipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)})
        )
        provider = FakeProvider()
        provider.raise_exc = RuntimeError("boom")
        result = Session(pipe, provider).run(pii_csv, request_id="r1")
        assert result.decision.reason == "error:RuntimeError"

    def test_logs_never_carry_raw_or_response(self, pii_csv, caplog) -> None:
        pipe = CapturingPipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)})
        )
        provider = FakeProvider(text="內含機密字樣")
        with caplog.at_level(logging.DEBUG, logger="secure_ai_gateway"):
            Session(pipe, provider).run(pii_csv, request_id="r1")
        records = " ".join(r.getMessage() for r in caplog.records)
        assert "王小明" not in records
        assert "內含機密字樣" not in records
        assert f"response_chars={len('內含機密字樣')}" in records  # counts only


class TestResultSafety:
    def test_repr_hides_response_text(self, pii_csv) -> None:
        pipe = CapturingPipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)})
        )
        provider = FakeProvider(text="secret response body")
        result = Session(pipe, provider).run(pii_csv, request_id="r1")
        assert "secret response body" not in repr(result)

    def test_instruction_and_document_share_one_token(self, pii_csv) -> None:
        # Same raw value in document and instruction -> exactly one
        # token on the wire (SR-022: instruction passes the same
        # pipeline and shares the session vault).
        engine = StubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
            instruction_spans=(_span(EntityType.PERSON, 3, 6, "王小明"),),
        )
        pipe = CapturingPipeline(engine)
        provider = FakeProvider()
        Session(pipe, provider).run(
            pii_csv, instruction="請分析王小明", request_id="r1"
        )
        (request,) = provider.requests
        content = request.to_body()["messages"][0]["content"]
        tokens = set(_TOKEN_RE.findall(content))
        assert len(tokens) == 1
        assert "王小明" not in content
