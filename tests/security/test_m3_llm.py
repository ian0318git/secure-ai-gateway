"""M3 security acceptance suite — LLM integration threat traceability.

Every case maps to an M3 acceptance bullet (docs/POC_PLAN.md M3):
- raw PII is absent from the provider request
- secrets are absent (and the provider is never called on BLOCK)
- token mappings are absent (mapping stays in the vault; the vault is
  empty at session end — SR-019)
- raw identifiers in the user instruction do not reach the provider
- provider error bodies are never logged
- prompt caching is disabled (DESIGN §20)

Engine and transport are stubbed; no NLP model, no network.
"""

from __future__ import annotations

import json
import logging
import re

import pytest

from secure_ai_gateway.errors import ProviderHTTPError
from secure_ai_gateway.llm.provider import AnthropicProvider
from secure_ai_gateway.models import (
    CellDetection,
    DetectionSpan,
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


def _text_response(text: str) -> dict:
    return {"type": "message", "content": [{"type": "text", "text": text}]}


class CapturingPipeline(Pipeline):
    """Pipeline that keeps the session vault for post-run assertions."""

    def __init__(self, engine):
        super().__init__(engine)
        self.last_vault = None

    def process_file(self, *args, **kwargs):
        result = super().process_file(*args, **kwargs)
        self.last_vault = result[3]
        return result


class FakeTransport:
    """Captures (endpoint, headers, body); serves a canned payload."""

    def __init__(self, payload: object) -> None:
        self._payload = payload
        self.calls: list[tuple[str, dict, dict]] = []

    def request_json(self, endpoint, headers, body, *, timeout):
        self.calls.append((endpoint, dict(headers), body))
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload  # type: ignore[return-value]


@pytest.fixture
def pii_csv(tmp_path):
    f = tmp_path / "pii.csv"
    f.write_bytes("客戶,營業收入\n王小明,8.4M\n".encode("utf-8"))
    return f


class TestRawPiiAbsent:
    """Acceptance bullet 1: raw PII is absent from the provider request."""

    def test_no_raw_pii_on_wire(self, pii_csv) -> None:
        engine = StubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
            instruction_spans=(_span(EntityType.PERSON, 3, 6, "王小明"),),
        )
        transport = FakeTransport(_text_response("done"))
        result = Session(
            CapturingPipeline(engine),
            AnthropicProvider(transport, api_key="sk-test"),
        ).run(pii_csv, instruction="請分析王小明", request_id="r1")
        assert result.delivered
        (_, _, body) = transport.calls[0]
        wire = json.dumps(body, ensure_ascii=False)
        assert "王小明" not in wire
        assert "PERSON_" in wire  # tokenised values go to the provider


class TestSecretsAbsent:
    """Acceptance bullet 2: secrets never reach the provider."""

    def test_document_secret_blocks_and_provider_never_called(
        self, tmp_path
    ) -> None:
        f = tmp_path / "s.csv"
        f.write_bytes("客戶,收入\nsk-live-abc,8.4M\n".encode("utf-8"))
        engine = StubEngine(
            {"r1_c0": (_span(EntityType.API_KEY, 0, 11, "sk-live-abc"),)}
        )
        transport = FakeTransport(_text_response("should never arrive"))
        result = Session(
            CapturingPipeline(engine),
            AnthropicProvider(transport, api_key="sk-test"),
        ).run(f, request_id="r1")
        assert result.decision.is_blocked()
        assert result.decision.reason == "secret:API_KEY"
        assert transport.calls == []

    def test_instruction_secret_blocks_and_provider_never_called(
        self, pii_csv
    ) -> None:
        engine = StubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
            instruction_spans=(_span(EntityType.API_KEY, 3, 9, "sk-abc"),),
        )
        transport = FakeTransport(_text_response("should never arrive"))
        result = Session(
            CapturingPipeline(engine),
            AnthropicProvider(transport, api_key="sk-test"),
        ).run(pii_csv, instruction="請處理 sk-abc", request_id="r1")
        assert result.decision.reason == "secret:API_KEY"
        assert transport.calls == []

    def test_api_key_never_in_body(self, pii_csv) -> None:
        engine = StubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        transport = FakeTransport(_text_response("ok"))
        Session(
            CapturingPipeline(engine),
            AnthropicProvider(transport, api_key="sk-super-secret-value"),
        ).run(pii_csv, request_id="r1")
        (_, headers, body) = transport.calls[0]
        assert headers["x-api-key"] == "sk-super-secret-value"
        assert "sk-super-secret-value" not in json.dumps(body)


class TestTokenMappingsAbsent:
    """Acceptance bullet 3: mappings stay inside the vault (SR-002)."""

    def test_every_token_on_wire_is_a_live_reverse_map_key(
        self, pii_csv
    ) -> None:
        engine = StubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
            instruction_spans=(_span(EntityType.PERSON, 3, 6, "王小明"),),
        )
        pipe = CapturingPipeline(engine)

        class MappingAwareTransport(FakeTransport):
            def request_json(self, endpoint, headers, body, *, timeout):
                # The vault is STILL ALIVE at call time (mappings are
                # destroyed only at session end, SR-019): every token
                # on the wire must resolve through the live reverse map.
                wire = json.dumps(body, ensure_ascii=False)
                assert "王小明" not in wire
                tokens = _TOKEN_RE.findall(wire)
                assert tokens, "expected tokenised values on the wire"
                for token in tokens:
                    assert token in pipe.last_vault.tokens()
                    assert pipe.last_vault.restore(token) == "王小明"
                return super().request_json(
                    endpoint, headers, body, timeout=timeout
                )

        transport = MappingAwareTransport(_text_response("done"))
        result = Session(
            pipe, AnthropicProvider(transport, api_key="sk-test")
        ).run(pii_csv, instruction="請分析王小明", request_id="r1")
        assert result.delivered

    def test_vault_destroyed_at_session_end(self, pii_csv) -> None:
        engine = StubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        pipe = CapturingPipeline(engine)
        transport = FakeTransport(_text_response("done"))
        Session(
            pipe, AnthropicProvider(transport, api_key="sk-test")
        ).run(pii_csv, request_id="r1")
        vault = pipe.last_vault
        assert len(vault) == 0
        assert vault.restore("PERSON_ffffffff") is None
        assert vault.tokens() == ()


class TestInstructionChannel:
    """Acceptance bullet 4: instruction raw identifiers never reach the
    provider (SR-022), and the document shares the vault."""

    def test_raw_instruction_identifier_absent_and_token_shared(
        self, tmp_path
    ) -> None:
        f = tmp_path / "x.csv"
        f.write_bytes("客戶,收入\n王小明,8.4M\n".encode("utf-8"))
        engine = StubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
            instruction_spans=(_span(EntityType.PERSON, 3, 6, "王小明"),),
        )
        transport = FakeTransport(_text_response("done"))
        Session(
            CapturingPipeline(engine),
            AnthropicProvider(transport, api_key="sk-test"),
        ).run(f, instruction="請分析王小明", request_id="r1")
        wire = json.dumps(transport.calls[0][2], ensure_ascii=False)
        assert "王小明" not in wire
        # Document and instruction share the session vault: the SAME raw
        # value yields exactly ONE token on the wire.
        tokens = set(_TOKEN_RE.findall(wire))
        assert len(tokens) == 1

    def test_clean_instruction_reaches_provider(self, pii_csv) -> None:
        engine = StubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        transport = FakeTransport(_text_response("done"))
        Session(
            CapturingPipeline(engine),
            AnthropicProvider(transport, api_key="sk-test"),
        ).run(pii_csv, instruction="請分析毛利率趨勢", request_id="r1")
        wire = json.dumps(transport.calls[0][2], ensure_ascii=False)
        assert "請分析毛利率趨勢" in wire


class TestErrorBodiesNeverLogged:
    """Acceptance bullet 5: provider error bodies are never logged."""

    def test_provider_error_logs_reason_only(self, pii_csv, caplog) -> None:
        engine = StubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        transport = FakeTransport(ProviderHTTPError(429))
        with caplog.at_level(logging.DEBUG, logger="secure_ai_gateway"):
            result = Session(
                CapturingPipeline(engine),
                AnthropicProvider(transport, api_key="sk-test"),
            ).run(pii_csv, request_id="r1")
        records = " ".join(r.getMessage() for r in caplog.records)
        assert result.decision.reason == "error:ProviderHTTPError"
        assert "provider_blocked" in records
        assert "王小明" not in records  # raw never logged anywhere
        assert "sk-test" not in records  # api key never logged


class TestPromptCachingDisabled:
    """Acceptance bullet 6: prompt caching is disabled (DESIGN §20)."""

    def test_no_cache_control_on_wire(self, pii_csv) -> None:
        engine = StubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        transport = FakeTransport(_text_response("done"))
        Session(
            CapturingPipeline(engine),
            AnthropicProvider(transport, api_key="sk-test"),
        ).run(pii_csv, request_id="r1")
        (_, _, body) = transport.calls[0]
        # Recursive: cache_control is opt-in, so it must be absent from
        # every node of the body actually transmitted.
        stack: list[object] = [body]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                assert "cache_control" not in item
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
        assert "cache_control" not in json.dumps(body)


class TestEndToEnd:
    def test_delivered_session_response_text(self, pii_csv) -> None:
        engine = StubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        transport = FakeTransport(_text_response("毛利約 34.2%"))
        result = Session(
            CapturingPipeline(engine),
            AnthropicProvider(transport, api_key="sk-test"),
        ).run(pii_csv, instruction="請分析", request_id="r1")
        assert result.delivered
        assert result.response_text == "毛利約 34.2%"
        assert result.report.request_id == "r1"

    def test_report_has_no_raw_or_token(self, pii_csv) -> None:
        engine = StubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        transport = FakeTransport(_text_response("done"))
        result = Session(
            CapturingPipeline(engine),
            AnthropicProvider(transport, api_key="sk-test"),
        ).run(pii_csv, request_id="r1")
        json_text = result.report.to_json()
        assert "王小明" not in json_text
        for token in _TOKEN_RE.findall(json_text):
            raise AssertionError(f"token leaked into report: {token}")
        assert result.report.tokenised_spans == 1
