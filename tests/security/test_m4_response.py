"""M4 security acceptance suite — response protection threat traceability.

Every case maps to an M4 acceptance bullet (docs/POC_PLAN.md M4):
- sensitive or policy-violating responses are blocked (fail closed)
- unknown tokens are never restored
- known tokens are restored only via the authorised guard path
- leaked raw values are blocked even when the vault knows them
- reserved-token inventions are caught by the second-layer net
- marker echoes (task compliance) and truncation fail closed
- mappings stay inside the vault and are destroyed on every path
  (SR-019); logs and reports never carry raw response content

Engine and transport are stubbed; no NLP model, no network. The
provider and parser are real (AnthropicProvider + parse_response).
"""

from __future__ import annotations

import json
import logging
import re

import pytest

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

# Mirrors of the engine's deterministic recognisers (recognizers.py),
# so the stub behaves like the real response scan without spaCy.
# Reserved 6-hex token shapes (T-T03 / SR-023) — the second-layer net
# that catches inventions which do not match the issued 8-hex TOKEN_RE.
_RESERVED_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:CUSTOMER|EMPLOYEE|EMAIL|PHONE|ADDRESS|LOCATION)"
    r"_([0-9a-f]{6})(?![A-Za-z0-9_])"
)
# CUSTOMER-shaped identifiers (M2 flag: a live CUSTOMER_<hex8> token
# would be re-detected as PII by this recogniser if scanned BEFORE
# restoration — the guard restores first, so it never fires on tokens).
_CUSTOMER_ID_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:CUSTOMER|CUST(?!OMER))[-_]?"
    r"[A-Z0-9]{4,16}(?![A-Za-z0-9])"
)


class ResponseStubEngine:
    """Duck-typed DetectionEngine. ``analyze_text`` deterministically
    finds known raw values, reserved 6-hex shapes, and CUSTOMER-shaped
    identifiers — the finding families the real response scan emits."""

    def __init__(
        self,
        spans_by_cell: dict[str, tuple[DetectionSpan, ...]],
        raw_types: dict[str, EntityType] | None = None,
    ) -> None:
        self._spans = spans_by_cell
        self._raw_types = raw_types or {}

    def analyze_cell(self, cell):
        return CellDetection(
            cell_id=cell.cell_id,
            spans=self._spans.get(cell.cell_id, ()),
        )

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]:
        found: list[DetectionSpan] = []
        for raw, entity in self._raw_types.items():
            start = 0
            while True:
                idx = text.find(raw, start)
                if idx < 0:
                    break
                found.append(_span(entity, idx, idx + len(raw), raw))
                start = idx + len(raw)
        for m in _CUSTOMER_ID_RE.finditer(text):
            found.append(
                _span(EntityType.CUSTOMER_ID, m.start(), m.end(), m.group(0))
            )
        for m in _RESERVED_RE.finditer(text):
            found.append(
                _span(EntityType.TOKEN_PATTERN, m.start(), m.end(), m.group(0))
            )
        return tuple(found)


def _span(
    entity: EntityType,
    start: int,
    end: int,
    raw: str,
) -> DetectionSpan:
    return DetectionSpan(entity, start, end, 0.9, SpanSource.PATTERN, raw)


def _text_response(text: str, *, stop_reason: str | None = None) -> dict:
    payload: dict[str, object] = {
        "type": "message",
        "content": [{"type": "text", "text": text}],
    }
    if stop_reason is not None:
        payload["stop_reason"] = stop_reason
    return payload


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


class TokenEchoTransport:
    """Serves a response containing one LIVE vault token, read from the
    vault at request time (mappings are alive until session end,
    SR-019)."""

    def __init__(self, pipe: CapturingPipeline) -> None:
        self._pipe = pipe
        self.calls: list[tuple[str, dict, dict]] = []

    def request_json(self, endpoint, headers, body, *, timeout):
        self.calls.append((endpoint, dict(headers), body))
        token = self._pipe.last_vault.tokens()[0]
        return _text_response(f"該客戶 {token} 經營良好")


@pytest.fixture
def pii_csv(tmp_path):
    f = tmp_path / "pii.csv"
    f.write_bytes("客戶,營業收入\n王小明,8.4M\n".encode("utf-8"))
    return f


def _run(pipe, transport, path, **kwargs):
    return Session(
        pipe, AnthropicProvider(transport, api_key="sk-test")
    ).run(path, **kwargs)


class TestSensitiveResponsesBlocked:
    """Acceptance bullet: sensitive responses are blocked (fail closed)."""

    def test_raw_pii_in_response_blocks(self, pii_csv) -> None:
        # 王大明 never appeared in the document; the model could not
        # know it, so its presence in the response is a leak.
        engine = ResponseStubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
            raw_types={"王大明": EntityType.PERSON},
        )
        result = _run(
            CapturingPipeline(engine),
            FakeTransport(_text_response("王大明 是我們的客戶")),
            pii_csv,
            request_id="r1",
        )
        assert result.decision.is_blocked()
        assert result.decision.reason == "response:pii:PERSON"
        assert result.response_text == ""
        assert not result.delivered

    def test_leaked_known_value_blocks(self, pii_csv) -> None:
        # The raw value IS in the vault (王小明 was tokenised), but the
        # only authorised path back is restoration; a raw leak of a
        # known value is still blocked (leak-vs-restored soundness).
        engine = ResponseStubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
            raw_types={"王小明": EntityType.PERSON},
        )
        result = _run(
            CapturingPipeline(engine),
            FakeTransport(_text_response("王小明 的帳戶被洩漏")),
            pii_csv,
            request_id="r1",
        )
        assert result.decision.reason == "response:pii:PERSON"
        assert not result.delivered

    def test_secret_in_response_blocks(self, pii_csv) -> None:
        engine = ResponseStubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
            raw_types={"sk-live-abc": EntityType.API_KEY},
        )
        result = _run(
            CapturingPipeline(engine),
            FakeTransport(_text_response("密鑰是 sk-live-abc")),
            pii_csv,
            request_id="r1",
        )
        assert result.decision.reason == "response:secret:API_KEY"
        assert result.response_text == ""


class TestUnknownTokens:
    """Acceptance bullet: unknown tokens are never restored."""

    def test_invented_8hex_token_blocks(self, pii_csv) -> None:
        # CUSTOMER_1234abcd matches the issued-token shape but is not
        # in the vault — it is hallucinated, not restorable.
        engine = ResponseStubEngine({})
        result = _run(
            CapturingPipeline(engine),
            FakeTransport(_text_response("請見 CUSTOMER_1234abcd 的資料")),
            pii_csv,
            request_id="r1",
        )
        assert result.decision.reason == "response:unknown_token"
        assert result.response_text == ""
        assert not result.delivered

    def test_reserved_invention_caught_by_second_layer_net(
        self, pii_csv
    ) -> None:
        # 6-hex reserved shape (EMAIL_4f8a21) is not an issued token
        # (TOKEN_RE needs 8 hex) and not in the vault; the sensitive
        # scan catches it. EMAIL_ is used so the reserved-shape finding
        # is the ONLY one — CUSTOMER_ inventions also match the
        # CUSTOMER_ID recogniser first.
        engine = ResponseStubEngine({})
        result = _run(
            CapturingPipeline(engine),
            FakeTransport(_text_response("聯絡 EMAIL_4f8a21 取得報表")),
            pii_csv,
            request_id="r1",
        )
        assert result.decision.reason == "response:pii:TOKEN_PATTERN"
        assert not result.delivered


class TestRestoration:
    """Acceptance bullet: known tokens are restored (authorised path)."""

    def test_known_token_restored(self, pii_csv) -> None:
        engine = ResponseStubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
            raw_types={"王小明": EntityType.PERSON},
        )
        pipe = CapturingPipeline(engine)
        result = _run(
            pipe,
            TokenEchoTransport(pipe),
            pii_csv,
            instruction="請分析",
            request_id="r1",
        )
        assert result.delivered
        assert "王小明" in result.response_text  # authorised restoration
        assert _TOKEN_RE.search(result.response_text) is None  # no tokens left

    def test_customer_token_restored_before_scan(self, pii_csv) -> None:
        # M2 flag pin at session level (DECISIONS M2): the stub detects
        # CUSTOMER-shaped identifiers exactly like the real engine, so
        # a PRE-restore scan would re-detect the live CUSTOMER_<hex8>
        # token as PII and block. The guard restores first — the token
        # never reaches the scanner.
        engine = ResponseStubEngine(
            {"r1_c0": (_span(EntityType.CUSTOMER_ID, 0, 16, "Aurora Motors AU"),)}
        )
        pipe = CapturingPipeline(engine)
        result = _run(
            pipe,
            TokenEchoTransport(pipe),
            pii_csv,
            request_id="r1",
        )
        assert not result.decision.is_blocked()
        assert result.delivered
        assert "Aurora Motors AU" in result.response_text


class TestCompliance:
    """Task-compliance validation: framing markers may not be echoed."""

    def test_instruction_marker_echo_blocks(self, pii_csv) -> None:
        engine = ResponseStubEngine({})
        result = _run(
            CapturingPipeline(engine),
            FakeTransport(_text_response("請先看 <<<INSTRUCTION>>> 再回答")),
            pii_csv,
            request_id="r1",
        )
        assert result.decision.reason == "response:marker_echo"
        assert result.response_text == ""

    def test_document_marker_echo_blocks(self, pii_csv) -> None:
        engine = ResponseStubEngine({})
        result = _run(
            CapturingPipeline(engine),
            FakeTransport(_text_response("資料如下 <<<DOCUMENT_DATA>>> 完畢")),
            pii_csv,
            request_id="r1",
        )
        assert result.decision.reason == "response:marker_echo"
        assert not result.delivered


class TestTruncation:
    """A truncated response never reaches the user (fail closed)."""

    def test_max_tokens_truncation_blocks(self, pii_csv) -> None:
        engine = ResponseStubEngine({})
        result = _run(
            CapturingPipeline(engine),
            FakeTransport(_text_response("分析到一半", stop_reason="max_tokens")),
            pii_csv,
            request_id="r1",
        )
        assert result.decision.reason == "response:truncated"
        assert result.response_text == ""
        assert not result.delivered

    def test_end_turn_delivers(self, pii_csv) -> None:
        engine = ResponseStubEngine({})
        result = _run(
            CapturingPipeline(engine),
            FakeTransport(_text_response("分析完成", stop_reason="end_turn")),
            pii_csv,
            request_id="r1",
        )
        assert result.delivered
        assert result.response_text == "分析完成"


class TestFailClosedAccounting:
    """SR-019 / SR-009: mappings destroyed, logs and reports stay clean."""

    def test_response_blocked_logged_reason_only(self, pii_csv, caplog) -> None:
        engine = ResponseStubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
            raw_types={"王小明": EntityType.PERSON},
        )
        with caplog.at_level(logging.DEBUG, logger="secure_ai_gateway"):
            result = _run(
                CapturingPipeline(engine),
                FakeTransport(_text_response("王小明 是我們的客戶")),
                pii_csv,
                request_id="r1",
            )
        records = " ".join(r.getMessage() for r in caplog.records)
        assert result.decision.reason == "response:pii:PERSON"
        assert "response_blocked" in records
        assert "王小明" not in records  # raw response never logged
        assert "sk-test" not in records  # api key never logged

    def test_vault_destroyed_after_response_block(self, pii_csv) -> None:
        engine = ResponseStubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
            raw_types={"王小明": EntityType.PERSON},
        )
        pipe = CapturingPipeline(engine)
        result = _run(
            pipe,
            FakeTransport(_text_response("王小明 是我們的客戶")),
            pii_csv,
            request_id="r1",
        )
        assert result.decision.is_blocked()
        vault = pipe.last_vault
        assert len(vault) == 0  # SR-019: destroyed on the BLOCK path too
        assert vault.tokens() == ()
        assert vault.restore("PERSON_ffffffff") is None

    def test_report_never_carries_response(self, pii_csv) -> None:
        engine = ResponseStubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
            raw_types={"王小明": EntityType.PERSON},
        )
        pipe = CapturingPipeline(engine)
        result = _run(
            pipe,
            TokenEchoTransport(pipe),
            pii_csv,
            request_id="r1",
        )
        assert result.delivered
        json_text = result.report.to_json()
        assert "王小明" not in json_text  # restored raw never in report
        assert "經營良好" not in json_text  # response text never in report
        assert _TOKEN_RE.search(json_text) is None  # tokens never in report
