"""Unit tests for the M3 Anthropic provider + stdlib transport.

No network is ever touched: FakeTransport captures calls; the real
UrllibTransport is exercised by monkeypatching urlopen. Error bodies
never leave the transport (DESIGN §18).
"""

from __future__ import annotations

import io
import json
import urllib.error
from typing import Mapping

import pytest

from secure_ai_gateway.errors import (
    ProviderConfigurationError,
    ProviderConnectionError,
    ProviderHTTPError,
    ProviderTimeoutError,
    ResponseParseError,
)
from secure_ai_gateway.llm.provider import (
    ANTHROPIC_VERSION,
    AnthropicProvider,
    UrllibTransport,
)
from secure_ai_gateway.llm.request_builder import LLMRequest, build_request
from secure_ai_gateway.models import DocumentCell
from secure_ai_gateway.policy.templates import resolve_template

_OK_PAYLOAD = {"type": "message", "content": [{"type": "text", "text": "34.2%"}]}


class FakeTransport:
    """Captures (endpoint, headers, body, timeout); serves a canned
    payload or raises a canned exception. No network."""

    def __init__(self, payload: object) -> None:
        self._payload = payload
        self.calls: list[tuple[str, dict, dict, float]] = []

    def request_json(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        body: dict[str, object],
        *,
        timeout: float,
    ) -> dict[str, object]:
        self.calls.append((endpoint, dict(headers), body, timeout))
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload  # type: ignore[return-value]


def _request() -> LLMRequest:
    cells = (DocumentCell("r1_c0", "客戶", "PERSON_a1b2c3d4", 1),)
    return build_request(
        protected_cells=cells,
        protected_instruction="請分析",
        template=resolve_template("gross_margin"),
    )


class TestProviderConstruction:
    def test_missing_key_raises_at_construction(self, monkeypatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ProviderConfigurationError):
            AnthropicProvider(FakeTransport(_OK_PAYLOAD))

    def test_env_key_read_at_construction(self, monkeypatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env")
        provider = AnthropicProvider(FakeTransport(_OK_PAYLOAD))
        assert provider is not None

    def test_explicit_key_overrides_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env")
        transport = FakeTransport(_OK_PAYLOAD)
        provider = AnthropicProvider(transport, api_key="sk-explicit")
        provider.complete(_request())
        (_, headers, _, _) = transport.calls[0]
        assert headers["x-api-key"] == "sk-explicit"


class TestProviderCall:
    def test_endpoint_and_headers(self) -> None:
        transport = FakeTransport(_OK_PAYLOAD)
        provider = AnthropicProvider(transport, api_key="sk-test")
        assert provider.complete(_request()) == "34.2%"
        (endpoint, headers, _, _) = transport.calls[0]
        assert endpoint == "https://api.anthropic.com/v1/messages"
        assert headers["x-api-key"] == "sk-test"
        assert headers["anthropic-version"] == ANTHROPIC_VERSION
        assert headers["content-type"] == "application/json"

    def test_api_key_never_in_body_or_json(self) -> None:
        transport = FakeTransport(_OK_PAYLOAD)
        provider = AnthropicProvider(transport, api_key="sk-super-secret")
        provider.complete(_request())
        (_, headers, body, _) = transport.calls[0]
        assert headers["x-api-key"] == "sk-super-secret"
        assert "sk-super-secret" not in json.dumps(body)

    def test_timeout_passed_to_transport(self) -> None:
        transport = FakeTransport(_OK_PAYLOAD)
        provider = AnthropicProvider(transport, api_key="sk-test", timeout=7.5)
        provider.complete(_request())
        assert transport.calls[0][3] == 7.5

    def test_provider_error_propagates(self) -> None:
        transport = FakeTransport(ProviderHTTPError(429))
        provider = AnthropicProvider(transport, api_key="sk-test")
        with pytest.raises(ProviderHTTPError) as exc:
            provider.complete(_request())
        assert exc.value.status_code == 429

    def test_response_parse_error_propagates(self) -> None:
        transport = FakeTransport({"type": "error", "error": {}})
        provider = AnthropicProvider(transport, api_key="sk-test")
        with pytest.raises(ResponseParseError):
            provider.complete(_request())


class TestUrllibTransport:
    def _fake_urlopen(self, monkeypatch, callable_) -> None:
        monkeypatch.setattr("urllib.request.urlopen", callable_)

    def _raises(self, exc: Exception):
        def fake(*a, **kw):
            raise exc

        return fake

    def test_http_error_maps_status_and_hides_body(self, monkeypatch) -> None:
        body = io.BytesIO(b'{"error":{"message":"echo sk-live-xyz"}}')
        http_error = urllib.error.HTTPError(
            "https://api.anthropic.com/v1/messages",
            401,
            "Unauthorized",
            {},
            body,
        )
        self._fake_urlopen(monkeypatch, self._raises(http_error))
        with pytest.raises(ProviderHTTPError) as exc:
            UrllibTransport().request_json(
                "https://x", {"k": "v"}, {"a": 1}, timeout=1.0
            )
        assert exc.value.status_code == 401
        assert "sk-live-xyz" not in str(exc.value)

    def test_timeout_error_maps(self, monkeypatch) -> None:
        self._fake_urlopen(monkeypatch, self._raises(TimeoutError()))
        with pytest.raises(ProviderTimeoutError):
            UrllibTransport().request_json("https://x", {}, {"a": 1}, timeout=1.0)

    def test_connection_error_maps(self, monkeypatch) -> None:
        self._fake_urlopen(
            monkeypatch,
            self._raises(
                urllib.error.URLError("[Errno -2] Name or service not known")
            ),
        )
        with pytest.raises(ProviderConnectionError):
            UrllibTransport().request_json("https://x", {}, {"a": 1}, timeout=1.0)

    def test_other_oserror_maps(self, monkeypatch) -> None:
        self._fake_urlopen(monkeypatch, self._raises(ConnectionResetError()))
        with pytest.raises(ProviderConnectionError):
            UrllibTransport().request_json("https://x", {}, {"a": 1}, timeout=1.0)

    def test_non_json_body_maps_to_parse_error(self, monkeypatch) -> None:
        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b"<html>not json</html>"

        self._fake_urlopen(monkeypatch, lambda *a, **kw: FakeResp())
        with pytest.raises(ResponseParseError):
            UrllibTransport().request_json("https://x", {}, {"a": 1}, timeout=1.0)

    def test_successful_call_parses_json(self, monkeypatch) -> None:
        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b'{"type":"message","content":[]}'

        self._fake_urlopen(monkeypatch, lambda *a, **kw: FakeResp())
        payload = UrllibTransport().request_json("https://x", {}, {"a": 1}, timeout=1.0)
        assert payload == {"type": "message", "content": []}
