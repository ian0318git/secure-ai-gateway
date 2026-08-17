"""Anthropic provider with an injectable stdlib transport (M3).

One provider behind the LLMProvider protocol (DESIGN §16). The HTTP
transport is injectable so tests never touch the network; the real
UrllibTransport uses only stdlib urllib (zero new dependencies).

The API key appears in exactly one place: the outbound ``x-api-key``
header. It is never in the body, never in repr, never in exceptions,
never logged (SR-011).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Mapping, Protocol

from secure_ai_gateway.errors import (
    ProviderConfigurationError,
    ProviderConnectionError,
    ProviderError,
    ProviderHTTPError,
    ProviderTimeoutError,
    ResponseParseError,
)
from secure_ai_gateway.llm.request_builder import LLMRequest
from secure_ai_gateway.llm.response_parser import (
    ParsedResponse,
    parse_response,
)

API_ENDPOINT = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_TIMEOUT_SECONDS = 30.0
_API_KEY_ENV = "ANTHROPIC_API_KEY"


class Transport(Protocol):
    """HTTP transport abstraction; injectable for tests."""

    def request_json(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        body: dict[str, object],
        *,
        timeout: float,
    ) -> dict[str, object]:
        """POST JSON, return the parsed response object.

        Raises ProviderError subclasses on failure; error bodies never
        leave the transport (read once, discarded — DESIGN §18).
        """
        ...


class UrllibTransport:
    """stdlib ``urllib.request`` POST.

    Error bodies are read once and discarded — they may echo the
    request payload (DESIGN §18). Exceptions carry status codes and
    static messages only.
    """

    def __init__(self, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout

    def request_json(
        self,
        endpoint: str,
        headers: Mapping[str, str],
        body: dict[str, object],
        *,
        timeout: float | None = None,
    ) -> dict[str, object]:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            endpoint, data=data, headers=dict(headers), method="POST"
        )
        try:
            with urllib.request.urlopen(
                req, timeout=self._timeout if timeout is None else timeout
            ) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            exc.read()  # read once and discard — may echo the payload
            raise ProviderHTTPError(exc.code) from exc
        except TimeoutError as exc:
            raise ProviderTimeoutError("provider call timed out") from exc
        except urllib.error.URLError as exc:
            raise ProviderConnectionError(
                f"provider unreachable: {exc.reason}"
            ) from exc
        except OSError as exc:
            raise ProviderConnectionError(
                f"provider unreachable: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise ResponseParseError("provider response is not JSON") from exc
        if not isinstance(payload, dict):
            raise ResponseParseError("provider response is not an object")
        return payload


class LLMProvider(Protocol):
    """External LLM behind the gateway boundary (DESIGN §16)."""

    def complete(self, request: LLMRequest) -> ParsedResponse:
        """Send the protected request, return the parsed response."""
        ...


class AnthropicProvider:
    """Anthropic Messages API provider (M3; one provider, DESIGN §20).

    The API key is read from the ``ANTHROPIC_API_KEY`` environment
    variable at construction (or passed explicitly, for tests). A
    missing key raises ProviderConfigurationError: the gateway fails
    closed before any call, with no silent fake fallback.
    """

    def __init__(
        self,
        transport: Transport | None = None,
        *,
        api_key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        key = api_key if api_key is not None else os.environ.get(_API_KEY_ENV)
        if not key:
            raise ProviderConfigurationError(
                "ANTHROPIC_API_KEY is not set; provider calls are "
                "impossible (fail closed)"
            )
        self._api_key = key
        self._timeout = timeout
        self._transport = (
            transport if transport is not None else UrllibTransport()
        )

    def complete(self, request: LLMRequest) -> ParsedResponse:
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        payload = self._transport.request_json(
            API_ENDPOINT,
            headers,
            request.to_body(),
            timeout=self._timeout,
        )
        return parse_response(payload)
