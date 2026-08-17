"""Gateway exception hierarchy.

All exceptions derive from GatewayError so the pipeline can fail
closed with a single handler. Exceptions never carry raw document
content or token values in their messages (see CLAUDE.md logging
rules).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secure_ai_gateway.models import EntityType


class GatewayError(Exception):
    """Base class for all gateway errors."""


class ResourceLimitError(GatewayError):
    """A resource limit (file size, rows, cells, tokens) was exceeded."""


class ParsingError(GatewayError):
    """A document could not be parsed safely."""


class EncodingDetectionError(GatewayError):
    """The document encoding could not be detected with confidence.

    Fail closed: never guess an encoding that might decode to
    mojibake and hide PII from the detectors.
    """


class PolicyError(GatewayError):
    """The policy engine could not evaluate the request."""


class DetectionError(GatewayError):
    """The detection engine failed (e.g. NLP backend unavailable)."""


class InstructionSecretError(GatewayError):
    """A secret-class span was found in the user instruction (SR-022).

    The pipeline converts this to a BLOCK decision with reason
    ``secret:<TYPE>``. The message carries the type name only, never
    the raw value (CLAUDE.md logging rules).
    """

    def __init__(self, entity_type: EntityType) -> None:
        self.entity_type = entity_type
        super().__init__(f"secret-class entity in instruction: {entity_type.value}")


class ProviderError(GatewayError):
    """Base for all LLM provider failures (M3).

    Messages are static; a provider error body is NEVER part of an
    exception (DESIGN §18 — error bodies may echo the request payload).
    """


class ProviderConfigurationError(ProviderError):
    """The provider could not be constructed (e.g. missing API key).

    Raised at construction time so the gateway fails closed before any
    call is attempted (no silent fake fallback).
    """


class ProviderHTTPError(ProviderError):
    """The provider returned a non-2xx HTTP status.

    The response body is read once by the transport and discarded — it
    may echo the request payload. The message is static.
    """

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"provider returned HTTP {status_code}")


class ProviderTimeoutError(ProviderError):
    """The provider call exceeded its timeout."""


class ProviderConnectionError(ProviderError):
    """The provider could not be reached (DNS, refused, network)."""


class ResponseParseError(GatewayError):
    """The provider response could not be parsed.

    Malformed, empty, or an error envelope. The exception never carries
    response content.
    """


class RequestBuildError(GatewayError):
    """The outbound request could not be built (e.g. nothing to send)."""


class VaultKeyError(GatewayError):
    """VAULT_MASTER_KEY missing or invalid (M6, SR-026).

    Raised before any session starts so the gateway fails closed —
    never a silent fallback to a session-only vault when persistence
    was requested.
    """


class VaultStoreError(GatewayError):
    """Persistent token store cannot be loaded or written (M6, SR-026).

    Tampered/truncated ciphertext, wrong key, wrong version, wrong
    shape, or an I/O failure — fail closed, never a silent reset or a
    partial load. Messages are static and never carry mappings.
    """
