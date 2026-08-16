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
