"""Gateway exception hierarchy.

All exceptions derive from GatewayError so the pipeline can fail
closed with a single handler. Exceptions never carry raw document
content or token values in their messages (see CLAUDE.md logging
rules).
"""


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
