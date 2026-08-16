"""Sanitised logging (CLAUDE.md §6 rule: no sensitive data in logs).

Only allow-listed, non-raw fields may be logged. ``log_event``
REJECTS any field whose key looks like it could carry raw content or
secrets — a bug in the caller, not something to paper over (fail
loud). Values passed must be ``log_view()`` output, counts, or other
metadata, never raw cell text.

``payload``/``error`` (exception) fields are likewise forbidden:
exceptions never carry raw content in this codebase (see errors.py).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Mapping

_FORBIDDEN_KEY = re.compile(
    r"(raw|payload|content|body|value|snippet|text|secret|password|"
    r"apikey|api_key|token|mapping|credential)",
    re.IGNORECASE,
)


def is_sanitised_fields(fields: Mapping[str, Any]) -> bool:
    """True when every key is allow-listed (no raw-content keys)."""
    for key in fields:
        if _FORBIDDEN_KEY.search(key):
            return False
    return True


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    **fields: Any,
) -> None:
    """Log an event with only allow-listed fields.

    Raises ``ValueError`` if any field key is forbidden — a failed
    log call is preferable to a raw-value leak. ``event`` must be a
    fixed string literal, never interpolated content.
    """
    if not is_sanitised_fields(fields):
        offending = [k for k in fields if _FORBIDDEN_KEY.search(k)]
        raise ValueError(
            f"refusing to log fields with forbidden keys: {offending}"
        )
    rendered = " ".join(
        f"{key}={value}" for key, value in sorted(fields.items())
    )
    logger.log(level, "%s %s", event, rendered)
