"""Token vault: session-scoped token mappings (DESIGN §11, SR-019/023).

The vault is the protected mapping store (T-T01 mitigation): the only
object that holds token <-> raw correspondence. One gateway invocation
creates one vault; the caller releases it at session end. "Destroyed"
is a scoping guarantee — Python cannot zeroise memory (SR-019).

No raw value and no token value ever appears in ``__repr__`` /
``log_view()`` (CLAUDE.md §6: token mappings never appear in logs,
responses, or client-visible surfaces).
"""

from __future__ import annotations

import re
import secrets
from typing import Callable, Protocol

from secure_ai_gateway.errors import GatewayError
from secure_ai_gateway.models import EntityType

# Mirrors the alternation in detection/recognizers.py:_TOKEN_PATTERN_RE.
# Generated tokens must stay disjoint from this reserved namespace
# (T-T03); the 8-hex suffix guarantees it (property-tested in
# tests/unit/test_vault.py against the live pattern string).
_RESERVED_TOKEN_PREFIXES = frozenset(
    {"CUSTOMER", "EMPLOYEE", "EMAIL", "PHONE", "ADDRESS", "LOCATION"}
)

_TOKEN_HEX_LENGTH = 8  # token_hex(4) -> 8 chars, 32 bits
_MAX_TOKEN_ATTEMPTS = 100  # bounded collision retry, then fail closed

# Shape of every issued token: uppercase-alnum prefix + 8 lowercase hex
# (all prefixes in _PREFIX_BY_TYPE match). Used by the M4 response guard
# to tell issued tokens from plain text. Deliberately NOT the reserved
# 6-hex TOKEN_PATTERN namespace (T-T03): an invented 6-hex string like
# CUSTOMER_4f8a21 falls through to the sensitive-data scan instead.
TOKEN_RE = re.compile(r"[A-Z][A-Z0-9]*_[0-9a-f]{8}")


class TokenFormatError(GatewayError):
    """No token prefix is defined for an entity type (fail closed)."""


class TokenCollisionError(GatewayError):
    """Token namespace exhausted for this session (fail closed)."""


# Prefix per entity type. Every policy TOKENISE type must be present
# (a unit test enumerates the policy set); unknown types fail closed,
# mirroring the DetectionError philosophy in detection/engine.py.
_PREFIX_BY_TYPE: dict[EntityType, str] = {
    EntityType.CUSTOMER_ID: "CUSTOMER",
    EntityType.EMPLOYEE_ID: "EMPLOYEE",
    EntityType.EMAIL: "EMAIL",
    EntityType.PHONE: "PHONE",
    EntityType.ADDRESS: "ADDRESS",
    EntityType.LOCATION: "LOCATION",
    EntityType.PERSON: "PERSON",
    EntityType.TW_ID: "TWID",
    EntityType.CREDIT_CARD: "CARD",
    EntityType.BANK_ACCOUNT: "ACCOUNT",
    EntityType.COMPANY_NAME: "COMPANY",
    EntityType.ORGANIZATION: "COMPANY",
    EntityType.TOKEN_PATTERN: "TOKEN",
}


def token_prefix(entity_type: EntityType) -> str:
    """Prefix for an entity type; raises TokenFormatError if unknown."""
    try:
        return _PREFIX_BY_TYPE[entity_type]
    except KeyError:
        raise TokenFormatError(
            f"no token prefix for entity type {entity_type.value}"
        ) from None


class TokenVault(Protocol):
    """Vault abstraction (DESIGN §11: a persistent vault arrives at MVP).

    ``restore`` of an unknown token returns None (never fabricates);
    no method exposes raw values through repr/log surfaces.
    """

    def token_for(self, entity_type: EntityType, raw: str) -> str: ...
    def restore(self, token: str) -> str | None: ...
    def tokens(self) -> tuple[str, ...]: ...
    def clear(self) -> None: ...
    def __len__(self) -> int: ...


class SessionTokenVault:
    """In-memory, session-scoped vault. One gateway invocation = one
    session = one thread (SR-019); not thread-safe by design.
    """

    def __init__(self, token_factory: Callable[[], str] | None = None) -> None:
        # Bound at construction so every vault gets a fresh callable;
        # the production default is stdlib `secrets` (no dependencies).
        self._factory: Callable[[], str] = token_factory or (
            lambda: secrets.token_hex(_TOKEN_HEX_LENGTH // 2)
        )
        self._forward: dict[tuple[EntityType, str], str] = {}
        self._reverse: dict[str, tuple[EntityType, str]] = {}
        # Protected instruction for this session (SR-022); consumed by
        # the M3 LLM integration, never logged or serialised.
        self.protected_instruction: str | None = None

    def token_for(self, entity_type: EntityType, raw: str) -> str:
        key = (entity_type, raw)
        if key in self._forward:  # value-keyed register: same value
            return self._forward[key]  # -> same token (idempotent)
        prefix = token_prefix(entity_type)
        for _ in range(_MAX_TOKEN_ATTEMPTS):
            candidate = f"{prefix}_{self._factory()}"
            if candidate == raw:  # no token/raw fixed points
                continue
            if candidate not in self._reverse:
                self._forward[key] = candidate
                self._reverse[candidate] = key
                return candidate
        raise TokenCollisionError(
            f"token namespace exhausted for {entity_type.value}"
        )

    def restore(self, token: str) -> str | None:
        key = self._reverse.get(token)
        return key[1] if key is not None else None

    def tokens(self) -> tuple[str, ...]:
        return tuple(self._reverse)

    def clear(self) -> None:
        self._forward.clear()
        self._reverse.clear()
        self.protected_instruction = None

    def __len__(self) -> int:
        return len(self._forward)

    def __repr__(self) -> str:
        return f"SessionTokenVault(mappings={len(self._forward)})"

    def log_view(self) -> str:
        return repr(self)
