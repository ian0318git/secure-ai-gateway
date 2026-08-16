"""Tokenisation (M2): session-scoped vault, span substitution, and the
protected instruction channel (SR-022).

Everything here stays inside the trusted environment (T-I03): no token
value or raw value ever leaves through logs or report surfaces.
"""

from secure_ai_gateway.tokenisation.substitution import (
    restore_text,
    tokenise_cells,
)
from secure_ai_gateway.tokenisation.vault import (
    SessionTokenVault,
    TokenCollisionError,
    TokenFormatError,
    TokenVault,
    token_prefix,
)

__all__ = [
    "SessionTokenVault",
    "TokenCollisionError",
    "TokenFormatError",
    "TokenVault",
    "restore_text",
    "token_prefix",
    "tokenise_cells",
]
