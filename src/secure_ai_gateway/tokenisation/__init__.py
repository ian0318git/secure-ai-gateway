"""Tokenisation (M2): session-scoped vault, span substitution, and the
protected instruction channel (SR-022).

Everything here stays inside the trusted environment (T-I03): no token
value or raw value ever leaves through logs or report surfaces.
"""

from secure_ai_gateway.tokenisation.persistent import (
    PersistentSessionVault,
    PersistentTokenStore,
    load_master_key,
)
from secure_ai_gateway.tokenisation.substitution import (
    protect_instruction,
    restore_text,
    restore_text_with_spans,
    tokenise_cells,
)
from secure_ai_gateway.tokenisation.vault import (
    TOKEN_RE,
    SessionTokenVault,
    TokenCollisionError,
    TokenFormatError,
    TokenVault,
    token_prefix,
)

__all__ = [
    "TOKEN_RE",
    "PersistentSessionVault",
    "PersistentTokenStore",
    "SessionTokenVault",
    "TokenCollisionError",
    "TokenFormatError",
    "TokenVault",
    "load_master_key",
    "protect_instruction",
    "restore_text",
    "restore_text_with_spans",
    "token_prefix",
    "tokenise_cells",
]
