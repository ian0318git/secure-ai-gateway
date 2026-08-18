"""M6 persistent token store: opt-in, Fernet-encrypted, on-disk
``token_for`` supplier (DESIGN §11.1, SR-019 carve-out, SR-026).

The persistent layer is a token_for SUPPLIER, never a restore
supplier: ``restore()`` reads only the session map (inherited from
SessionTokenVault), so a token issued in an earlier session that
appears in an LLM response is still an unknown token (response guard
step 1, fail closed — D1).

Activation is strictly opt-in (explicit approval 2026-08-18, SR-019):
``PersistentSessionVault`` is constructed explicitly (CLI
``--vault-store``); the default pipeline path never touches this
module and keeps the PoC session-only behaviour unchanged.

Fail-closed rules (SR-026): missing/invalid VAULT_MASTER_KEY and any
unloadable or unwritable store raise GatewayError subclasses — never a
silent reset, partial load, or fallback to a session-only vault.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
from collections.abc import Callable
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from secure_ai_gateway.errors import VaultKeyError, VaultStoreError
from secure_ai_gateway.logging import log_event
from secure_ai_gateway.models import EntityType
from secure_ai_gateway.tokenisation.vault import SessionTokenVault

logger = logging.getLogger("secure_ai_gateway.tokenisation.persistent")

STORE_VERSION = 1

_ENV_KEY_NAME = "VAULT_MASTER_KEY"


def load_master_key(env_name: str = _ENV_KEY_NAME) -> bytes:
    """Read the master key from the environment (SR-026, D3).

    The value is urlsafe base64 of exactly 32 random bytes; padded and
    paddingless encodings are both accepted. Missing, undecodable, or
    wrong-length values raise VaultKeyError (fail closed).
    """
    raw = os.environ.get(env_name)
    if raw is None or raw == "":
        raise VaultKeyError(
            f"{env_name} is not set (base64 of 32 random bytes); "
            "persistent token storage fails closed without it"
        )
    try:
        decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (binascii.Error, ValueError):
        decoded = b""
    if len(decoded) != 32:
        raise VaultKeyError(
            f"{env_name} must decode to exactly 32 bytes, got "
            f"{len(decoded)}; generate with "
            "`python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\"`"
        )
    # Fernet expects the urlsafe-base64 form of the key; return the
    # normalised (padded) encoding, independent of how the user wrote it.
    return base64.urlsafe_b64encode(decoded)


class PersistentTokenStore:
    """Fernet-encrypted JSON mapping store (D4: atomic writes).

    One process at a time; no locking (DECISIONS M6, D6 — the atomic
    rename prevents torn reads; concurrent writers lose updates, not
    integrity). The file exists only after the first commit.
    """

    def __init__(self, path: str | Path, key: bytes) -> None:
        self._path = Path(path)
        try:
            self._fernet = Fernet(key)
        except (ValueError, TypeError) as exc:
            raise VaultKeyError(
                "invalid VAULT_MASTER_KEY for Fernet"
            ) from exc
        if self._path.exists() and not self._path.is_file():
            raise VaultStoreError(
                f"persistent store path is not a file: {self._path.name}"
            )
        if self._path.parent.exists() and not self._path.parent.is_dir():
            raise VaultStoreError(
                f"persistent store parent is not a directory: "
                f"{self._path.parent}"
            )
        self._mappings: dict[str, dict[str, str]] = {}
        if self._path.exists():
            self._mappings = self._load()
        log_event(
            logger,
            "vault_store_open",
            path=self._path.name,
            entries=len(self._mappings),
        )

    # -- read side (token_for supplier) ---------------------------------

    def token_for(self, entity_type: EntityType, raw: str) -> str | None:
        by_raw = self._mappings.get(entity_type.value)
        return by_raw.get(raw) if by_raw is not None else None

    def __len__(self) -> int:
        return sum(len(by_raw) for by_raw in self._mappings.values())

    # -- write side (write-through commit, D5) --------------------------

    def commit(self, entity_type: EntityType, raw: str, token: str) -> None:
        by_raw = self._mappings.setdefault(entity_type.value, {})
        by_raw[raw] = token
        self._save()

    # -- internals -------------------------------------------------------

    def _load(self) -> dict[str, dict[str, str]]:
        try:
            ciphertext = self._path.read_bytes()
            plaintext = self._fernet.decrypt(ciphertext)
            payload = json.loads(plaintext)
        except (OSError, InvalidToken, ValueError) as exc:
            # Fernet.decrypt raises InvalidToken (not a ValueError);
            # json.loads raises JSONDecodeError (a ValueError subclass).
            raise VaultStoreError(
                "persistent store cannot be loaded (missing, tampered, "
                "truncated, or encrypted with a different key)"
            ) from exc
        if not isinstance(payload, dict):
            raise VaultStoreError("persistent store payload is not an object")
        if payload.get("version") != STORE_VERSION:
            raise VaultStoreError(
                f"persistent store version mismatch (expected "
                f"{STORE_VERSION})"
            )
        mappings = payload.get("mappings")
        if not isinstance(mappings, dict) or not all(
            isinstance(by_raw, dict)
            and all(isinstance(k, str) and isinstance(v, str) for k, v in by_raw.items())
            for by_raw in mappings.values()
        ):
            raise VaultStoreError("persistent store mappings have an invalid shape")
        return mappings

    def _save(self) -> None:
        payload = json.dumps(
            {"version": STORE_VERSION, "mappings": self._mappings},
            ensure_ascii=False,
        )
        ciphertext = self._fernet.encrypt(payload.encode("utf-8"))
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            with open(tmp, "wb") as fh:
                fh.write(ciphertext)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        except OSError as exc:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise VaultStoreError(
                f"persistent store could not be written: {self._path.name}"
            ) from exc


class PersistentSessionVault(SessionTokenVault):
    """Session vault whose token_for consults a persistent store (D1/D2).

    token_for order: session map -> store (reuse, registered into the
    session map) -> fresh generation + write-through commit. The store
    is never consulted by restore(): a cross-session token stays
    unknown in a new session (fail closed). clear() clears only the
    session map — the store persists by design (the approved SR-019
    carve-out).
    """

    def __init__(
        self,
        store: PersistentTokenStore,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        super().__init__(token_factory)
        self.store = store  # public: inspection surface for tests

    def token_for(self, entity_type: EntityType, raw: str) -> str:
        key = (entity_type, raw)
        if key in self._forward:  # session idempotence first
            return self._forward[key]
        stored = self.store.token_for(entity_type, raw)
        if stored is not None and stored not in self._reverse:
            # Reuse the stored identity and register it in this
            # session's map. The reverse-map guard (D7) skips a store
            # token that already belongs to a different raw in this
            # session (fixed-factory pathology); the fresh generation
            # below then overwrites the stale store entry (self-heal).
            self._forward[key] = stored
            self._reverse[stored] = key
            return stored
        token = super().token_for(entity_type, raw)
        self.store.commit(entity_type, raw, token)
        return token

    def clear(self) -> None:
        # Session map only. Wiping the store here would destroy
        # cross-session identities on every blocked request (session.py
        # clears on every path) — the store is the approved carve-out.
        super().clear()

    def __repr__(self) -> str:
        return (
            f"PersistentSessionVault(mappings={len(self)}, "
            f"store={len(self.store)})"
        )
