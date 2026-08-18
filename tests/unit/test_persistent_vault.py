"""M6 persistent token store — unit tests (SR-026, DESIGN §11.1).

Covers key loading (fail closed), store mechanics (round-trip, reuse,
atomic writes), and PersistentSessionVault semantics (D1: the store is
a token_for supplier only; D2: clear() keeps the store; D7: collision
self-heal).
"""

from __future__ import annotations

import base64

import pytest
from cryptography.fernet import Fernet

from secure_ai_gateway.errors import (
    GatewayError,
    VaultKeyError,
    VaultStoreError,
)
from secure_ai_gateway.models import EntityType
from secure_ai_gateway.tokenisation.persistent import (
    PersistentSessionVault,
    PersistentTokenStore,
    load_master_key,
)
from secure_ai_gateway.tokenisation.vault import TOKEN_RE

_KEY = Fernet.generate_key()
_KEY64 = _KEY.decode()


def _write_store(path, key: bytes, plaintext: bytes) -> None:
    """Write an arbitrary plaintext encrypted with ``key``."""
    path.write_bytes(Fernet(key).encrypt(plaintext))


def _seed(path, key: bytes, mappings: dict[str, dict[str, str]]) -> None:
    store = PersistentTokenStore(path, key)
    for type_value, by_raw in mappings.items():
        entity_type = EntityType(type_value)
        for raw, token in by_raw.items():
            store.commit(entity_type, raw, token)


class TestKeyLoading:
    """VAULT_MASTER_KEY loading fails closed (SR-026, D3)."""

    def test_missing_env_fails_closed(self, monkeypatch) -> None:
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        with pytest.raises(VaultKeyError) as exc:
            load_master_key()
        assert isinstance(exc.value, GatewayError)
        assert "VAULT_MASTER_KEY" in str(exc.value)

    def test_empty_env_fails_closed(self, monkeypatch) -> None:
        monkeypatch.setenv("VAULT_MASTER_KEY", "")
        with pytest.raises(VaultKeyError):
            load_master_key()

    def test_invalid_base64_fails_closed(self, monkeypatch) -> None:
        monkeypatch.setenv("VAULT_MASTER_KEY", "not base64!!")
        with pytest.raises(VaultKeyError):
            load_master_key()

    def test_wrong_decoded_length_fails_closed(self, monkeypatch) -> None:
        for n in (16, 33):
            monkeypatch.setenv(
                "VAULT_MASTER_KEY", base64.urlsafe_b64encode(b"x" * n).decode()
            )
            with pytest.raises(VaultKeyError):
                load_master_key()

    def test_valid_fernet_key_accepted(self, monkeypatch) -> None:
        monkeypatch.setenv("VAULT_MASTER_KEY", _KEY64)
        assert load_master_key() == _KEY

    def test_paddingless_base64_accepted(self, monkeypatch) -> None:
        monkeypatch.setenv("VAULT_MASTER_KEY", _KEY64.rstrip("="))
        assert load_master_key() == _KEY

    def test_invalid_fernet_key_fails_closed(self, tmp_path) -> None:
        # 32 decodable bytes that are not a valid Fernet key.
        with pytest.raises(VaultKeyError):
            PersistentTokenStore(tmp_path / "s.vault", b"x" * 32)


class TestPersistentTokenStore:
    """Store mechanics: round-trip, reuse, overwrite, atomic writes."""

    def test_missing_file_yields_empty_store(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        store = PersistentTokenStore(path, _KEY)
        assert len(store) == 0
        assert store.token_for(EntityType.PERSON, "王小明") is None
        assert not path.exists()  # nothing written until first commit

    def test_commit_round_trips(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        store = PersistentTokenStore(path, _KEY)
        store.commit(EntityType.PERSON, "王小明", "PERSON_a1b2c3d4")
        fresh = PersistentTokenStore(path, _KEY)
        assert fresh.token_for(EntityType.PERSON, "王小明") == "PERSON_a1b2c3d4"

    def test_reuse_across_two_store_instances(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        store1 = PersistentTokenStore(path, _KEY)
        store1.commit(EntityType.EMAIL, "bob@example.com", "EMAIL_00aa11bb")
        store2 = PersistentTokenStore(path, _KEY)
        assert store2.token_for(EntityType.EMAIL, "bob@example.com") == "EMAIL_00aa11bb"

    def test_commit_overwrites_same_raw(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        store = PersistentTokenStore(path, _KEY)
        store.commit(EntityType.PERSON, "王小明", "PERSON_a1b2c3d4")
        store.commit(EntityType.PERSON, "王小明", "PERSON_eeeeffff")
        assert len(store) == 1
        assert store.token_for(EntityType.PERSON, "王小明") == "PERSON_eeeeffff"

    def test_multiple_types_independent(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        store = PersistentTokenStore(path, _KEY)
        store.commit(EntityType.PERSON, "王小明", "PERSON_a1b2c3d4")
        store.commit(EntityType.EMAIL, "bob@example.com", "EMAIL_00aa11bb")
        assert len(store) == 2
        assert store.token_for(EntityType.PERSON, "bob@example.com") is None

    def test_atomic_write_cleanup_on_failure(self, tmp_path, monkeypatch) -> None:
        path = tmp_path / "s.vault"
        store = PersistentTokenStore(path, _KEY)
        store.commit(EntityType.PERSON, "王小明", "PERSON_a1b2c3d4")
        before = path.read_bytes()
        import secure_ai_gateway.tokenisation.persistent as persistent_mod

        def _boom(src, dst) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(persistent_mod.os, "replace", _boom)
        with pytest.raises(VaultStoreError):
            store.commit(EntityType.PERSON, "李大同", "PERSON_bbbb2222")
        assert path.read_bytes() == before  # main file untouched
        assert not path.with_suffix(".vault.tmp").exists()  # tmp cleaned

    def test_store_errors_never_contain_raw(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        store = PersistentTokenStore(path, _KEY)
        store.commit(EntityType.PERSON, "王小明", "PERSON_a1b2c3d4")
        path.write_bytes(b"garbage")
        with pytest.raises(VaultStoreError) as exc:
            PersistentTokenStore(path, _KEY)
        assert "王小明" not in str(exc.value)
        assert "PERSON_a1b2c3d4" not in str(exc.value)


class TestPersistentSessionVault:
    """D1 (supplier-not-restorer), D2 (clear keeps store), D7 (self-heal)."""

    def test_store_mapping_reused_without_rewrite(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        _seed(path, _KEY, {"PERSON": {"王小明": "PERSON_a1b2c3d4"}})
        before = path.read_bytes()
        vault = PersistentSessionVault(PersistentTokenStore(path, _KEY))
        assert vault.token_for(EntityType.PERSON, "王小明") == "PERSON_a1b2c3d4"
        assert len(vault) == 1
        assert path.read_bytes() == before  # reuse: no commit

    def test_unknown_raw_fresh_token_committed(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        vault = PersistentSessionVault(PersistentTokenStore(path, _KEY))
        token = vault.token_for(EntityType.PERSON, "王小明")
        assert TOKEN_RE.fullmatch(token)
        assert PersistentTokenStore(path, _KEY).token_for(
            EntityType.PERSON, "王小明"
        ) == token

    def test_reuse_across_two_vault_instances_same_store(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        vault1 = PersistentSessionVault(PersistentTokenStore(path, _KEY))
        t1 = vault1.token_for(EntityType.PERSON, "王小明")
        vault2 = PersistentSessionVault(PersistentTokenStore(path, _KEY))
        assert vault2.token_for(EntityType.PERSON, "王小明") == t1

    def test_two_stores_different_tokens(self, tmp_path) -> None:
        vault1 = PersistentSessionVault(
            PersistentTokenStore(tmp_path / "a.vault", _KEY)
        )
        vault2 = PersistentSessionVault(
            PersistentTokenStore(tmp_path / "b.vault", _KEY)
        )
        t1 = vault1.token_for(EntityType.PERSON, "王小明")
        t2 = vault2.token_for(EntityType.PERSON, "王小明")
        assert t1 != t2

    def test_restore_is_session_scoped_never_store(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        vault1 = PersistentSessionVault(PersistentTokenStore(path, _KEY))
        t1 = vault1.token_for(EntityType.PERSON, "王小明")
        vault2 = PersistentSessionVault(PersistentTokenStore(path, _KEY))
        # D1: the store is never consulted by restore — a token issued
        # in an earlier session stays unknown (fail closed).
        assert vault2.restore(t1) is None
        assert vault2.tokens() == ()

    def test_clear_keeps_store(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        vault = PersistentSessionVault(PersistentTokenStore(path, _KEY))
        token = vault.token_for(EntityType.PERSON, "王小明")
        vault.clear()
        assert len(vault) == 0
        assert vault.restore(token) is None
        assert len(PersistentTokenStore(path, _KEY)) == 1  # store survives
        vault2 = PersistentSessionVault(PersistentTokenStore(path, _KEY))
        assert vault2.token_for(EntityType.PERSON, "王小明") == token

    def test_same_raw_same_session_idempotent(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        calls = []

        def factory() -> str:
            calls.append(1)
            return "a1b2c3d4"

        vault = PersistentSessionVault(
            PersistentTokenStore(path, _KEY), token_factory=factory
        )
        t1 = vault.token_for(EntityType.PERSON, "王小明")
        t2 = vault.token_for(EntityType.PERSON, "王小明")
        assert t1 == t2
        assert calls == [1]  # factory once: session idempotence first

    def test_session_uniqueness_guard_against_store(self, tmp_path) -> None:
        # D7: a store token that the session already holds for a
        # different raw is never double-registered; the fresh
        # generation overwrites the stale store entry (self-heal).
        path = tmp_path / "s.vault"
        _seed(path, _KEY, {"PERSON": {"王小明": "PERSON_a1b2c3d4"}})
        draws = iter(["a1b2c3d4", "b2c3d4e5"])
        vault = PersistentSessionVault(
            PersistentTokenStore(path, _KEY), token_factory=lambda: next(draws)
        )
        t_lee = vault.token_for(EntityType.PERSON, "李大同")
        assert t_lee == "PERSON_a1b2c3d4"  # factory drew the store token
        t_wang = vault.token_for(EntityType.PERSON, "王小明")
        assert t_wang == "PERSON_b2c3d4e5"  # guard fired, fresh + self-heal
        assert vault.tokens() == ("PERSON_a1b2c3d4", "PERSON_b2c3d4e5")
        assert PersistentTokenStore(path, _KEY).token_for(
            EntityType.PERSON, "王小明"
        ) == "PERSON_b2c3d4e5"

    def test_persisted_token_matches_token_re(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        vault = PersistentSessionVault(PersistentTokenStore(path, _KEY))
        token = vault.token_for(EntityType.PERSON, "王小明")
        vault.clear()
        vault2 = PersistentSessionVault(PersistentTokenStore(path, _KEY))
        assert TOKEN_RE.fullmatch(vault2.token_for(EntityType.PERSON, "王小明"))
        assert token == vault2.token_for(EntityType.PERSON, "王小明")

    def test_repr_and_log_view_no_raw_no_token(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        vault = PersistentSessionVault(PersistentTokenStore(path, _KEY))
        token = vault.token_for(EntityType.PERSON, "王小明")
        assert token
        assert repr(vault) == "PersistentSessionVault(mappings=1, store=1)"
        assert "王小明" not in repr(vault)
        assert token not in repr(vault)
        assert vault.log_view() == repr(vault)

    def test_public_surface_pinned(self, tmp_path) -> None:
        # Mirror of test_tokens.py:378 — persistence must not grow the
        # session-vault public surface beyond the store attribute.
        vault = PersistentSessionVault(PersistentTokenStore(tmp_path / "s.vault", _KEY))
        public = {name for name in dir(vault) if not name.startswith("_")}
        assert public <= {
            "clear",
            "log_view",
            "protected_instruction",
            "restore",
            "store",
            "token_for",
            "tokens",
        }
