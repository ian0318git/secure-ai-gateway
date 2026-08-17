"""M6 security suite: persistent token store fail-closed and leak pins
(SR-026, T-T05/T-T06/T-I10/T-I11, DESIGN §11.1).

Pins: at-rest ciphertext is opaque (no raw, no token, no structure);
every load failure fails closed; the store is a token_for supplier
only (D1: a previous-session token in a response stays
response:unknown_token); the pipeline factory shares one store across
sessions; store files are never committed.
"""

from __future__ import annotations

import json

import pytest
from cryptography.fernet import Fernet

from secure_ai_gateway.errors import VaultStoreError
from secure_ai_gateway.models import (
    CellDetection,
    DetectionSpan,
    EntityType,
    SpanSource,
)
from secure_ai_gateway.pipeline import Pipeline
from secure_ai_gateway.response.guard import ResponseGuard
from secure_ai_gateway.tokenisation.persistent import PersistentTokenStore
from secure_ai_gateway.tokenisation.vault import TOKEN_RE

_KEY = Fernet.generate_key()


def _encrypt(plaintext: bytes) -> bytes:
    return Fernet(_KEY).encrypt(plaintext)


def _seed(path, key: bytes, mappings: dict[str, dict[str, str]]) -> None:
    store = PersistentTokenStore(path, key)
    for type_value, by_raw in mappings.items():
        entity_type = EntityType(type_value)
        for raw, token in by_raw.items():
            store.commit(entity_type, raw, token)


class GuardStubEngine:
    """Minimal engine: input spans per cell (so the pipeline tokenises),
    nothing sensitive in a delivered response."""

    def __init__(self, spans_by_cell: dict[str, tuple[DetectionSpan, ...]] | None = None):
        self._spans = spans_by_cell or {}

    def analyze_cell(self, cell):
        return CellDetection(
            cell_id=cell.cell_id,
            spans=self._spans.get(cell.cell_id, ()),
        )

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]:
        return ()


def _span(entity: EntityType, start: int, end: int, raw: str) -> DetectionSpan:
    return DetectionSpan(entity, start, end, 0.9, SpanSource.PATTERN, raw)


class TestAtRestProtection:
    def test_store_file_is_opaque_ciphertext(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        _seed(
            path,
            _KEY,
            {
                "PERSON": {"王小明": "PERSON_a1b2c3d4"},
                "EMAIL": {"bob@example.com": "EMAIL_00aa11bb"},
                "CUSTOMER_ID": {"Aurora Motors AU": "CUSTOMER_4f8a21de"},
            },
        )
        data = path.read_bytes()
        assert data.startswith(b"gAAAA")  # Fernet version marker
        for needle in (
            "王小明".encode(),  # raw values
            b"Aurora",
            b"bob@example.com",
            b"PERSON_a1b2c3d4",  # tokens
            b"CUSTOMER_4f8a21de",
            b"mappings",  # JSON structure
            b"version",
            b"PERSON",
            b"{",
        ):
            assert needle not in data, f"plaintext leak: {needle!r}"

    def test_tampered_ciphertext_fails_closed(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        _seed(path, _KEY, {"PERSON": {"王小明": "PERSON_a1b2c3d4"}})
        data = bytearray(path.read_bytes())
        data[len(data) // 2] ^= 0x01  # flip one byte mid-file
        path.write_bytes(bytes(data))
        with pytest.raises(VaultStoreError):
            PersistentTokenStore(path, _KEY)

    def test_truncated_file_fails_closed(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        _seed(path, _KEY, {"PERSON": {"王小明": "PERSON_a1b2c3d4"}})
        path.write_bytes(path.read_bytes()[:10])
        with pytest.raises(VaultStoreError):
            PersistentTokenStore(path, _KEY)

    def test_empty_file_fails_closed(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        path.write_bytes(b"")
        with pytest.raises(VaultStoreError):
            PersistentTokenStore(path, _KEY)

    def test_wrong_key_fails_closed(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        _seed(path, _KEY, {"PERSON": {"王小明": "PERSON_a1b2c3d4"}})
        other = Fernet.generate_key()
        with pytest.raises(VaultStoreError):
            PersistentTokenStore(path, other)

    def test_non_json_plaintext_fails_closed(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        path.write_bytes(_encrypt(b"just some text"))
        with pytest.raises(VaultStoreError):
            PersistentTokenStore(path, _KEY)

    def test_wrong_version_fails_closed(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        path.write_bytes(
            _encrypt(json.dumps({"version": 2, "mappings": {}}).encode())
        )
        with pytest.raises(VaultStoreError):
            PersistentTokenStore(path, _KEY)

    def test_bad_mappings_shape_fails_closed(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        for payload in (
            {"version": 1, "mappings": {"PERSON": ["x"]}},
            {"version": 1, "mappings": {"PERSON": {"王小明": 42}}},
        ):
            path.write_bytes(
                _encrypt(json.dumps(payload, ensure_ascii=False).encode())
            )
            with pytest.raises(VaultStoreError):
                PersistentTokenStore(path, _KEY)

    def test_unknown_entity_types_preserved(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        # An entity type from an older store version loads fine and is
        # inert (never consulted — token_for is called with live
        # EntityType members only, never reachable via restore).
        path.write_bytes(
            _encrypt(
                json.dumps(
                    {
                        "version": 1,
                        "mappings": {"DEPRECATED_OLD_TYPE": {"legacy": "TOKEN_11223344"}},
                    }
                ).encode()
            )
        )
        store = PersistentTokenStore(path, _KEY)
        assert len(store) == 1  # inert, but counted


class TestCrossSessionSemantics:
    """D1: the store supplies token_for, never restore."""

    def test_previous_session_token_in_response_blocks(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        _seed(path, _KEY, {"PERSON": {"王小明": "PERSON_a1b2c3d4"}})
        store = PersistentTokenStore(path, _KEY)
        vault1 = _persistent_vault(store)
        assert vault1.token_for(EntityType.PERSON, "王小明") == "PERSON_a1b2c3d4"
        # A new session over the same store: the session map is empty.
        vault2 = _persistent_vault(PersistentTokenStore(path, _KEY))
        outcome = ResponseGuard(GuardStubEngine()).check(
            "請見 PERSON_a1b2c3d4 的資料", vault2, "end_turn"
        )
        assert outcome.status == "blocked"
        assert outcome.reason == "response:unknown_token"

    def test_same_session_token_delivers(self, tmp_path) -> None:
        path = tmp_path / "s.vault"
        _seed(path, _KEY, {"PERSON": {"王小明": "PERSON_a1b2c3d4"}})
        vault = _persistent_vault(PersistentTokenStore(path, _KEY))
        assert vault.token_for(EntityType.PERSON, "王小明") == "PERSON_a1b2c3d4"
        outcome = ResponseGuard(GuardStubEngine()).check(
            "請見 PERSON_a1b2c3d4 的資料", vault, "end_turn"
        )
        assert outcome.status == "ok"
        assert "王小明" in outcome.text  # authorised restoration

    def test_pipeline_factory_shared_store_reuses_tokens(
        self, tmp_path, monkeypatch
    ) -> None:
        from secure_ai_gateway.tokenisation.persistent import (
            PersistentSessionVault,
        )

        path = tmp_path / "s.vault"
        store = PersistentTokenStore(path, _KEY)
        engine = GuardStubEngine(
            {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        pipe = Pipeline(
            engine,
            vault_factory=lambda: PersistentSessionVault(store=store),
        )
        csv = tmp_path / "p.csv"
        csv.write_bytes("客戶,營業收入\n王小明,8.4M\n".encode("utf-8"))
        _result1 = pipe.process_file(csv, request_id="r1")
        _result2 = pipe.process_file(csv, request_id="r2")
        vault1, vault2 = _result1[3], _result2[3]
        # Two sessions over one store issue the same identity...
        t1 = vault1.tokens()[0]
        t2 = vault2.tokens()[0]
        assert t1 == t2
        assert TOKEN_RE.fullmatch(t1)
        # ...and each session registers it in its own map (D1: a vault
        # that never tokenised a value cannot restore it — pinned in
        # test_previous_session_token_in_response_blocks).
        assert vault2.restore(t1) == "王小明"


def _persistent_vault(store):
    from secure_ai_gateway.tokenisation.persistent import (
        PersistentSessionVault,
    )

    return PersistentSessionVault(store=store)


class TestRepoHygiene:
    def test_gitignore_excludes_vault_stores(self) -> None:
        import subprocess

        out = subprocess.run(
            ["git", "check-ignore", "demo.vault", "demo.vault.tmp"],
            cwd="/home/ian/github-project/secure-ai-gateway",
            capture_output=True,
            text=True,
        )
        assert out.returncode == 0
        assert "demo.vault" in out.stdout
        assert "demo.vault.tmp" in out.stdout
