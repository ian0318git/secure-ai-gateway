"""Session token vault tests: format, reserved-namespace disjointness
(T-T03), mapping semantics, collision handling, sanitisation (SR-002).
No engine, no NLP — the vault is pure state.
"""

from __future__ import annotations

import re
import secrets

import pytest

from secure_ai_gateway.errors import GatewayError
from secure_ai_gateway.models import EntityType
from secure_ai_gateway.policy.engine import _TOKENISE_TYPES
from secure_ai_gateway.tokenisation.vault import (
    _MAX_TOKEN_ATTEMPTS,
    _RESERVED_TOKEN_PREFIXES,
    _TOKEN_HEX_LENGTH,
    SessionTokenVault,
    TokenCollisionError,
    TokenFormatError,
    token_prefix,
)

# The live reserved pattern: recompiled with presidio's global flags
# (pattern recognisers are compiled with re.I | re.M | re.S), exactly
# as presidio's PatternRecognizer does.
_RESERVED_RE = re.compile(
    r"(?<![A-Za-z0-9_])(CUSTOMER|EMPLOYEE|EMAIL|PHONE|ADDRESS|LOCATION)"
    r"_([0-9a-f]{6})(?![A-Za-z0-9_])",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)

_TOKEN_FORMAT_RE = re.compile(r"^[A-Z][A-Z0-9]*_[0-9a-f]{8}$")


class TestTokenFormat:
    def test_token_shape(self) -> None:
        token = SessionTokenVault().token_for(EntityType.PERSON, "王小明")
        assert _TOKEN_FORMAT_RE.match(token) is not None

    def test_hex_length_constant_consistent(self) -> None:
        # _TOKEN_HEX_LENGTH is the number of hex chars; token_hex(n)
        # yields 2n chars, so the factory uses // 2.
        assert _TOKEN_HEX_LENGTH == 8
        token = SessionTokenVault().token_for(EntityType.PERSON, "王小明")
        assert len(token.rsplit("_", 1)[1]) == _TOKEN_HEX_LENGTH

    @pytest.mark.parametrize(
        ("entity_type", "expected_prefix"),
        [
            (EntityType.CUSTOMER_ID, "CUSTOMER"),
            (EntityType.EMPLOYEE_ID, "EMPLOYEE"),
            (EntityType.EMAIL, "EMAIL"),
            (EntityType.PHONE, "PHONE"),
            (EntityType.ADDRESS, "ADDRESS"),
            (EntityType.LOCATION, "LOCATION"),
            (EntityType.PERSON, "PERSON"),
            (EntityType.TW_ID, "TWID"),
            (EntityType.CREDIT_CARD, "CARD"),
            (EntityType.BANK_ACCOUNT, "ACCOUNT"),
            (EntityType.COMPANY_NAME, "COMPANY"),
            (EntityType.ORGANIZATION, "COMPANY"),
            (EntityType.TOKEN_PATTERN, "TOKEN"),
        ],
    )
    def test_prefix_table(self, entity_type: EntityType, expected_prefix: str) -> None:
        assert token_prefix(entity_type) == expected_prefix

    def test_prefix_table_covers_every_tokenise_type(self) -> None:
        # Every entity the policy would TOKENISE must have a prefix;
        # an unknown type fails closed via TokenFormatError.
        for entity_type in _TOKENISE_TYPES:
            token_prefix(entity_type)  # raises TokenFormatError if unmapped

    def test_unknown_type_fails_closed(self) -> None:
        # Block-class types are valid EntityType members with no token
        # prefix (policy never tokenises them) — an unmapped type must
        # fail closed rather than fabricate a prefix.
        for entity_type in (EntityType.SECRET, EntityType.PASSWORD):
            with pytest.raises(TokenFormatError) as exc:
                token_prefix(entity_type)
            assert isinstance(exc.value, GatewayError)

    def test_unknown_type_token_for_fails_closed(self) -> None:
        with pytest.raises(TokenFormatError):
            SessionTokenVault().token_for(EntityType.API_KEY, "sk-abc")


class TestTokenNamespaceDisjointness:
    """T-T03 property: generated tokens never match the reserved
    TOKEN_PATTERN namespace, whatever presidio's compile flags do."""

    @staticmethod
    def _samples(prefix: str, n: int) -> list[str]:
        factory = secrets.token_hex
        return [f"{prefix}_{factory(4)}" for _ in range(n)]

    @pytest.mark.parametrize(
        "prefix",
        ["CUSTOMER", "EMPLOYEE", "EMAIL", "PHONE", "ADDRESS", "LOCATION",
         "PERSON", "TWID", "CARD", "ACCOUNT", "COMPANY", "TOKEN"],
    )
    def test_no_match_bare_or_embedded(self, prefix: str) -> None:
        for token in self._samples(prefix, 500):
            assert _RESERVED_RE.search(token) is None
            assert _RESERVED_RE.search(f"xx{token}yy") is None
            assert _RESERVED_RE.search(f" {token} ") is None
            assert _RESERVED_RE.search(f"前{token}後") is None

    @pytest.mark.parametrize(
        "control",
        ["CUSTOMER_4f8a21", "CUSTOMER_4F8A21", "EMAIL_000000",
         "x CUSTOMER_4f8a21 y"],
    )
    def test_harness_sensitivity(self, control: str) -> None:
        # Controls MUST match — proves the harness can see the reserved
        # format and the zero-match results above are meaningful.
        assert _RESERVED_RE.search(control) is not None

    def test_reserved_prefix_constant_mirrors_regex(self) -> None:
        # The vault's reserved set must stay equal to the recognizer's
        # alternation; otherwise a future regex change silently breaks
        # the disjointness guarantee.
        from secure_ai_gateway.detection.recognizers import _TOKEN_PATTERN_RE

        alternation = set(
            _TOKEN_PATTERN_RE.pattern.split("(?<![A-Za-z0-9_])(")[1]
            .split(")")[0]
            .split("|")
        )
        assert alternation == _RESERVED_TOKEN_PREFIXES

    def test_known_redetection_boundary_for_m3(self) -> None:
        # M3 flag: a CUSTOMER_-prefixed token IS re-detected by the
        # CUSTOMER_ID recogniser. Harmless in M2 (detection always runs
        # before substitution) but M3's response scanner must restore
        # tokens BEFORE scanning. This test pins the boundary.
        from secure_ai_gateway.detection.recognizers import _CUSTOMER_ID_RE

        token = SessionTokenVault().token_for(EntityType.CUSTOMER_ID, "CUST_A12")
        assert _CUSTOMER_ID_RE.search(token) is not None
        # ...while the reserved TOKEN_PATTERN namespace is not touched.
        assert _RESERVED_RE.search(token) is None


class TestTokenSubstringSafety:
    def test_no_token_is_substring_of_another(self) -> None:
        # restore_text matches longest-first; this property guarantees
        # that matching is unambiguous across any token pair.
        vault = SessionTokenVault()
        tokens = [
            vault.token_for(EntityType.PERSON, f"客戶{i}") for i in range(200)
        ]
        for i, a in enumerate(tokens):
            for b in tokens[i + 1:]:
                assert a not in b and b not in a


class TestSessionTokenVault:
    def test_same_key_same_token(self) -> None:
        vault = SessionTokenVault()
        assert vault.token_for(EntityType.PERSON, "王小明") == \
            vault.token_for(EntityType.PERSON, "王小明")

    def test_factory_not_called_on_cache_hit(self) -> None:
        calls: list[str] = []

        def factory() -> str:
            calls.append("draw")
            return "abcdef01"

        vault = SessionTokenVault(token_factory=factory)
        vault.token_for(EntityType.PERSON, "王小明")
        vault.token_for(EntityType.PERSON, "王小明")
        assert calls == ["draw"]

    def test_same_raw_different_type_different_tokens(self) -> None:
        vault = SessionTokenVault()
        a = vault.token_for(EntityType.CUSTOMER_ID, "CUST_A12")
        b = vault.token_for(EntityType.TOKEN_PATTERN, "CUST_A12")
        assert a != b
        assert vault.restore(a) == "CUST_A12"
        assert vault.restore(b) == "CUST_A12"
        # Type preserved through restoration by construction: the
        # reverse map keys on the token, so both restores are raw.
        assert vault.restore(a) == vault.restore(b)

    def test_different_raw_same_type_different_tokens(self) -> None:
        vault = SessionTokenVault()
        a = vault.token_for(EntityType.PERSON, "王小明")
        b = vault.token_for(EntityType.PERSON, "李大同")
        assert a != b

    def test_fixed_point_guard(self) -> None:
        # A factory draw equal to the raw value must not produce a
        # token identical to the raw (token/raw fixed point).
        draws = iter(["ab12cd34", "abcd1234"])

        def factory() -> str:
            return next(draws)

        vault = SessionTokenVault(token_factory=factory)
        token = vault.token_for(EntityType.CUSTOMER_ID, "CUSTOMER_ab12cd34")
        assert token != "CUSTOMER_ab12cd34"
        assert token == "CUSTOMER_abcd1234"
        assert vault.restore(token) == "CUSTOMER_ab12cd34"

    def test_collision_retries_then_fails_closed(self) -> None:
        def factory() -> str:
            return "00000000"  # always collides with the first token

        vault = SessionTokenVault(token_factory=factory)
        vault.token_for(EntityType.PERSON, "王小明")
        with pytest.raises(TokenCollisionError) as exc:
            vault.token_for(EntityType.PERSON, "李大同")
        assert isinstance(exc.value, GatewayError)
        assert "王小明" not in str(exc.value)

    def test_collision_attempts_bounded(self) -> None:
        # The retry loop is bounded (fail-closed, not infinite).
        calls = 0

        def factory() -> str:
            nonlocal calls
            calls += 1
            return "00000000"

        vault = SessionTokenVault(token_factory=factory)
        vault.token_for(EntityType.PERSON, "王小明")
        with pytest.raises(TokenCollisionError):
            vault.token_for(EntityType.PERSON, "李大同")
        # 1 draw for the first (successful) mapping + the bounded retries.
        assert calls == 1 + _MAX_TOKEN_ATTEMPTS

    def test_restore_unknown_returns_none(self) -> None:
        vault = SessionTokenVault()
        assert vault.restore("CUSTOMER_deadbeef") is None
        assert vault.restore("NOT_A_TOKEN") is None

    def test_restore_after_clear(self) -> None:
        vault = SessionTokenVault()
        token = vault.token_for(EntityType.PERSON, "王小明")
        vault.clear()
        assert vault.restore(token) is None
        assert len(vault) == 0

    def test_clear_resets_protected_instruction(self) -> None:
        vault = SessionTokenVault()
        vault.protected_instruction = "protected"
        vault.clear()
        assert vault.protected_instruction is None

    def test_len_counts_mappings(self) -> None:
        vault = SessionTokenVault()
        assert len(vault) == 0
        vault.token_for(EntityType.PERSON, "王小明")
        vault.token_for(EntityType.PERSON, "李大同")
        assert len(vault) == 2

    def test_tokens_lists_issued_tokens(self) -> None:
        vault = SessionTokenVault()
        t1 = vault.token_for(EntityType.PERSON, "王小明")
        t2 = vault.token_for(EntityType.EMAIL, "bob@x.com")
        assert set(vault.tokens()) == {t1, t2}

    def test_factory_called_once_per_new_mapping(self) -> None:
        calls = 0

        def factory() -> str:
            nonlocal calls
            calls += 1
            return f"{calls:07d}ab"

        vault = SessionTokenVault(token_factory=factory)
        vault.token_for(EntityType.PERSON, "王小明")
        vault.token_for(EntityType.PERSON, "李大同")
        assert calls == 2

    def test_two_vaults_share_no_state(self) -> None:
        v1 = SessionTokenVault()
        v2 = SessionTokenVault()
        token = v1.token_for(EntityType.PERSON, "王小明")
        assert token not in v2.tokens()
        assert v2.restore(token) is None


class TestVaultSanitisation:
    def test_repr_has_no_raw_or_token(self) -> None:
        vault = SessionTokenVault()
        token = vault.token_for(EntityType.PERSON, "王小明")
        assert repr(vault) == "SessionTokenVault(mappings=1)"
        assert "王小明" not in repr(vault)
        assert token not in repr(vault)

    def test_log_view_has_no_raw_or_token(self) -> None:
        vault = SessionTokenVault()
        token = vault.token_for(EntityType.PERSON, "王小明")
        assert "王小明" not in vault.log_view()
        assert token not in vault.log_view()

    def test_repr_no_tokens_when_populated(self) -> None:
        vault = SessionTokenVault()
        for i in range(10):
            vault.token_for(EntityType.PERSON, f"客戶{i}")
        assert repr(vault) == "SessionTokenVault(mappings=10)"
        assert all(f"客户{i}" not in repr(vault) for i in range(10))
