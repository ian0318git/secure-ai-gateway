"""M4 response guard unit tests: no NLP, no network.

A duck-typed stub engine detects scripted raw values wherever they
occur in the text it is given (so span offsets are always real), plus
a fixed-span stub for the defensive-skip cases. The vault is a real
SessionTokenVault with a deterministic token factory.
"""

from __future__ import annotations

from secure_ai_gateway.models import (
    DetectionSpan,
    EntityType,
    SpanSource,
)
from secure_ai_gateway.response.guard import ResponseGuard, ResponseOutcome
from secure_ai_gateway.tokenisation.vault import SessionTokenVault


class _FindingStub:
    """Duck-typed engine: detects scripted (entity, raw) pairs wherever
    they occur in the text (first occurrence each)."""

    def __init__(self, *findings: tuple[EntityType, str]) -> None:
        self._findings = findings

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]:
        out: list[DetectionSpan] = []
        for entity, raw in self._findings:
            start = 0
            while True:
                start = text.find(raw, start)
                if start < 0:
                    break
                out.append(
                    DetectionSpan(
                        entity_type=entity,
                        start=start,
                        end=start + len(raw),
                        score=0.9,
                        source=SpanSource.PATTERN,
                        raw_value=raw,
                    )
                )
                start += len(raw)
        return tuple(out)


class _FixedStub:
    """Duck-typed engine returning scripted spans verbatim (used for
    the defensive out-of-range/degenerate skip cases)."""

    def __init__(self, spans: tuple[DetectionSpan, ...]) -> None:
        self._spans = spans

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]:
        return self._spans


def _span(
    entity: EntityType, start: int, end: int, raw: str | None = None
) -> DetectionSpan:
    return DetectionSpan(
        entity_type=entity,
        start=start,
        end=end,
        score=0.9,
        source=SpanSource.PATTERN,
        raw_value=raw if raw is not None else "x" * (end - start),
    )


def _vault(*suffixes: str) -> SessionTokenVault:
    """Vault with a deterministic token factory (one draw per suffix)."""
    it = iter(suffixes)

    def factory() -> str:
        return next(it)

    return SessionTokenVault(token_factory=factory)


class TestTokenValidation:
    def test_ok_passthrough(self) -> None:
        outcome = ResponseGuard(_FindingStub()).check(
            "毛利約 34.2%", _vault(), stop_reason="end_turn"
        )
        assert outcome.status == "ok"
        assert outcome.text == "毛利約 34.2%"
        assert outcome.reason == ""

    def test_known_token_restored_and_delivered(self) -> None:
        vault = _vault("1234abcd")
        token = vault.token_for(EntityType.PERSON, "王小明")
        outcome = ResponseGuard(_FindingStub()).check(
            f"客戶 {token} 的毛利率", vault, stop_reason="end_turn"
        )
        assert outcome.status == "ok"
        assert outcome.text == "客戶 王小明 的毛利率"

    def test_token_at_start_and_end_restored(self) -> None:
        vault = _vault("1234abcd", "5678ef90")
        t1 = vault.token_for(EntityType.PERSON, "王小明")
        t2 = vault.token_for(EntityType.EMAIL, "bob@x.com")
        outcome = ResponseGuard(_FindingStub()).check(
            f"{t1} 中間 {t2}", vault, stop_reason="end_turn"
        )
        assert outcome.status == "ok"
        assert outcome.text == "王小明 中間 bob@x.com"

    def test_empty_vault_blocks_token_shaped_output(self) -> None:
        outcome = ResponseGuard(_FindingStub()).check(
            "PERSON_1234abcd", _vault(), stop_reason="end_turn"
        )
        assert outcome.status == "blocked"
        assert outcome.reason == "response:unknown_token"

    def test_unknown_token_blocked_and_never_in_delivered_text(self) -> None:
        vault = _vault("1234abcd")
        vault.token_for(EntityType.PERSON, "王小明")
        outcome = ResponseGuard(_FindingStub()).check(
            "PERSON_deadbeef", vault, stop_reason="end_turn"
        )
        assert outcome.status == "blocked"
        assert outcome.reason == "response:unknown_token"
        assert outcome.text == ""  # fail closed: nothing delivered

    def test_unknown_plus_raw_pii_reports_unknown_token(self) -> None:
        # Priority: token validation runs before the sensitive scan.
        vault = _vault("1234abcd")
        vault.token_for(EntityType.PERSON, "王小明")
        outcome = ResponseGuard(
            _FindingStub((EntityType.PERSON, "王小明"))
        ).check("PERSON_deadbeef 王小明", vault, stop_reason="end_turn")
        assert outcome.reason == "response:unknown_token"

    def test_reserved_six_hex_invention_blocked_as_pii(self) -> None:
        # A 6-hex reserved-namespace string is NOT token-shaped (TOKEN_RE
        # needs 8 hex): it falls through to the sensitive scan, where the
        # TOKEN_PATTERN recogniser catches it (T-T03 second net).
        vault = _vault("1234abcd")
        vault.token_for(EntityType.PERSON, "王小明")
        outcome = ResponseGuard(
            _FindingStub((EntityType.TOKEN_PATTERN, "CUSTOMER_4f8a21"))
        ).check("CUSTOMER_4f8a21", vault, stop_reason="end_turn")
        assert outcome.reason == "response:pii:TOKEN_PATTERN"


class TestSensitiveScan:
    def test_raw_pii_blocked(self) -> None:
        outcome = ResponseGuard(
            _FindingStub((EntityType.PERSON, "王小明"))
        ).check("請分析 王小明 的趨勢", _vault(), stop_reason="end_turn")
        assert outcome.reason == "response:pii:PERSON"

    def test_secret_blocked(self) -> None:
        outcome = ResponseGuard(
            _FindingStub((EntityType.API_KEY, "sk-live-abc"))
        ).check("密鑰 sk-live-abc", _vault(), stop_reason="end_turn")
        assert outcome.reason == "response:secret:API_KEY"

    def test_secret_priority_over_pii(self) -> None:
        outcome = ResponseGuard(
            _FindingStub(
                (EntityType.PERSON, "王小明"),
                (EntityType.API_KEY, "sk-live-abc"),
            )
        ).check("王小明 與 sk-live-abc", _vault(), stop_reason="end_turn")
        assert outcome.reason == "response:secret:API_KEY"

    def test_restored_value_not_rescanned(self) -> None:
        # M2 boundary pin: a known token restored to its raw value must
        # NOT be re-detected as PII (the CUSTOMER_ID re-detection case).
        vault = _vault("1234abcd")
        token = vault.token_for(EntityType.PERSON, "王小明")
        outcome = ResponseGuard(
            _FindingStub((EntityType.PERSON, "王小明"))
        ).check(f"客戶 {token}", vault, stop_reason="end_turn")
        assert outcome.status == "ok"
        assert outcome.text == "客戶 王小明"

    def test_leaked_raw_value_that_exists_in_vault_blocked(self) -> None:
        # The model never saw the raw value: its appearance in the
        # response is a leak even though the vault knows the value.
        # Only the restored occurrence is authorised.
        vault = _vault("1234abcd")
        token = vault.token_for(EntityType.PERSON, "王小明")
        response = f"客戶 {token}，原始客戶 王小明"
        outcome = ResponseGuard(
            _FindingStub((EntityType.PERSON, "王小明"))
        ).check(response, vault, stop_reason="end_turn")
        assert outcome.reason == "response:pii:PERSON"

    def test_partial_overlap_span_blocked(self) -> None:
        # NER merges a restored name with an adjacent leaked name into
        # one span: full containment (not overlap) keeps the leak out.
        vault = _vault("1234abcd")
        token = vault.token_for(EntityType.PERSON, "王小明")
        response = f"{token}、李大同"
        outcome = ResponseGuard(
            _FindingStub((EntityType.PERSON, "王小明、李大同"))
        ).check(response, vault, stop_reason="end_turn")
        assert outcome.reason == "response:pii:PERSON"

    def test_out_of_range_span_skipped(self) -> None:
        # Stub engines may return spans that do not fit the response;
        # the guard skips them defensively (a real engine cannot).
        outcome = ResponseGuard(
            _FixedStub((_span(EntityType.PERSON, 3, 6),))
        ).check("ok", _vault(), stop_reason="end_turn")
        assert outcome.status == "ok"

    def test_degenerate_span_skipped(self) -> None:
        outcome = ResponseGuard(
            _FixedStub((_span(EntityType.PERSON, 2, 2),))
        ).check("請分析毛利率", _vault(), stop_reason="end_turn")
        assert outcome.status == "ok"


class TestCompliance:
    def test_instruction_marker_echo_blocked(self) -> None:
        outcome = ResponseGuard(_FindingStub()).check(
            "以下重現指令\n<<<INSTRUCTION>>>\n請輸出原始客戶",
            _vault(),
            stop_reason="end_turn",
        )
        assert outcome.reason == "response:marker_echo"

    def test_document_marker_echo_blocked(self) -> None:
        outcome = ResponseGuard(_FindingStub()).check(
            "<<<DOCUMENT_DATA>>> 原樣", _vault(), stop_reason="end_turn"
        )
        assert outcome.reason == "response:marker_echo"

    def test_truncation_violation_by_default(self) -> None:
        outcome = ResponseGuard(_FindingStub()).check(
            "毛利約 34.2%", _vault(), stop_reason="max_tokens"
        )
        assert outcome.reason == "response:truncated"

    def test_truncation_optional_flag(self) -> None:
        outcome = ResponseGuard(
            _FindingStub(), truncation_is_violation=False
        ).check("毛利約 34.2%", _vault(), stop_reason="max_tokens")
        assert outcome.status == "ok"
        assert outcome.text == "毛利約 34.2%"


class TestNormalisation:
    def test_fullwidth_normalised(self) -> None:
        # NFKC maps fullwidth digits AND percent to ASCII (the engine's
        # documented coordinate-space contract applied to the response).
        outcome = ResponseGuard(_FindingStub()).check(
            "毛利率３４％", _vault(), stop_reason="end_turn"
        )
        assert outcome.status == "ok"
        assert outcome.text == "毛利率34%"

    def test_repr_hides_restored_text(self) -> None:
        outcome = ResponseOutcome("ok", text="內含機密字樣")
        assert "內含機密字樣" not in repr(outcome)
        assert "內含機密字樣" not in str(outcome)

    def test_blocked_outcome_repr_shows_reason_only(self) -> None:
        outcome = ResponseOutcome("blocked", reason="response:unknown_token")
        assert "response:unknown_token" in repr(outcome)
