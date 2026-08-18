"""M2 security test suite — tokenisation threat traceability.

Every case maps to a threat / security requirement:
- SR-019 / T-I03: session-scoped vault, no cross-session persistence
- SR-002 / T-I05: no raw value, no token, no mapping in any surface
  (payload, report, logs, repr) — the payload is the M2 proxy for the
  future LLM request (mappings never enter LLM requests)
- SR-022 / T-I08: instruction is protected input, same pipeline as
  the document; instruction secrets BLOCK the request
- SR-023 / T-I07: opaque, non-sequential tokens (no internal sequence)
- T-T03: reserved token namespace handled without confusion
- T-T01: mapping store integrity (no mutation surface, no fabrication)
- SR-024: dispositions executed end-to-end

The engine is stubbed (duck-typed); no NLP model is loaded here.
"""

from __future__ import annotations

import logging
import re

import pytest

from secure_ai_gateway.limits import ResourceLimits
from secure_ai_gateway.logging import log_event
from secure_ai_gateway.models import (
    CellDetection,
    DetectionSpan,
    Disposition,
    EntityType,
    SpanSource,
)
from secure_ai_gateway.pipeline import Pipeline
from secure_ai_gateway.tokenisation.substitution import restore_text
from secure_ai_gateway.tokenisation.vault import (
    _RESERVED_TOKEN_PREFIXES,
    SessionTokenVault,
)

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9]*_[0-9a-f]{8}$")


class StubEngine:
    """Duck-typed DetectionEngine; instruction-aware."""

    def __init__(
        self,
        spans_by_cell: dict[str, tuple[DetectionSpan, ...]],
        instruction_spans: tuple[DetectionSpan, ...] = (),
    ):
        self._spans = spans_by_cell
        self._instruction_spans = instruction_spans

    def analyze_cell(self, cell):
        return CellDetection(
            cell_id=cell.cell_id,
            spans=self._spans.get(cell.cell_id, ()),
        )

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]:
        return self._instruction_spans


def _span(
    entity: EntityType,
    start: int,
    end: int,
    raw: str,
    score: float = 0.9,
) -> DetectionSpan:
    return DetectionSpan(
        entity, start, end, score, SpanSource.PATTERN, raw
    )


@pytest.fixture
def pii_csv(tmp_path):
    """One PII cell (王小明) + one clean numeric cell."""
    f = tmp_path / "pii.csv"
    f.write_bytes(
        "客戶,營業收入\n王小明,8.4M\n".encode()
    )
    return f


def _pipeline_with_person(cell_value: str, tmp_path, **extra_spans):
    """Fixture file whose r1_c0 is ``cell_value`` with a full-span
    PERSON detection; returns (file, pipeline)."""
    f = tmp_path / "x.csv"
    f.write_bytes(
        f"客戶,營業收入\n{cell_value},8.4M\n".encode()
    )
    spans = {"r1_c0": (_span(EntityType.PERSON, 0, len(cell_value), cell_value),)}
    spans.update(extra_spans)
    return f, Pipeline(StubEngine(spans), ResourceLimits())


class TestSessionIsolation:
    """SR-019: session-scoped mappings, destroyed at session end."""

    def test_two_sessions_share_no_state(self, pii_csv) -> None:
        pipe = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}),
            ResourceLimits(),
        )
        _, _, _, v1 = pipe.process_file(pii_csv, request_id="r1")
        _, _, _, v2 = pipe.process_file(pii_csv, request_id="r2")
        assert v1 is not v2
        assert set(v1.tokens()).isdisjoint(v2.tokens())
        for token in v1.tokens():
            assert v2.restore(token) is None

    def test_same_raw_two_sessions_different_tokens(self, pii_csv) -> None:
        pipe = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}),
            ResourceLimits(),
        )
        _, _, _, v1 = pipe.process_file(pii_csv, request_id="r1")
        _, _, _, v2 = pipe.process_file(pii_csv, request_id="r2")
        assert v1.restore(v1.tokens()[0]) == "王小明"
        assert v2.restore(v2.tokens()[0]) == "王小明"
        assert v1.tokens()[0] != v2.tokens()[0]

    def test_clear_destroys_mappings(self) -> None:
        vault = SessionTokenVault()
        token = vault.token_for(EntityType.PERSON, "王小明")
        vault.clear()
        assert len(vault) == 0
        assert vault.restore(token) is None
        assert vault.tokens() == ()

    def test_blocked_session_leaves_no_state(self, tmp_path) -> None:
        f = tmp_path / "s.csv"
        f.write_bytes("客戶,營業收入\n王小明,8.4M\n".encode())
        pipe = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.API_KEY, 0, 3, "sk-"),)}),
            ResourceLimits(),
        )
        decision, _, retained, vault = pipe.process_file(f, request_id="r1")
        assert decision.is_blocked()
        assert retained == ()
        assert len(vault) == 0


class TestNoMappingLeak:
    """SR-002 / T-I03 / T-I05: no raw, no token, no mapping outside
    the vault — the protected payload is the M2 proxy for the future
    LLM request."""

    def _run(self, pii_csv):
        pipe = Pipeline(
            StubEngine(
                {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
                instruction_spans=(_span(EntityType.PERSON, 3, 6, "王小明"),),
            ),
            ResourceLimits(),
        )
        decision, report, retained, vault = pipe.process_file(
            pii_csv, instruction="請分析王小明", request_id="r1"
        )
        assert not decision.is_blocked()
        return decision, report, retained, vault

    def test_protected_payload_has_no_raw_values(self, pii_csv) -> None:
        _, _, retained, vault = self._run(pii_csv)
        payload = " ".join(c.value for c in retained)
        payload += " " + (vault.protected_instruction or "")
        assert "王小明" not in payload
        assert "請分析" in payload  # instruction structure survives

    def test_payload_tokens_are_reverse_map_keys(self, pii_csv) -> None:
        # Every token-looking string in the outbound payload resolves
        # through the vault — nothing foreign, nothing fabricated.
        _, _, retained, vault = self._run(pii_csv)
        payload = " ".join(c.value for c in retained)
        payload += " " + (vault.protected_instruction or "")
        found = [t for t in re.findall(r"[A-Z][A-Z0-9]*_[0-9a-f]{8}", payload)]
        assert found, "payload should carry at least the document token"
        for token in found:
            assert token in vault.tokens()
            assert vault.restore(token) == "王小明"

    def test_round_trip_restores_payload(self, pii_csv) -> None:
        _, _, retained, vault = self._run(pii_csv)
        protected = " ".join(c.value for c in retained)
        restored = restore_text(protected, vault)
        assert "王小明" in restored

    def test_report_has_no_raw_and_no_token(self, pii_csv) -> None:
        _, report, _, vault = self._run(pii_csv)
        json_text = report.to_json()
        md_text = report.to_markdown()
        assert "王小明" not in json_text and "王小明" not in md_text
        for token in vault.tokens():
            assert token not in json_text and token not in md_text
        assert report.tokenised_spans == 1

    def test_logs_contain_no_raw_and_no_token(self, pii_csv, caplog) -> None:
        with caplog.at_level(logging.DEBUG, logger="secure_ai_gateway"):
            _, _, _, vault = self._run(pii_csv)
        records = " ".join(r.getMessage() for r in caplog.records)
        assert "王小明" not in records
        for token in vault.tokens():
            assert token not in records

    def test_log_event_rejects_token_and_mapping_keys(self) -> None:
        for key in ("token_value", "mapping_id", "mapping_dump", "tokenised_spans"):
            with pytest.raises(ValueError):
                log_event(logging.getLogger("t"), "e", **{key: 1})

    def test_vault_repr_leaks_nothing(self) -> None:
        vault = SessionTokenVault()
        token = vault.token_for(EntityType.PERSON, "王小明")
        assert "王小明" not in repr(vault)
        assert token not in repr(vault)
        assert "王小明" not in vault.log_view()
        assert token not in vault.log_view()


class TestInstructionChannel:
    """SR-022 / T-I08: the instruction passes through the same
    detection + tokenisation pipeline as the document."""

    def test_instruction_pii_tokenised(self, tmp_path) -> None:
        f = tmp_path / "x.csv"
        f.write_bytes("客戶,營業收入\n王小明,8.4M\n".encode())
        pipe = Pipeline(
            StubEngine(
                {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
                instruction_spans=(
                    _span(EntityType.PERSON, 3, 6, "王小明"),
                ),
            ),
            ResourceLimits(),
        )
        decision, _, _, vault = pipe.process_file(
            f, instruction="請分析王小明", request_id="r1"
        )
        assert not decision.is_blocked()
        assert vault.protected_instruction is not None
        assert "王小明" not in vault.protected_instruction
        # Document and instruction share the session vault: same raw
        # value -> the SAME token in both places.
        doc_token = vault.tokens()[0]
        assert doc_token in vault.protected_instruction
        assert vault.restore(doc_token) == "王小明"

    def test_instruction_secret_blocks_request(self, tmp_path) -> None:
        f = tmp_path / "x.csv"
        f.write_bytes("客戶,營業收入\n王小明,8.4M\n".encode())
        pipe = Pipeline(
            StubEngine(
                {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)},
                instruction_spans=(_span(EntityType.API_KEY, 3, 9, "sk-abc"),),
            ),
            ResourceLimits(),
        )
        decision, report, retained, vault = pipe.process_file(
            f, instruction="請處理 sk-abc", request_id="r1"
        )
        assert decision.is_blocked()
        assert decision.reason == "secret:API_KEY"
        assert retained == ()
        assert len(vault) == 0
        assert report.request_id == "r1"

    def test_clean_instruction_passes_through(self, pii_csv) -> None:
        pipe = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}),
            ResourceLimits(),
        )
        _, _, _, vault = pipe.process_file(
            pii_csv, instruction="請分析毛利率趨勢", request_id="r1"
        )
        assert vault.protected_instruction == "請分析毛利率趨勢"


class TestOpaqueTokens:
    """SR-023 / T-I07: randomly generated, never sequential."""

    def test_token_format(self) -> None:
        for entity in (
            EntityType.PERSON, EntityType.EMAIL, EntityType.TW_ID,
            EntityType.CUSTOMER_ID, EntityType.COMPANY_NAME,
        ):
            token = SessionTokenVault().token_for(entity, f"raw-{entity.value}")
            assert _TOKEN_RE.match(token) is not None

    def test_vault_consumes_factory_verbatim(self) -> None:
        # A counter factory proves the vault adds NO sequence of its
        # own: tokens follow the draws exactly, in call order.
        draws = iter(["aaaa1111", "bbbb2222", "cccc3333"])

        def factory() -> str:
            return next(draws)

        vault = SessionTokenVault(token_factory=factory)
        t1 = vault.token_for(EntityType.PERSON, "王小明")
        t2 = vault.token_for(EntityType.PERSON, "李大同")
        assert (t1, t2) == ("PERSON_aaaa1111", "PERSON_bbbb2222")

    def test_fifty_real_tokens_all_distinct(self) -> None:
        vault = SessionTokenVault()
        tokens = {
            vault.token_for(EntityType.CUSTOMER_ID, f"c{i:04d}")
            for i in range(50)
        }
        assert len(tokens) == 50

    def test_prefix_reserved_set_is_documented(self) -> None:
        # The reserved namespace the detector claims; generated tokens
        # must stay outside it (property-tested in test_vault.py).
        assert _RESERVED_TOKEN_PREFIXES == {
            "CUSTOMER", "EMPLOYEE", "EMAIL", "PHONE", "ADDRESS", "LOCATION",
        }


class TestReservedNamespace:
    """T-T03: source data matching the token format is tokenised
    itself; the reserved namespace never causes confusion."""

    def test_reserved_six_hex_source_tokenised_and_restored(self, tmp_path) -> None:
        # A 6-hex CUSTOMER_ value in the source IS the reserved format:
        # it must be tokenised (never passes through raw), and the
        # round trip restores the exact original.
        source = "CUSTOMER_4f8a21"
        f, _ = _pipeline_with_person(source, tmp_path)
        pipe = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.TOKEN_PATTERN, 0, len(source), source),)}),
            ResourceLimits(),
        )
        decision, _, retained, vault = pipe.process_file(f, request_id="r1")
        assert not decision.is_blocked()
        cell = next(c for c in retained if c.cell_id == "r1_c0")
        assert cell.value != source
        assert "CUSTOMER_" not in cell.value
        assert cell.value.startswith("TOKEN_")
        assert vault.restore(cell.value) == source

    def test_eight_hex_token_shaped_source_unconfused(self, tmp_path) -> None:
        # An 8-hex value is token-SHAPED but NOT the reserved format;
        # it is still PII (CUSTOMER_ID) and round-trips cleanly.
        source = "CUSTOMER_ab12cd34"
        f, _ = _pipeline_with_person(source, tmp_path)
        pipe = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.CUSTOMER_ID, 0, len(source), source),)}),
            ResourceLimits(),
        )
        decision, _, retained, vault = pipe.process_file(f, request_id="r1")
        assert not decision.is_blocked()
        cell = next(c for c in retained if c.cell_id == "r1_c0")
        assert cell.value != source
        assert _TOKEN_RE.match(cell.value)
        assert vault.restore(cell.value) == source

    def test_generated_tokens_never_match_reserved_regex(self) -> None:
        # Property: many real tokens across prefixes never match the
        # reserved TOKEN_PATTERN namespace (unit-level re-check).
        from secure_ai_gateway.detection.recognizers import _TOKEN_PATTERN_RE

        reserved = re.compile(
            _TOKEN_PATTERN_RE.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL
        )
        vault = SessionTokenVault()
        for i in range(300):
            token = vault.token_for(
                EntityType.EMAIL if i % 2 else EntityType.PERSON,
                f"raw{i:05d}",
            )
            assert reserved.search(token) is None


class TestVaultIntegrity:
    """T-T01: the mapping store cannot be tampered with through the
    public surface."""

    def test_public_surface_is_read_only_plus_token_for(self) -> None:
        vault = SessionTokenVault()
        public = {name for name in dir(vault) if not name.startswith("_")}
        assert public <= {
            "clear", "log_view", "protected_instruction", "restore",
            "token_for", "tokens",
        }

    def test_token_for_stable_for_key(self) -> None:
        vault = SessionTokenVault()
        a = vault.token_for(EntityType.PERSON, "王小明")
        b = vault.token_for(EntityType.PERSON, "王小明")
        assert a == b

    def test_restore_never_fabricates(self) -> None:
        vault = SessionTokenVault()
        vault.token_for(EntityType.PERSON, "王小明")
        assert vault.restore("PERSON_ffffffff") is None
        assert vault.restore("王小明") is None

    def test_vaults_share_no_dict_state(self) -> None:
        v1 = SessionTokenVault()
        v2 = SessionTokenVault()
        t1 = v1.token_for(EntityType.PERSON, "王小明")
        assert t1 not in v2.tokens()
        assert v2.restore(t1) is None


class TestDispositionsExecuted:
    """SR-024: policy dispositions are executed end-to-end."""

    def test_tokenise_executed(self, pii_csv) -> None:
        pipe = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}),
            ResourceLimits(),
        )
        decision, report, retained, vault = pipe.process_file(
            pii_csv, request_id="r1"
        )
        assert not decision.is_blocked()
        assert decision.disposition_for("r1_c0") is Disposition.TOKENISE
        assert report.tokenised_spans == 1
        cell = next(c for c in retained if c.cell_id == "r1_c0")
        assert "王小明" not in cell.value
        assert vault.restore(cell.value) == "王小明"

    def test_secret_blocks(self, tmp_path) -> None:
        f = tmp_path / "s.csv"
        f.write_bytes("客戶,營業收入\nsk-live-abc,8.4M\n".encode())
        pipe = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.API_KEY, 0, 11, "sk-live-abc"),)}),
            ResourceLimits(),
        )
        decision, _, retained, _ = pipe.process_file(f, request_id="r1")
        assert decision.is_blocked()
        assert decision.reason == "secret:API_KEY"
        assert retained == ()

    def test_non_required_column_dropped(self, tmp_path) -> None:
        f = tmp_path / "w.csv"
        f.write_bytes(
            "客戶,營業收入,員工手機\n王小明,8.4M,0912345678\n".encode()
        )
        pipe = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}),
            ResourceLimits(),
        )
        decision, report, retained, _ = pipe.process_file(f, request_id="r1")
        assert not decision.is_blocked()
        assert "r1_c2" not in {c.cell_id for c in retained}
        assert report.dropped_cells == 2  # header + data cell

    def test_allow_cell_passes_raw_non_pii(self, pii_csv) -> None:
        pipe = Pipeline(
            StubEngine({"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}),
            ResourceLimits(),
        )
        _, _, retained, _ = pipe.process_file(pii_csv, request_id="r1")
        values = {c.cell_id: c.value for c in retained}
        assert values["r1_c1"] == "8.4M"
        assert values["r0_c0"] == "客戶"