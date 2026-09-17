"""Channel isolation, proven by sweep rather than by inspection.

Two claims are load-bearing here and they are different claims:

**C1 — structural separation.** ``payload["report"]`` is *exactly*
``MetadataReport.to_dict()``. It is not "the report plus a bit", so the
existing security suite's guarantee (report channels carry no raw and no
token) transfers to the dashboard unchanged, with no new argument.

**C2 — no undeclared raw.** Everything outside ``RAW_OR_TOKEN_PATHS`` is
raw-free and token-free. The sweep is evidence, not proof: an undeclared
field is caught only when it holds a fixture-known value or a
``TOKEN_RE`` match. The companion test asserts the declared paths really
exist and the raw really is present — so a sweep that passes vacuously
fails instead.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import (
    CSV_BYTES,
    RAW_PERSON_1,
    RAW_PERSON_2,
    TOKEN_RE,
    Harness,
    SessionRun,
    keys_of,
    span,
    walk_paths,
)

from secure_ai_gateway.models import EntityType
from tools.dashboard.model import (
    RAW_OR_TOKEN_PATHS,
    redacted_view,
    to_payload,
)

SENTINEL = "SENTINELVALUEzz"


@pytest.fixture
def rich(doc: Path, person_spans) -> SessionRun:
    """A delivered run where EVERY declared raw path is populated.

    The instruction carries a protected value too, so
    ``instruction.protected`` and ``instruction.spans[].raw`` are not
    ``None`` — otherwise the sweep would skip them silently.
    """
    harness = Harness(
        spans_by_cell=person_spans,
        instruction_spans=(
            span(EntityType.PERSON, 0, len(RAW_PERSON_2), RAW_PERSON_2),
        ),
    )
    return harness.run(doc, instruction=f"{RAW_PERSON_2} 的毛利率")


def resolve(node, path: str) -> list:
    """Every value a declared ``RAW_OR_TOKEN_PATHS`` entry resolves to."""
    values = [node]
    for part in path.split("."):
        many = part.endswith("[]")
        key = part[:-2] if many else part
        nxt: list = []
        for value in values:
            if not isinstance(value, dict) or key not in value:
                continue
            child = value[key]
            if not many:
                nxt.append(child)
            elif isinstance(child, list):
                nxt.extend(child)
        values = nxt
    return values


def build(path: str) -> dict:
    """A minimal payload holding ``SENTINEL`` at exactly ``path``."""
    parts = path.split(".")
    root: dict = {}
    cursor: dict = root
    for part in parts[:-1]:
        many = part.endswith("[]")
        key = part[:-2] if many else part
        nxt: dict = {}
        if many:
            cursor[key] = [nxt]
        else:
            cursor[key] = nxt
        cursor = nxt
    last = parts[-1]
    if last.endswith("[]"):
        cursor[last[:-2]] = [SENTINEL]
    else:
        cursor[last] = SENTINEL
    return root


def leaves(payload: dict) -> list[tuple[str, object]]:
    return walk_paths(payload)


class TestReportChannelIsTheLibraryReport:
    def test_report_is_exactly_the_library_report(
        self, rich: SessionRun
    ) -> None:
        assert rich.payload["report"] == rich.result.report.to_dict()

    def test_report_markdown_is_exactly_the_library_markdown(
        self, rich: SessionRun
    ) -> None:
        assert (
            rich.payload["report_markdown"]
            == rich.result.report.to_markdown()
        )

    def test_mapping_is_never_inside_the_report_channel(
        self, rich: SessionRun
    ) -> None:
        # The separation is structural, not a redaction step: the
        # report channel is the library object, so a mapping key can
        # only get in by the library putting it there.
        assert "mapping" not in rich.payload["report"]
        assert "mapping" not in rich.payload["report_markdown"]

    def test_report_channel_carries_no_raw_and_no_token(
        self, rich: SessionRun
    ) -> None:
        text = json.dumps(rich.payload["report"], ensure_ascii=False)
        text += rich.payload["report_markdown"]
        for raw in (RAW_PERSON_1, RAW_PERSON_2):
            assert raw not in text
        assert TOKEN_RE.search(text) is None


class TestRedactedSweep:
    def test_sweep_is_not_vacuous(self, rich: SessionRun) -> None:
        # Without this, every assertion below would pass on a payload
        # that simply recorded nothing.
        text = json.dumps(rich.payload, ensure_ascii=False)
        assert RAW_PERSON_1 in text and RAW_PERSON_2 in text
        assert TOKEN_RE.search(text) is not None
        assert rich.payload["mapping"]

    def test_nothing_outside_declared_paths_carries_raw(
        self, rich: SessionRun
    ) -> None:
        for path, value in leaves(redacted_view(rich.payload)):
            for raw in (RAW_PERSON_1, RAW_PERSON_2):
                assert raw not in str(value), f"{path} carries raw content"

    def test_nothing_outside_declared_paths_carries_a_token(
        self, rich: SessionRun
    ) -> None:
        for path, value in leaves(redacted_view(rich.payload)):
            assert TOKEN_RE.search(str(value)) is None, f"{path} carries a token"

    def test_nothing_outside_declared_paths_carries_a_credential(
        self, rich: SessionRun
    ) -> None:
        # The provider seam never sees ``x-api-key``, so no credential
        # can reach the dashboard at all — asserted, not assumed.
        for path, value in leaves(redacted_view(rich.payload)):
            assert "sk-" not in str(value), f"{path} carries a credential"

    def test_redaction_leaves_the_report_channel_intact(
        self, rich: SessionRun
    ) -> None:
        assert redacted_view(rich.payload)["report"] == rich.payload["report"]

    def test_redaction_is_non_destructive(self, rich: SessionRun) -> None:
        before = json.dumps(rich.payload, ensure_ascii=False, sort_keys=True)
        redacted_view(rich.payload)
        assert (
            json.dumps(rich.payload, ensure_ascii=False, sort_keys=True)
            == before
        )


class TestDeclaredPathsDoNotDrift:
    @pytest.mark.parametrize("path", sorted(RAW_OR_TOKEN_PATHS))
    def test_every_declared_path_is_populated(self, rich, path) -> None:
        # A declared path that never holds anything is a path whose
        # protection is untested; a declared path that no longer exists
        # means the field was renamed and the declaration is stale.
        values = resolve(rich.payload, path)
        assert values, f"{path} does not exist in the payload"
        assert all(value is not None for value in values), path

    @pytest.mark.parametrize("path", sorted(RAW_OR_TOKEN_PATHS))
    def test_stripper_actually_reaches_every_declared_path(self, path) -> None:
        # The other direction: `redacted_view` must remove the value at
        # every declared path, including the nested `[]` ones.
        stripped = json.dumps(redacted_view(build(path)))
        assert SENTINEL not in stripped, f"stripper misses {path}"

    def test_an_undeclared_field_is_caught_by_the_sweep(self) -> None:
        # Guards the guard: the sweep must actually notice a leak, i.e.
        # it is not simply returning nothing.
        payload = to_payload(_trace_with_stray_raw())
        leaked = [
            path
            for path, value in leaves(redacted_view(payload))
            if RAW_PERSON_1 in str(value)
        ]
        assert leaked, "the sweep would not have caught a stray raw field"


def _trace_with_stray_raw():
    """A trace carrying a raw value OUTSIDE every declared path."""
    from tools.dashboard.model import SessionTrace

    trace = SessionTrace(request_id="x", started_at=0.0)
    trace.audit.append({"event": f"stray {RAW_PERSON_1}"})
    return trace


class TestWireBody:
    def test_recorded_body_is_what_the_provider_received(
        self, rich: SessionRun
    ) -> None:
        received = rich.harness.provider.requests[0]
        assert rich.payload["payload"]["body"] == received.to_body()

    def test_to_body_is_stable(self, rich: SessionRun) -> None:
        received = rich.harness.provider.requests[0]
        assert received.to_body() == received.to_body()

    def test_wire_body_carries_no_raw(self, rich: SessionRun) -> None:
        body = json.dumps(rich.payload["payload"]["body"], ensure_ascii=False)
        assert RAW_PERSON_1 not in body
        assert RAW_PERSON_2 not in body

    def test_wire_body_carries_tokens_but_never_the_mapping(
        self, rich: SessionRun
    ) -> None:
        body = rich.payload["payload"]["body"]
        text = json.dumps(body, ensure_ascii=False)
        assert TOKEN_RE.findall(text), "document tokens should be on the wire"
        # The body has an exact, closed key set. Asserting the shape is
        # the durable form of this claim: a substring grep for
        # "mapping" would trip over the system prompt's own prose
        # ("their mapping never leaves the caller's environment").
        assert set(body) == {"model", "max_tokens", "system", "messages"}
        assert "mapping" not in set(keys_of(body))

    def test_no_mapping_raw_value_appears_on_the_wire(
        self, rich: SessionRun
    ) -> None:
        text = json.dumps(rich.payload["payload"]["body"], ensure_ascii=False)
        for entry in rich.payload["mapping"]:
            assert entry["raw"] not in text
            assert entry["token"] in text

    def test_system_prompt_is_not_raw_document_content(
        self, rich: SessionRun
    ) -> None:
        system = rich.payload["payload"]["system"]
        assert RAW_PERSON_1 not in system
        assert TOKEN_RE.search(system) is None


class TestAuditChannel:
    """The M5 battery (tests/security/test_m5_audit.py:217-236), re-run
    over the events as the RECORDER captured them — the recorder must
    not be a route by which a log-only guarantee is weakened."""

    def test_audit_events_carry_no_raw(
        self, rich: SessionRun
    ) -> None:
        joined = " ".join(e["event"] for e in rich.payload["audit"])
        assert joined, "no audit events were captured"
        assert RAW_PERSON_1 not in joined
        assert RAW_PERSON_2 not in joined
        assert "sk-" not in joined
        assert TOKEN_RE.search(joined) is None
        assert "<<<" not in joined  # prompt framing

    def test_every_audit_event_carries_the_request_id(
        self, rich: SessionRun
    ) -> None:
        for entry in rich.payload["audit"]:
            assert "request_id=" in entry["event"], entry["event"]

    def test_audit_events_are_structured_not_reparsed(
        self, rich: SessionRun
    ) -> None:
        # The recorder stores the sanitised message verbatim; it never
        # re-renders it (a second renderer is a second place to leak).
        assert all(
            set(entry) == {"at", "logger", "level", "event"}
            for entry in rich.payload["audit"]
        )


class TestSourceMetadata:
    def test_source_records_the_file_but_not_its_contents(
        self, rich: SessionRun
    ) -> None:
        assert rich.payload["source"]["name"] == "report.csv"
        assert rich.payload["source"]["rows"] == 3

    def test_a_second_file_is_not_confused_with_the_first(
        self, tmp_path: Path, person_spans
    ) -> None:
        harness = Harness(spans_by_cell=person_spans)
        other = tmp_path / "other.csv"
        other.write_bytes(CSV_BYTES)
        run = harness.run(other)
        assert run.payload["source"]["name"] == "other.csv"
