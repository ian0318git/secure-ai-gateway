"""The recording seams: capture-at-issue beats ``vault.clear()``.

The load-bearing claim of the whole tool is that a session's mapping is
captured **before** SR-019 destroys it. These tests assert both halves
in the same breath: the real vault is empty afterwards, and the payload
still carries the mapping.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from conftest import (
    RAW_PERSON_1,
    RAW_PERSON_2,
    REQUEST_ID,
    TOKEN_RE,
    BoomProvider,
    EchoLikeProvider,
    Harness,
    SessionRun,
    span,
)

from secure_ai_gateway.llm.response_parser import ParsedResponse
from secure_ai_gateway.models import CellDetection, EntityType
from secure_ai_gateway.pipeline import Pipeline
from secure_ai_gateway.session import Session
from tools.dashboard.recorder import (
    DashboardRecorder,
    RecordingProvider,
    RecordingVault,
    _MemoryLogHandler,
    wrap_engine,
)


class UnknownTokenProvider:
    """Answers with a well-formed but never-issued token — the M4
    guard must fail closed (``response:unknown_token``)."""

    def complete(self, request) -> ParsedResponse:
        return ParsedResponse(
            text="客戶 PERSON_deadbeef 的營收成長", stop_reason="end_turn"
        )


class PhaseEngine:
    """Returns different spans for the instruction scan and the
    response scan, so a test can prove which one was recorded."""

    def __init__(self, spans_by_cell) -> None:
        self._spans = spans_by_cell
        self.text_calls: list[str] = []

    def analyze_cell(self, cell) -> CellDetection:
        return CellDetection(
            cell_id=cell.cell_id, spans=self._spans.get(cell.cell_id, ())
        )

    def analyze_text(self, text: str):
        self.text_calls.append(text)
        if len(self.text_calls) == 1:  # protect_instruction
            return (span(EntityType.PERSON, 0, 3, RAW_PERSON_2),)
        return (span(EntityType.CREDIT_CARD, 0, 5, "41111"),)  # guard scan


class TestCaptureAtIssue:
    def test_mapping_survives_the_session_clearing_the_vault(
        self, finished: SessionRun
    ) -> None:
        # SR-019 is intact: the session cleared the real vault...
        assert len(finished.vault) == 0
        # ...yet the mapping was captured at issue time.
        assert len(finished.payload["mapping"]) == 2
        raws = {entry["raw"] for entry in finished.payload["mapping"]}
        assert raws == {RAW_PERSON_1, RAW_PERSON_2}

    def test_captured_tokens_match_what_crossed_the_wire(
        self, finished: SessionRun
    ) -> None:
        issued = {e["token"] for e in finished.payload["mapping"]}
        protected = {
            cell["value_protected"] for cell in finished.payload["cells"]
        }
        on_wire = set(TOKEN_RE.findall(str(finished.payload["payload"])))
        assert issued == on_wire, "wire carries a token we did not record"
        for token in issued:
            assert any(token in str(value) for value in protected)

    def test_blocked_response_still_reports_the_mapping(
        self, doc: Path, person_spans
    ) -> None:
        harness = Harness(
            spans_by_cell=person_spans, provider=UnknownTokenProvider()
        )
        run = harness.run(doc, instruction="請分析")
        assert not run.result.delivered
        assert run.result.decision.reason == "response:unknown_token"
        assert len(run.vault) == 0
        assert len(run.payload["mapping"]) == 2

    def test_provider_failure_fails_closed_and_is_recorded(
        self, doc: Path, person_spans
    ) -> None:
        harness = Harness(
            spans_by_cell=person_spans, provider=BoomProvider()
        )
        run = harness.run(doc)
        assert not run.result.delivered
        assert run.result.decision.reason == "error:RuntimeError"
        assert len(run.vault) == 0
        # Tokenisation happened before the provider was called, so the
        # mapping is still complete despite the failure.
        assert len(run.payload["mapping"]) == 2


class TestPhaseDisambiguation:
    def test_response_scan_never_overwrites_instruction_spans(
        self, doc: Path, person_spans
    ) -> None:
        recorder = DashboardRecorder()
        engine = PhaseEngine(person_spans)
        pipeline = Pipeline(
            wrap_engine(recorder, engine),
            vault_factory=lambda: RecordingVault(recorder),
        )
        session = Session(
            pipeline, RecordingProvider(recorder, EchoLikeProvider())
        )
        recorder.begin_session("p1", RAW_PERSON_2)
        with recorder.capture_logs():
            result = session.run(
                doc, instruction=RAW_PERSON_2, request_id="p1"
            )
        recorder.finish(result)
        trace = recorder.trace("p1")
        assert trace is not None

        # analyze_text ran twice — instruction, then response guard.
        assert len(engine.text_calls) == 2
        assert engine.text_calls[0] == RAW_PERSON_2
        # Only the instruction scan is reported; the response scan
        # (CREDIT_CARD) must not have leaked into the instruction view.
        assert {
            s["entity_type"] for s in trace.instruction_spans
        } == {"PERSON"}


class TestStageTracking:
    def test_every_stage_reaches_done_on_a_delivered_run(
        self, finished: SessionRun
    ) -> None:
        stages = {s["id"]: s["status"] for s in finished.payload["stages"]}
        assert stages == {
            "parse": "done",
            "detect": "done",
            "policy": "done",
            "minimise": "done",
            "tokenise": "done",
            "provider": "done",
            "response": "done",
        }

    def test_stages_after_a_policy_block_stay_pending(
        self, doc: Path, person_spans
    ) -> None:
        harness = Harness(
            spans_by_cell=person_spans,
            instruction_spans=(span(EntityType.API_KEY, 0, 5, "sk-xx"),),
        )
        run = harness.run(doc, instruction="sk-xx")
        assert not run.result.delivered
        stages = {s["id"]: s["status"] for s in run.payload["stages"]}
        assert stages["parse"] == "done"
        assert stages["provider"] == "pending"
        assert stages["response"] == "pending"


class TestObservations:
    def test_cells_record_raw_values_and_spans(
        self, finished: SessionRun
    ) -> None:
        by_id = {c["cell_id"]: c for c in finished.payload["cells"]}
        first = by_id["r1_c0"]
        assert first["value"] == RAW_PERSON_1
        assert first["value_protected"] != RAW_PERSON_1
        assert first["disposition"] == "TOKENISE"
        assert [s["raw"] for s in first["spans"]] == [RAW_PERSON_1]
        assert first["spans"][0]["entity_type"] == "PERSON"

    def test_headers_are_recorded_too(self, finished: SessionRun) -> None:
        by_id = {c["cell_id"]: c for c in finished.payload["cells"]}
        assert by_id["r0_c0"]["column"] == "客戶"
        assert by_id["r0_c0"]["value"] == "客戶"

    def test_mapping_records_where_each_value_occurred(
        self, finished: SessionRun
    ) -> None:
        entry = next(
            e for e in finished.payload["mapping"] if e["raw"] == RAW_PERSON_1
        )
        assert len(entry["occurrences"]) == 1
        assert entry["occurrences"][0]["cell_id"] == "r1_c0"
        assert entry["occurrences"][0]["column"] == "客戶"

    def test_instruction_and_its_protected_form_are_both_captured(
        self, doc: Path, person_spans
    ) -> None:
        harness = Harness(
            spans_by_cell=person_spans,
            instruction_spans=(
                span(EntityType.PERSON, 0, len(RAW_PERSON_2), RAW_PERSON_2),
            ),
        )
        instruction = f"{RAW_PERSON_2} 的毛利率"
        run = harness.run(doc, instruction=instruction)
        recorded = run.payload["instruction"]
        assert recorded["text"] == instruction
        assert recorded["protected"] != instruction
        assert RAW_PERSON_2 not in (recorded["protected"] or "")
        assert [s["raw"] for s in recorded["spans"]] == [RAW_PERSON_2]

    def test_audit_events_are_captured_in_order(
        self, finished: SessionRun
    ) -> None:
        events = [
            entry["event"].split(" ", 1)[0]
            for entry in finished.payload["audit"]
        ]
        assert events == ["parsed", "processed", "provider_call", "provider_ok"]

    def test_report_channel_is_captured(
        self, finished: SessionRun
    ) -> None:
        assert finished.payload["report"] == finished.result.report.to_dict()
        assert (
            finished.payload["report_markdown"]
            == finished.result.report.to_markdown()
        )


class TestRetention:
    def test_max_sessions_evicts_the_oldest(self, doc: Path, person_spans):
        harness = Harness(spans_by_cell=person_spans, max_sessions=2)
        for index in range(3):
            harness.run(doc, request_id=f"s{index}")
        assert harness.recorder.request_ids() == ("s1", "s2")

    def test_purge_finished_before_drops_only_stale_sessions(
        self, doc: Path, person_spans
    ) -> None:
        harness = Harness(spans_by_cell=person_spans)
        harness.run(doc, request_id="old")
        harness.run(doc, request_id="new")
        # A trace is stale when it FINISHED before the cutoff — the
        # cutoff is "now minus the retention window", so a cutoff in the
        # past drops nothing, and a cutoff in the future drops all.
        assert harness.recorder.purge_finished_before(0.0) == 0
        assert harness.recorder.request_ids() == ("old", "new")
        assert harness.recorder.purge_finished_before(time.time() + 1) == 2
        assert harness.recorder.request_ids() == ()
        assert harness.recorder.current() is None
        harness.run(doc, request_id="again")
        assert harness.recorder.purge_finished_before(0.0) == 0
        assert harness.recorder.request_ids() == ("again",)

    def test_purge_keeps_a_running_session(
        self, doc: Path, person_spans
    ) -> None:
        harness = Harness(spans_by_cell=person_spans)
        harness.run(doc, request_id="done")
        harness.recorder.begin_session("live")
        assert harness.recorder.purge_finished_before(10**12) == 1
        assert harness.recorder.request_ids() == ("live",)


class TestLogCapture:
    def test_handler_is_detached_after_the_context_exits(
        self, doc: Path, person_spans
    ) -> None:
        harness = Harness(spans_by_cell=person_spans)
        logger = logging.getLogger("secure_ai_gateway")
        before = len(logger.handlers)
        with harness.recorder.capture_logs():
            assert len(logger.handlers) == before + 1
        assert len(logger.handlers) == before

    def test_level_is_restored_after_the_context_exits(
        self, doc: Path, person_spans
    ) -> None:
        harness = Harness(spans_by_cell=person_spans)
        logger = logging.getLogger("secure_ai_gateway")
        before = logger.level
        with harness.recorder.capture_logs():
            pass
        assert logger.level == before

    def test_events_are_captured_even_without_basicConfig(
        self, doc: Path, person_spans
    ) -> None:
        # Python's default root level is WARNING, and ``Logger.log``
        # drops the record at the call site before any handler runs —
        # so without the level bump in ``capture_logs`` the audit panel
        # is silently empty for a caller that never called
        # ``basicConfig``. Force that condition explicitly rather than
        # trusting the ambient level pytest happens to have left.
        root = logging.getLogger()
        previous = root.level
        root.setLevel(logging.WARNING)
        try:
            harness = Harness(spans_by_cell=person_spans)
            run = harness.run(doc)
        finally:
            root.setLevel(previous)
        assert [e["event"].split(" ")[0] for e in run.payload["audit"]][
            :2
        ] == ["parsed", "processed"]

    def test_console_logging_is_not_disturbed(
        self, doc: Path, person_spans, caplog
    ) -> None:
        harness = Harness(spans_by_cell=person_spans)
        with caplog.at_level(logging.INFO, logger="secure_ai_gateway"):
            harness.run(doc)
        assert any(
            r.getMessage().startswith("parsed ") for r in caplog.records
        )

    def test_a_broken_log_record_never_breaks_a_run(
        self, harness: Harness
    ) -> None:
        # ``record.getMessage()`` raises on the format/argument mismatch.
        # The recorder's handler must swallow it: a logging call must
        # never be able to abort a pipeline run.
        record = logging.LogRecord(
            "secure_ai_gateway",
            logging.ERROR,
            __file__,
            1,
            "%d",
            ("not-a-number",),
            None,
        )
        handler = _MemoryLogHandler(harness.recorder.note_log)
        handler.emit(record)  # must not raise
        assert harness.recorder.trace(REQUEST_ID) is None

    def test_a_broken_log_record_is_swallowed_through_the_logger(
        self, harness: Harness
    ) -> None:
        # Same claim through ``Logger.handle`` — the path a real call
        # takes. ``propagate`` is turned off so pytest's own handler
        # (which re-raises on a broken record) is not what is measured.
        record = logging.LogRecord(
            "secure_ai_gateway",
            logging.ERROR,
            __file__,
            1,
            "%d",
            ("not-a-number",),
            None,
        )
        logger = logging.getLogger("secure_ai_gateway")
        previous = logger.propagate
        logger.propagate = False
        try:
            with harness.recorder.capture_logs():
                logger.handle(record)  # must not raise
        finally:
            logger.propagate = previous
        assert harness.recorder.trace(REQUEST_ID) is None


class TestTraceLookup:
    def test_unknown_request_id_returns_none(self, harness: Harness) -> None:
        assert harness.recorder.trace("nope") is None

    def test_revision_increases_as_the_session_runs(
        self, harness: Harness, doc: Path
    ) -> None:
        start = harness.recorder.revision
        harness.run(doc)
        assert harness.recorder.revision > start
