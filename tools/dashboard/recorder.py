"""Capture architecture: observe a real ``Session.run`` from outside.

Every hook here is a **pre-existing public extension point** of the
gateway — ``src/secure_ai_gateway`` is not modified by this tool:

===========  ==========================================  ==============
Seam         Existing hook                               Observes
===========  ==========================================  ==============
Vault        ``Pipeline(vault_factory=...)``             the mapping,
             (``pipeline.py:93-97``)                     at ISSUE time
Engine       ``Pipeline(engine, ...)`` — the duck-typed  cells + spans
             seam the test suite already uses
Provider     ``Session(pipeline, provider)``             wire body +
                                                         raw response
Logging      a ``logging.Handler`` on the parent logger  audit stream
===========  ==========================================  ==============

**Why capture at issue time rather than snapshotting the vault:**
``Session.run`` calls ``vault.clear()`` in a ``finally``
(``session.py:159``). Any scheme that snapshots the vault races a block
it does not control, and breaks silently on refactor.
``SessionTokenVault.token_for`` is the ONLY token-creation path
(``vault.py:110-126``), so recording there captures the complete
mapping before any ``clear()`` can run — on every path, including the
fail-closed ones. This mirrors the M6 ``PersistentSessionVault``
precedent.

**Why the provider seam, not the transport seam:** a transport wrapper
would (a) miss ``EchoProvider``, which has no transport, and (b) *see
the ``x-api-key`` header*. The provider seam never sees the credential,
so there is no secret anywhere in the dashboard's data.

SR-019 is preserved: ``clear()`` still destroys the real mapping. The
recorder holds a SEPARATE in-memory structure, released at process
exit (recorded exception, docs/DECISIONS.md 2026-09-18).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, Protocol, cast

from secure_ai_gateway.detection.engine import DetectionEngine
from secure_ai_gateway.llm.provider import LLMProvider
from secure_ai_gateway.llm.request_builder import LLMRequest
from secure_ai_gateway.llm.response_parser import ParsedResponse
from secure_ai_gateway.models import (
    CellDetection,
    DetectionSpan,
    DocumentCell,
    EntityType,
)
from secure_ai_gateway.session import SessionResult
from secure_ai_gateway.tokenisation.vault import SessionTokenVault
from tools.dashboard.model import SessionTrace

_LOG_ROOT = "secure_ai_gateway"

#: Log events that mark an exact stage boundary (no inference needed
#: except ``detect``, which is labelled honestly in the UI).
_STAGE_DONE = {
    "parsed": ("parse",),
    "processed": ("detect", "policy", "minimise", "tokenise"),
}

#: Terminal events that name the stage that actually failed. A bare
#: ``blocked`` is NOT listed: it fires both for a policy block (nothing
#: failed) and for a pipeline exception (we cannot say where), so the
#: remaining stages stay ``pending`` rather than being mislabelled.
_STAGE_FAILED = {
    "response_blocked": "response",
    "provider_blocked": "provider",
}


class _LogSink(Protocol):
    def __call__(
        self, logger: str, level: str, message: str, created: float
    ) -> None: ...


class _MemoryLogHandler(logging.Handler):
    """Captures already-sanitised ``log_event`` output, in memory only.

    Reads the sanitised stream; never writes to it. ``emit`` never
    raises (logging would swallow it, but silent failure is worse than
    a dropped line).
    """

    def __init__(self, sink: _LogSink) -> None:
        super().__init__()
        self._sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 — a log line must never break a run
            return
        try:
            self._sink(record.name, record.levelname, message, record.created)
        except Exception:  # noqa: BLE001 — same
            return


class DashboardRecorder:
    """Owns the captured traces. One writer, N readers.

    The session worker thread is the only writer; HTTP handler threads
    read. Every access goes through ``self._lock``.
    """

    def __init__(self, *, max_sessions: int = 20) -> None:
        self._lock = threading.RLock()
        self._traces: dict[str, SessionTrace] = {}
        self._order: list[str] = []
        self._current: SessionTrace | None = None
        self._phase = "request"
        self._revision = 0
        self._max_sessions = max_sessions

    # -- session lifecycle --------------------------------------------------

    def begin_session(
        self, request_id: str, instruction: str | None = None
    ) -> SessionTrace:
        with self._lock:
            trace = SessionTrace(
                request_id=request_id,
                started_at=time.time(),
                instruction=instruction,
            )
            trace.stages["parse"] = {
                "status": "running",
                "detail": "",
                "at": time.time(),
            }
            self._current = trace
            self._phase = "request"
            self._traces[request_id] = trace
            self._order.append(request_id)
            self._evict_locked()
            self._revision += 1
            return trace

    def finish(
        self, result: SessionResult, *, error: str | None = None
    ) -> None:
        with self._lock:
            trace = self._current
            if trace is None:
                return
            trace.finished_at = time.time()
            trace.status = (
                "error"
                if error
                else ("delivered" if result.delivered else "blocked")
            )
            trace.status_reason = error or result.decision.reason
            trace.error = error
            trace.report = result.report.to_dict()
            trace.report_markdown = result.report.to_markdown()
            trace.source = {
                "name": result.report.source_name,
                "format": result.report.file_format,
                "encoding": result.report.encoding,
                "rows": result.report.row_count,
                "cells": result.report.cell_count,
                "estimated_tokens": result.report.estimated_tokens,
                "neutralised_formula_cells": (
                    result.report.neutralised_formula_cells
                ),
            }
            for cell_decision in result.decision.cell_decisions:
                trace.dispositions[cell_decision.cell_id] = {
                    "disposition": cell_decision.disposition.value,
                    "reason": cell_decision.reason,
                }
            trace.outcome = {
                "delivered": result.delivered,
                "reason": result.decision.reason,
                "restored_text": result.response_text or None,
            }
            for stage in ("response", "provider"):
                if trace.stages.get(stage, {}).get("status") == "running":
                    self._set_stage_locked(stage, "done")
            self._revision += 1

    def abort(self, request_id: str, reason: str) -> None:
        """Mark a session that never produced a SessionResult."""
        with self._lock:
            trace = self._traces.get(request_id)
            if trace is None:
                return
            trace.finished_at = time.time()
            trace.status = "error"
            trace.status_reason = reason
            trace.error = reason
            self._revision += 1

    # -- observations -------------------------------------------------------

    def note_cell(self, cell: DocumentCell, detection: CellDetection) -> None:
        with self._lock:
            trace = self._current
            if trace is None:
                return
            if trace.stages.get("detect", {}).get("status") != "done":
                self._set_stage_locked("detect", "running")
            if cell.cell_id in trace.cells:
                return
            trace.cells[cell.cell_id] = {
                "cell_id": cell.cell_id,
                "column": cell.column,
                "row": cell.row,
                "value": cell.value,
                "spans": [
                    _span_record(span) for span in detection.spans
                ],
            }
            self._revision += 1

    def note_text(self, text: str, spans: tuple[DetectionSpan, ...]) -> None:
        """Record an ``analyze_text`` call on the **instruction**.

        Called twice per session: once by ``protect_instruction`` on the
        raw instruction (request phase), once by the response guard on
        the restored response (response phase). The phase flag is set by
        ``RecordingProvider`` — deterministic, no text matching, no
        re-scan of the response here (the guard's own verdict arrives on
        ``SessionResult``).

        ``text`` is deliberately not stored: it is the same string the
        caller passed as ``instruction``, already on the trace.
        """
        with self._lock:
            trace = self._current
            if trace is None or self._phase != "request":
                return
            trace.instruction_spans = [_span_record(span) for span in spans]

    def note_pair(
        self, entity_type: EntityType, raw: str, token: str
    ) -> None:
        with self._lock:
            trace = self._current
            if trace is None:
                return
            trace.mappings[(entity_type.value, raw)] = {"token": token}

    def note_protected_instruction(self, text: str | None) -> None:
        with self._lock:
            trace = self._current
            if trace is not None and text is not None:
                trace.protected_instruction = text

    def note_request(self, request: LLMRequest, body: dict[str, Any]) -> None:
        with self._lock:
            trace = self._current
            if trace is None:
                return
            trace.wire = {
                "model": request.model,
                "max_tokens": request.max_tokens,
                "system": request.system,
                "body": body,
                "chars": len(request.to_json()),
            }
            # The object the provider actually received: exact cell_id
            # -> protected value, no re-derivation from the body string.
            trace.protected_cells = {
                cell.cell_id: cell.value for cell in request.document
            }
            self._set_stage_locked("provider", "running")
            self._revision += 1

    def note_response(self, parsed: ParsedResponse) -> None:
        with self._lock:
            trace = self._current
            if trace is None:
                return
            trace.response = {
                "raw_text": parsed.text,
                "stop_reason": parsed.stop_reason,
            }
            self._set_stage_locked("provider", "done")
            self._set_stage_locked("response", "running")
            self._revision += 1

    def enter_response_phase(self) -> None:
        with self._lock:
            self._phase = "response"

    def note_provider_error(self, name: str) -> None:
        with self._lock:
            trace = self._current
            if trace is not None:
                trace.error = f"provider:{name}"
            self._set_stage_locked("provider", "failed")

    def note_log(
        self, logger: str, level: str, message: str, created: float
    ) -> None:
        with self._lock:
            trace = self._current
            if trace is None:
                return
            trace.audit.append(
                {
                    "at": created,
                    "logger": logger,
                    "level": level,
                    "event": message,
                }
            )
            event = message.split(" ", 1)[0]
            for stage in _STAGE_DONE.get(event, ()):
                self._set_stage_locked(stage, "done")
            failed = _STAGE_FAILED.get(event)
            if failed is not None:
                self._set_stage_locked(failed, "failed")
            elif event == "provider_call":
                self._set_stage_locked("provider", "running")
            elif event == "provider_ok":
                self._set_stage_locked("provider", "done")
                self._set_stage_locked("response", "running")

    @contextmanager
    def capture_logs(self) -> Iterator[None]:
        """Temporarily tap the gateway's sanitised log stream.

        The logger's level is raised to INFO for the duration only when
        it would otherwise drop the events: Python's default root level
        is WARNING, and ``Logger.log`` discards the record *before* any
        handler sees it — so without this the audit panel would be
        silently empty unless the caller happened to call
        ``basicConfig``. ``propagate`` is never touched, and the
        previous level is restored on exit.
        """
        handler = _MemoryLogHandler(self.note_log)
        target = logging.getLogger(_LOG_ROOT)
        previous_level = target.level
        if target.getEffectiveLevel() > logging.INFO:
            target.setLevel(logging.INFO)
        target.addHandler(handler)
        try:
            yield
        finally:
            target.removeHandler(handler)
            target.setLevel(previous_level)

    # -- reads --------------------------------------------------------------

    @property
    def revision(self) -> int:
        with self._lock:
            return self._revision

    def request_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._order)

    def current(self) -> SessionTrace | None:
        with self._lock:
            return self._current

    def trace(self, request_id: str) -> SessionTrace | None:
        with self._lock:
            return self._traces.get(request_id)

    # -- internals ----------------------------------------------------------

    def _set_stage_locked(self, stage: str, status: str) -> None:
        trace = self._current
        if trace is None:
            return
        record = trace.stages.setdefault(
            stage, {"status": "pending", "detail": "", "at": None}
        )
        if record["status"] == status:
            return
        record["status"] = status
        record["at"] = time.time()
        self._revision += 1

    def purge_finished_before(self, cutoff: float) -> int:
        """Drop finished traces older than ``cutoff`` (``--purge-after``).

        "Finished" is the test, NOT "not current": the newest session
        stays ``current`` after it finishes, so excluding it would keep
        one session's raw data alive for as long as the operator submits
        nothing new — exactly what a purge window exists to bound. A
        still-running session (``finished_at is None``) is never dropped.
        """
        with self._lock:
            stale = [
                rid
                for rid, trace in self._traces.items()
                if trace.finished_at is not None
                and trace.finished_at < cutoff
            ]
            for rid in stale:
                del self._traces[rid]
                if rid in self._order:
                    self._order.remove(rid)
            if self._current is not None and self._current.request_id in stale:
                # Keep ``current()`` and ``request_ids()`` consistent: a
                # purged session must not still be served as the head.
                self._current = None
            if stale:
                self._revision += 1
            return len(stale)

    def _evict_locked(self) -> None:
        """Bound in-memory growth (plan §Risks 9)."""
        while len(self._order) > self._max_sessions:
            dropped = self._order.pop(0)
            if dropped == (self._current.request_id if self._current else ""):
                continue
            self._traces.pop(dropped, None)


def _span_record(span: DetectionSpan) -> dict[str, Any]:
    return {
        "entity_type": span.entity_type.value,
        "start": span.start,
        "end": span.end,
        "score": span.score,
        "source": span.source.value,
        "raw": span.raw_value,
        "checksum_valid": span.checksum_valid,
    }


class RecordingVault(SessionTokenVault):
    """``SessionTokenVault`` that reports issued pairs to the recorder.

    SR-019 is NOT weakened: ``clear()`` is inherited in effect and still
    destroys the real mapping. The recorder keeps a SEPARATE in-memory
    copy. No new public API is added to ``vault.py``.
    """

    def __init__(self, recorder: DashboardRecorder) -> None:
        self._recorder = recorder
        super().__init__()

    def token_for(self, entity_type: EntityType, raw: str) -> str:
        token = super().token_for(entity_type, raw)
        self._recorder.note_pair(entity_type, raw, token)
        return token

    def clear(self) -> None:
        # Capture the protected instruction immediately before the
        # session destroys it (SR-022 output).
        self._recorder.note_protected_instruction(self.protected_instruction)
        super().clear()


class RecordingEngine:
    """Duck-typed ``DetectionEngine`` wrapper — the seam the test suite
    already uses (``StubEngine``). Records cells, spans, and text scans.

    Duck-typed rather than subclassed: subclassing ``DetectionEngine``
    would force an eager 575 MB spaCy load (``ner.py:122-124``) or a
    fake ``__init__``. One documented ``cast`` at the factory keeps
    mypy clean.
    """

    def __init__(self, recorder: DashboardRecorder, inner: Any) -> None:
        self._recorder = recorder
        self._inner = inner

    def analyze_cell(self, cell: DocumentCell) -> CellDetection:
        result: CellDetection = self._inner.analyze_cell(cell)
        self._recorder.note_cell(cell, result)
        return result

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]:
        spans: tuple[DetectionSpan, ...] = self._inner.analyze_text(text)
        self._recorder.note_text(text, spans)
        return spans

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def wrap_engine(
    recorder: DashboardRecorder, inner: DetectionEngine
) -> DetectionEngine:
    """Wrap an engine so ``Pipeline`` and ``ResponseGuard`` both use it.

    ``Pipeline.engine`` returns whatever was passed, and ``Session``
    builds its guard from it (``session.py:58``) — so one wrapper
    covers both the cell scan and the response scan.
    """
    return cast(DetectionEngine, RecordingEngine(recorder, inner))


class RecordingProvider:
    """``LLMProvider`` wrapper. Covers BOTH ``--provider fake``
    (``EchoProvider``) and ``anthropic`` — a ``Transport`` wrapper would
    only cover the latter.
    """

    def __init__(self, recorder: DashboardRecorder, inner: LLMProvider) -> None:
        self._recorder = recorder
        self._inner = inner

    def complete(self, request: LLMRequest) -> ParsedResponse:
        body = request.to_body()
        self._recorder.note_request(request, body)
        try:
            parsed = self._inner.complete(request)
        except Exception as exc:
            self._recorder.note_provider_error(type(exc).__name__)
            raise
        self._recorder.note_response(parsed)
        self._recorder.enter_response_phase()
        return parsed


def make_vault_factory(
    recorder: DashboardRecorder,
) -> Callable[[], SessionTokenVault]:
    """A ``vault_factory`` for ``Pipeline`` — one recording vault per
    session, so SR-019's per-session scoping is unchanged.
    """
    return lambda: RecordingVault(recorder)
