"""Fixtures for the dashboard test suite.

Everything here uses a **stub engine** — the 575 MB spaCy Chinese model
is never loaded, following the pattern in tests/unit/test_detection.py.
The real ``Session.run`` orchestration IS exercised: the dashboard's
whole premise is that it observes the real path, so a test that stubbed
the session would prove nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from secure_ai_gateway.llm.request_builder import LLMRequest
from secure_ai_gateway.llm.response_parser import ParsedResponse
from secure_ai_gateway.models import (
    CellDetection,
    DetectionSpan,
    EntityType,
    SpanSource,
)
from secure_ai_gateway.pipeline import Pipeline
from secure_ai_gateway.session import Session, SessionResult
from secure_ai_gateway.tokenisation.vault import SessionTokenVault
from tools.dashboard.model import to_payload
from tools.dashboard.recorder import (
    DashboardRecorder,
    RecordingProvider,
    RecordingVault,
    wrap_engine,
)

TOKEN_RE = re.compile(r"[A-Z][A-Z0-9]*_[0-9a-f]{8}")

REQUEST_ID = "testrun01"

#: The two raw values the default fixture protects. Every isolation
#: assertion below keys off these.
RAW_PERSON_1 = "Aurora Motors AU"
RAW_PERSON_2 = "王小明"
FIXTURE_RAWS = (RAW_PERSON_1, RAW_PERSON_2)

CSV_BYTES = (
    "客戶,營業收入,成本,毛利率\n"
    f"{RAW_PERSON_1},8.4M,5.7M,32%\n"
    f"{RAW_PERSON_2},12.1M,8.0M,34%\n"
).encode()


class StubEngine:
    """Duck-typed DetectionEngine; no NLP model is loaded.

    Records both call sequences so a test can prove the recorder saw
    the instruction scan and the (deliberately ignored) response scan.
    """

    def __init__(
        self,
        spans_by_cell: dict[str, tuple[DetectionSpan, ...]] | None = None,
        instruction_spans: tuple[DetectionSpan, ...] = (),
        response_spans: tuple[DetectionSpan, ...] = (),
    ) -> None:
        self.spans_by_cell = spans_by_cell or {}
        self.instruction_spans = instruction_spans
        self.response_spans = response_spans
        self.cell_calls: list[str] = []
        self.text_calls: list[str] = []

    def analyze_cell(self, cell) -> CellDetection:
        self.cell_calls.append(cell.cell_id)
        return CellDetection(
            cell_id=cell.cell_id,
            spans=self.spans_by_cell.get(cell.cell_id, ()),
        )

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]:
        """``analyze_text`` is called TWICE per session — once on the
        instruction, once by the response guard. Returning
        ``instruction_spans`` to both calls would make every run look
        like a response leak, so the two scans are answered separately.
        """
        self.text_calls.append(text)
        if len(self.text_calls) == 1:
            return self.instruction_spans
        return self.response_spans


def span(
    entity: EntityType, start: int, end: int, raw: str
) -> DetectionSpan:
    return DetectionSpan(entity, start, end, 0.9, SpanSource.PATTERN, raw)


class EchoLikeProvider:
    """Answers by naming each protected cell through its token.

    Mirrors ``EchoProvider`` so the real M4 scan + restore path runs
    rather than being short-circuited by a canned string.
    """

    def __init__(self) -> None:
        self.requests: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> ParsedResponse:
        self.requests.append(request)
        cells = sorted(request.document, key=lambda c: (c.row, c.cell_id))
        text = "；".join(f"{c.column}={c.value}" for c in cells)
        return ParsedResponse(text=text or "no cells", stop_reason="end_turn")


class BoomProvider:
    """Fails closed after the request is built."""

    def complete(self, request: LLMRequest) -> ParsedResponse:
        raise RuntimeError("provider exploded")


@dataclass
class SessionRun:
    """One completed session, plus the objects that produced it.

    ``harness`` is kept so a test can reach the inner provider — the
    one the request ACTUALLY arrived at — rather than re-deriving what
    the wire body must have been.
    """

    result: SessionResult
    payload: dict
    vault: SessionTokenVault
    harness: Harness


class Harness:
    """Wires the four recording seams around a real ``Session``."""

    def __init__(
        self,
        *,
        spans_by_cell: dict[str, tuple[DetectionSpan, ...]] | None = None,
        instruction_spans: tuple[DetectionSpan, ...] = (),
        provider=None,
        max_sessions: int = 20,
    ) -> None:
        self.recorder = DashboardRecorder(max_sessions=max_sessions)
        self.engine = StubEngine(spans_by_cell, instruction_spans)
        self.provider = (
            EchoLikeProvider() if provider is None else provider
        )
        self.vaults: list[SessionTokenVault] = []
        self.pipeline = Pipeline(
            wrap_engine(self.recorder, self.engine),
            vault_factory=self._make_vault,
        )
        self.session = Session(
            self.pipeline, RecordingProvider(self.recorder, self.provider)
        )

    def _make_vault(self) -> SessionTokenVault:
        vault = RecordingVault(self.recorder)
        self.vaults.append(vault)
        return vault

    def run(
        self,
        path: Path,
        *,
        instruction: str | None = None,
        template_name: str = "gross_margin",
        request_id: str = REQUEST_ID,
    ) -> SessionRun:
        self.recorder.begin_session(request_id, instruction)
        with self.recorder.capture_logs():
            result = self.session.run(
                path,
                instruction=instruction,
                template_name=template_name,
                request_id=request_id,
            )
        self.recorder.finish(result)
        trace = self.recorder.trace(request_id)
        assert trace is not None, "recorder lost the session it just ran"
        return SessionRun(result, to_payload(trace), self.vaults[-1], self)


@pytest.fixture
def doc(tmp_path: Path) -> Path:
    """Synthetic financial CSV with two detectable person values."""
    path = tmp_path / "report.csv"
    path.write_bytes(CSV_BYTES)
    return path


@pytest.fixture
def person_spans() -> dict[str, tuple[DetectionSpan, ...]]:
    return {
        "r1_c0": (span(EntityType.PERSON, 0, len(RAW_PERSON_1), RAW_PERSON_1),),
        "r2_c0": (span(EntityType.PERSON, 0, len(RAW_PERSON_2), RAW_PERSON_2),),
    }


@pytest.fixture
def harness(person_spans) -> Harness:
    return Harness(spans_by_cell=person_spans)


@pytest.fixture
def finished(harness: Harness, doc: Path) -> SessionRun:
    return harness.run(doc)


def keys_of(node) -> list[str]:
    """Every dict key anywhere in ``node`` — used to assert a *field*
    is absent, which prose mentioning the same word cannot break."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            found.append(key)
            found.extend(keys_of(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(keys_of(item))
    return found


def walk_paths(node, path: str = "") -> list[tuple[str, object]]:
    """Every (json-path, value) pair in a payload, in the same
    ``cells[].value`` notation ``RAW_OR_TOKEN_PATHS`` uses."""
    found: list[tuple[str, object]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else key
            found.extend(walk_paths(value, child))
    elif isinstance(node, list):
        for item in node:
            found.extend(walk_paths(item, f"{path}[]"))
    else:
        found.append((path, node))
    return found
