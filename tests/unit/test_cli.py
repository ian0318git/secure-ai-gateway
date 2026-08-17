"""Unit tests for the M3 interactive CLI.

The real DetectionEngine (spaCy zh model, ~575MB) is never loaded:
cli.DetectionEngine is monkeypatched with a stub factory.
"""

from __future__ import annotations

import pytest

from secure_ai_gateway import cli
from secure_ai_gateway.llm.request_builder import build_request
from secure_ai_gateway.models import (
    CellDetection,
    DetectionSpan,
    DocumentCell,
    EntityType,
    SpanSource,
)
from secure_ai_gateway.policy.templates import resolve_template


class StubEngine:
    """Duck-typed DetectionEngine; no NLP model loaded."""

    def __init__(
        self,
        spans_by_cell: dict[str, tuple[DetectionSpan, ...]],
    ):
        self._spans = spans_by_cell

    def analyze_cell(self, cell):
        return CellDetection(
            cell_id=cell.cell_id,
            spans=self._spans.get(cell.cell_id, ()),
        )

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]:
        return ()


def _span(entity: EntityType, start: int, end: int, raw: str) -> DetectionSpan:
    return DetectionSpan(entity, start, end, 0.9, SpanSource.PATTERN, raw)


def _stub_detection(monkeypatch, spans_by_cell) -> None:
    engine = StubEngine(spans_by_cell)
    monkeypatch.setattr(cli, "DetectionEngine", lambda: engine)


@pytest.fixture
def pii_csv(tmp_path):
    f = tmp_path / "pii.csv"
    f.write_bytes("客戶,營業收入\n王小明,8.4M\n".encode("utf-8"))
    return f


class TestParser:
    def test_defaults(self) -> None:
        args = cli.build_parser().parse_args(["--file", "x.csv"])
        assert args.template == "gross_margin"
        assert args.provider == "anthropic"
        assert args.instruction is None

    def test_provider_choices(self) -> None:
        parser = cli.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--file", "x.csv", "--provider", "gpt"])


class TestEchoProvider:
    def test_returns_prose_with_token_references(self) -> None:
        # The fake provider answers in prose, referencing protected
        # values through their tokens — echoing the protected JSON back
        # would send the real NER haywire (quotes/column names merge
        # with entities) and always trip the M4 guard.
        cells = (DocumentCell("r1_c0", "客戶", "PERSON_a1b2c3d4", 1),)
        req = build_request(
            protected_cells=cells,
            protected_instruction="請分析",
            template=resolve_template("gross_margin"),
        )
        parsed = cli.EchoProvider().complete(req)
        assert (
            parsed.text
            == "關於「請分析」的初步分析：\n"
            "客戶 的數值為 PERSON_a1b2c3d4，已納入分析。"
        )
        assert "<<<" not in parsed.text  # no prompt framing in the reply


class TestMain:
    def test_fake_provider_demo(self, monkeypatch, pii_csv, capsys) -> None:
        _stub_detection(
            monkeypatch, {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        code = cli.main(
            [
                "--file",
                str(pii_csv),
                "--instruction",
                "請分析",
                "--provider",
                "fake",
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "offline demo" in out
        assert "DELIVERED" in out
        assert "PERSON_" not in out  # tokens restored, not echoed
        assert "王小明" in out  # authorised restoration, M4 scan+restore
        assert "請分析" in out  # clean instruction passes through
        assert "not scanned" not in out  # M4 note removed

    def test_blocked_input_exit_1(self, monkeypatch, tmp_path, capsys) -> None:
        f = tmp_path / "s.csv"
        f.write_bytes("客戶,收入\nsk-live-abc,8.4M\n".encode("utf-8"))
        _stub_detection(
            monkeypatch,
            {"r1_c0": (_span(EntityType.API_KEY, 0, 11, "sk-live-abc"),)},
        )
        code = cli.main(["--file", str(f), "--provider", "fake"])
        out = capsys.readouterr().out
        assert code == 1
        assert "secret:API_KEY" in out
        assert "sk-live-abc" not in out

    def test_missing_api_key_exit_2(self, monkeypatch, pii_csv, capsys) -> None:
        _stub_detection(
            monkeypatch, {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        code = cli.main(["--file", str(pii_csv), "--provider", "anthropic"])
        err = capsys.readouterr().err
        assert code == 2
        assert "ANTHROPIC_API_KEY" in err
        assert "--provider fake" in err
