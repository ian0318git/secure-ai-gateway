"""M5 security suite — benchmark evidence re-check (SR-015).

The COMMITTED benchmark report (bench_reports/benchmark_report.json)
is re-verified against the normative acceptance thresholds:
``scripts/check_acceptance.py::check`` re-derives every metric from
the raw tp/fp/fn numbers and does NOT trust the report's own
"acceptance" verdict. A failing check here fails the suite.

The thresholds come from ``benchmark.report.ACCEPTANCE`` — the
documented floors (BENCHMARK.md §6): aggregate Recall >= 0.90 /
Precision >= 0.80; per-entity (PERSON / ADDRESS / TW_ID / EMAIL /
PHONE / CUSTOMER_ID / EMPLOYEE_ID) Recall >= 0.85 / Precision >= 0.80.
They are pinned in this file so they can never be lowered to make a
report pass (CLAUDE.md §6.12).

The injection-control evidence in the report is pinned too: 200/200
attack-phrase hits, zero findings on the clean control.

The checker is loaded with importlib (import-only chain into
benchmark.report — no NLP model is loaded; pytest never loads spaCy).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CHECK_SCRIPT = _REPO_ROOT / "scripts" / "check_acceptance.py"
_REPORT_PATH = _REPO_ROOT / "bench_reports" / "benchmark_report.json"


def _load_checker():
    """Import scripts/check_acceptance.py in isolation (import-only)."""
    spec = importlib.util.spec_from_file_location(
        "m5_check_acceptance", _CHECK_SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def checker():
    return _load_checker()


@pytest.fixture(scope="module")
def report():
    return json.loads(_REPORT_PATH.read_text(encoding="utf-8"))


class TestBenchmarkEvidence:
    def test_committed_report_passes_normative_check(
        self, checker, report
    ) -> None:
        # check() re-derives recall/precision from raw tp/fp/fn; the
        # report's own acceptance verdict is not trusted.
        assert checker.check(report) is True

    def test_aggregate_thresholds_are_the_documented_floors(
        self, checker
    ) -> None:
        accept = checker.ACCEPTANCE
        assert accept["aggregate_recall"] == ("recall", 0.90)
        assert accept["aggregate_precision"] == ("precision", 0.80)

    def test_per_entity_thresholds_are_the_documented_floors(
        self, checker
    ) -> None:
        accept = checker.ACCEPTANCE
        for entity in (
            "PERSON",
            "ADDRESS",
            "TW_ID",
            "EMAIL",
            "PHONE",
            "CUSTOMER_ID",
            "EMPLOYEE_ID",
        ):
            assert accept[f"{entity}_recall"] == ("recall", 0.85)
            assert accept[f"{entity}_precision"] == ("precision", 0.80)

    def test_per_entity_rows_in_report_are_complete(self, checker, report) -> None:
        # Every thresholded entity has a row with raw tp/fp/fn numbers,
        # so check()'s re-derivation is meaningful for all of them.
        per_entity = report["per_entity"]
        for entity in ("PERSON", "ADDRESS", "TW_ID", "EMAIL", "PHONE",
                       "CUSTOMER_ID", "EMPLOYEE_ID"):
            row = per_entity[entity]
            for key in ("tp", "fp", "fn"):
                assert row[key] >= 0

    def test_injection_control_evidence(self, report) -> None:
        # The injection detector's benchmark evidence (M1 acceptance):
        # 200/200 attack phrases detected, zero findings on the clean
        # control (clean-control FP = 0).
        injection = report["injection"]
        assert injection["expected"] == 200
        assert injection["hits"] == 200
        assert injection["missed"] == []
        assert injection["clean_control"] > 0
        assert injection["clean_findings"] == []
