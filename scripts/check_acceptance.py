#!/usr/bin/env python3
"""Verify M1 acceptance thresholds (BENCHMARK.md §6, normative).

Reads bench_reports/benchmark_report.json and re-computes every
acceptance check independently from the raw tp/fp/fn numbers (it does
NOT trust the report's own "acceptance" field). Any violation exits
non-zero — the acceptance thresholds are never lowered to make the
benchmark pass (docs/DESIGN.md §9).

Usage: python scripts/check_acceptance.py [report.json]
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from benchmark.report import ACCEPTANCE  # noqa: E402

DEFAULT_REPORT = os.path.join("bench_reports", "benchmark_report.json")


def _precision(row: dict) -> float:
    denom = row["tp"] + row["fp"]
    return row["tp"] / denom if denom else 0.0


def _recall(row: dict) -> float:
    denom = row["tp"] + row["fn"]
    return row["tp"] / denom if denom else 0.0


def check(report: dict) -> bool:
    aggregate = report["aggregate"]
    per_entity = report["per_entity"]
    passed = True
    print(f"{'metric':<24}{'actual':>8}{'required':>10}  result")
    for key, (metric, required) in sorted(ACCEPTANCE.items()):
        if key.startswith("aggregate_"):
            actual = _recall(aggregate) if metric == "recall" else _precision(
                aggregate
            )
        else:
            entity_name, _ = key.rsplit("_", 1)
            row = per_entity[entity_name]
            actual = _recall(row) if metric == "recall" else _precision(row)
        ok = actual >= required
        passed = passed and ok
        print(
            f"{key:<24}{actual:>8.4f}{required:>10.4f}  "
            f"{'PASS' if ok else 'FAIL'}"
        )
    return passed


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_REPORT
    if not os.path.exists(path):
        print(f"report not found: {path}", file=sys.stderr)
        print("run: python -m benchmark.run", file=sys.stderr)
        return 2
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    passed = check(report)
    print(f"\nacceptance: {'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
