"""End-to-end benchmark run (BENCHMARK.md §5, normative protocol).

Flow:
1. generate corpus (seed 42) and split 80/20 by record_id hash;
2. run the NLP model ONCE over all train+test cells via
   ``analyze_cell_raw`` (pre-threshold spans, BENCHMARK.md §5.2) —
   calibration is a pure filter over the cached raw spans;
3. calibrate per-entity thresholds on the TRAIN split only (grid
   0.40–0.90 step 0.05, maximise F1; tie-break recall > precision >
   lower threshold; floor 0.40);
4. final metrics from the held-out TEST split with the calibrated
   thresholds;
5. score the injection strings and the clean control set separately
   (BENCHMARK.md §5.4);
6. write bench_reports/benchmark_report.json + .md (§8).

The report is deterministic: same environment + same code produces a
byte-identical JSON (BENCHMARK.md §7).
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict

from benchmark.generate import BENCHMARK_SEED, Corpus, Record, generate
from benchmark.report import build_report, write_report
from benchmark.scoring import EntityScores, score_cell
from benchmark.split import split
from secure_ai_gateway.detection.engine import DetectionEngine
from secure_ai_gateway.injection.detector import detect
from secure_ai_gateway.models import DocumentCell, EntityType

THRESHOLD_GRID = tuple(round(0.40 + 0.05 * i, 2) for i in range(11))
DEFAULT_THRESHOLD = 0.5


def _cell(record: Record) -> DocumentCell:
    return DocumentCell(
        cell_id=record.record_id, column="", value=record.cell_text, row=0
    )


def _analyze_all(
    engine: DetectionEngine, records: tuple[Record, ...]
) -> dict[str, tuple]:
    """One NLP pass over every record; returns record_id -> raw spans."""
    raw: dict[str, tuple] = {}
    for record in records:
        detection = engine.analyze_cell_raw(_cell(record))
        raw[record.record_id] = detection.spans
    return raw


def _filter_by_type(
    spans, entity_type: EntityType, threshold: float
) -> tuple:
    return tuple(
        s for s in spans if s.entity_type is entity_type and s.score >= threshold
    )


def calibrate(
    train: tuple[Record, ...], raw: dict[str, tuple]
) -> dict[EntityType, float]:
    """Grid-search per-entity thresholds on the train split (§5.2).

    Matching is per-type independent (same-type pairs only), so each
    entity's grid search scores only its own spans against its own
    ground truth.
    """
    present: set[EntityType] = set()
    for record in train:
        present.update(span.entity_type for span in record.gt_spans)

    thresholds: dict[EntityType, float] = {}
    for entity in sorted(present, key=lambda e: e.value):
        best: tuple[float, float, float, float] | None = None  # (f1, r, p, -t)
        for t in THRESHOLD_GRID:
            scores = EntityScores()
            for record in train:
                # Matching is per-type independent, so each entity's
                # grid search scores only its own spans vs its own GT.
                gt_entity = tuple(
                    g for g in record.gt_spans if g.entity_type is entity
                )
                preds = _filter_by_type(raw[record.record_id], entity, t)
                if not gt_entity and not preds:
                    continue
                score_cell(gt_entity, preds, {entity: scores})
            candidate = (scores.f1, scores.recall, scores.precision, -t)
            if best is None or candidate > best:
                best = candidate
        thresholds[entity] = -best[3]
    return thresholds


def evaluate(
    records: tuple[Record, ...],
    raw: dict[str, tuple],
    thresholds: dict[EntityType, float],
) -> tuple[EntityScores, dict[EntityType, EntityScores]]:
    """Final metrics: test split, calibrated thresholds (§5.3)."""
    aggregate = EntityScores()
    per_entity: dict[EntityType, EntityScores] = defaultdict(EntityScores)
    for record in records:
        preds = tuple(
            s
            for s in raw[record.record_id]
            if s.score >= thresholds.get(s.entity_type, DEFAULT_THRESHOLD)
        )
        if not record.gt_spans and not preds:
            continue
        scores: dict[EntityType, EntityScores] = defaultdict(EntityScores)
        score_cell(record.gt_spans, preds, scores)
        for entity, entity_scores in scores.items():
            per_entity[entity].merge(entity_scores)
            aggregate.merge(entity_scores)
    return aggregate, per_entity


def score_injections(corpus: Corpus) -> dict:
    """BENCHMARK.md §5.4: injection strings + clean control."""
    injections = [r for r in corpus.records if r.kind == "INJECTION"]
    clean = [r for r in corpus.records if r.kind == "CLEAN"]
    hits = 0
    misses: list[tuple[str, str, str]] = []
    for record in injections:
        findings = detect(record.cell_text, location=f"bench:{record.record_id}")
        matched = any(
            f.category is record.injection.category
            and f.severity == record.injection.severity
            for f in findings
        )
        if matched:
            hits += 1
        else:
            misses.append(
                (
                    record.record_id,
                    record.injection.category.value,
                    str(record.injection.severity),
                )
            )
    clean_findings = [
        r.record_id
        for r in clean
        if detect(r.cell_text, location=f"bench:{r.record_id}")
    ]
    return {
        "expected": len(injections),
        "hits": hits,
        "missed": misses,
        "clean_control": len(clean),
        "clean_findings": clean_findings,
    }


def run(seed: int = BENCHMARK_SEED, out_dir: str = "bench_reports") -> dict:
    """Run the full benchmark and write the report."""
    corpus = generate(seed)
    train, test = split(corpus)
    print(
        f"corpus: {corpus.positives} positive, {corpus.negatives} negative, "
        f"{corpus.injections} injection; "
        f"train={len(train)} test={len(test)}",
        file=sys.stderr,
    )

    engine = DetectionEngine()
    raw_train = _analyze_all(engine, train)
    raw_test = _analyze_all(engine, test)
    del engine  # release the ~575MB model before report writing

    thresholds = calibrate(train, raw_train)
    aggregate, per_entity = evaluate(test, raw_test, thresholds)
    injection = score_injections(corpus)

    thresholds_out: dict[str, float] = {
        e.value: thresholds.get(e, DEFAULT_THRESHOLD) for e in EntityType
    }
    report = build_report(corpus, thresholds_out, aggregate, per_entity, injection)
    json_path, md_path = write_report(report, out_dir)
    print(f"report: {json_path}", file=sys.stderr)
    print(f"acceptance: {'PASS' if report['acceptance']['passed'] else 'FAIL'}",
          file=sys.stderr)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the M1 detection benchmark (docs/BENCHMARK.md)."
    )
    parser.add_argument("--seed", type=int, default=BENCHMARK_SEED)
    parser.add_argument("--out-dir", default="bench_reports")
    args = parser.parse_args()
    run(seed=args.seed, out_dir=args.out_dir)


if __name__ == "__main__":
    main()
