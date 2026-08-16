"""Benchmark report writer (BENCHMARK.md §8, normative format).

Determinism note: BENCHMARK.md §7 requires byte-identical report JSON
for the same environment and code. A wall-clock ``generated_at`` field
would violate that, so the report carries a deterministic ``run_id``
(SHA-256 fingerprint of the corpus) instead — recorded in
docs/DECISIONS.md.
"""

from __future__ import annotations

import hashlib
import json
import os

from benchmark.generate import Corpus
from benchmark.scoring import EntityScores
from secure_ai_gateway.models import EntityType

REPORT_JSON_NAME = "benchmark_report.json"
REPORT_MD_NAME = "benchmark_report.md"

# BENCHMARK.md §6 — acceptance thresholds (never changed to make the
# benchmark pass; docs/DESIGN.md §9).
ACCEPTANCE: dict[str, tuple[str, float]] = {
    "aggregate_recall": ("recall", 0.90),
    "aggregate_precision": ("precision", 0.80),
    "PERSON_recall": ("recall", 0.85),
    "PERSON_precision": ("precision", 0.80),
    "ADDRESS_recall": ("recall", 0.85),
    "ADDRESS_precision": ("precision", 0.80),
    "TW_ID_recall": ("recall", 0.85),
    "TW_ID_precision": ("precision", 0.80),
    "EMAIL_recall": ("recall", 0.85),
    "EMAIL_precision": ("precision", 0.80),
    "PHONE_recall": ("recall", 0.85),
    "PHONE_precision": ("precision", 0.80),
    "CUSTOMER_ID_recall": ("recall", 0.85),
    "CUSTOMER_ID_precision": ("precision", 0.80),
    "EMPLOYEE_ID_recall": ("recall", 0.85),
    "EMPLOYEE_ID_precision": ("precision", 0.80),
}


def corpus_fingerprint(corpus: Corpus) -> str:
    """Deterministic run identifier: SHA-256 over the record stream."""
    digest = hashlib.sha256()
    for record in corpus.records:
        digest.update(record.record_id.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(record.cell_text.encode("utf-8"))
        digest.update(b"\x00")
        for span in record.gt_spans:
            digest.update(
                f"{span.start}:{span.end}:{span.entity_type.value}".encode()
            )
    return digest.hexdigest()[:12]


def _entity_row(name: str, scores: EntityScores) -> dict:
    return {
        "tp": scores.tp,
        "fp": scores.fp,
        "fn": scores.fn,
        "precision": round(scores.precision, 4),
        "recall": round(scores.recall, 4),
        "f1": round(scores.f1, 4),
        "ioU_ge_0_5": round(scores.ioU_ge_0_5(), 4),
    }


def build_report(
    corpus: Corpus,
    thresholds: dict[str, float],
    aggregate: EntityScores,
    per_entity: dict[EntityType, EntityScores],
    injection: dict,
) -> dict:
    """Assemble the report dict (BENCHMARK.md §8)."""
    per_entity_out: dict[str, dict] = {}
    for entity in EntityType:
        per_entity_out[entity.value] = _entity_row(
            entity.value, per_entity.get(entity, EntityScores())
        )
    per_entity_out["aggregate"] = _entity_row("aggregate", aggregate)

    details: dict[str, dict] = {}
    passed = True
    for key, (metric, required) in ACCEPTANCE.items():
        if key == "aggregate_recall":
            actual = aggregate.recall
        elif key == "aggregate_precision":
            actual = aggregate.precision
        else:
            entity_name, _ = key.rsplit("_", 1)  # handles CUSTOMER_ID_*
            actual = per_entity_out[entity_name][metric]
        ok = actual >= required
        passed = passed and ok
        details[key] = {
            "actual": round(actual, 4),
            "required": required,
            "passed": ok,
        }

    report = {
        "seed": corpus.seed,
        "run_id": corpus_fingerprint(corpus),
        "corpus": {
            "positive": corpus.positives,
            "negative": corpus.negatives,
            "injection": corpus.injections,
        },
        "calibrated_thresholds": dict(sorted(thresholds.items())),
        "aggregate": _entity_row("aggregate", aggregate),
        "per_entity": per_entity_out,
        "injection": injection,
        "acceptance": {"passed": passed, "details": details},
    }
    return report


def write_report(report: dict, out_dir: str = "bench_reports") -> tuple[str, str]:
    """Write JSON + markdown; returns (json_path, md_path)."""
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, REPORT_JSON_NAME)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    md_path = os.path.join(out_dir, REPORT_MD_NAME)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(_to_markdown(report))
    return json_path, md_path


def _to_markdown(report: dict) -> str:
    lines = [
        "# Detection Benchmark Report",
        "",
        f"- seed: {report['seed']}",
        f"- run_id: {report['run_id']}",
        "- corpus: "
        f"{report['corpus']['positive']} positive, "
        f"{report['corpus']['negative']} negative, "
        f"{report['corpus']['injection']} injection",
        f"- acceptance: {'PASS' if report['acceptance']['passed'] else 'FAIL'}",
        "",
        "## Aggregate",
        "",
        "| tp | fp | fn | precision | recall | f1 |",
        "|---|---|---|---|---|---|",
        "| {} | {} | {} | {:.4f} | {:.4f} | {:.4f} |".format(
            report["aggregate"]["tp"],
            report["aggregate"]["fp"],
            report["aggregate"]["fn"],
            report["aggregate"]["precision"],
            report["aggregate"]["recall"],
            report["aggregate"]["f1"],
        ),
        "",
        "## Per-entity",
        "",
        "| entity | tp | fp | fn | precision | recall | f1 | IoU>=0.5 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for entity, row in sorted(report["per_entity"].items()):
        lines.append(
            "| {} | {} | {} | {} | {:.4f} | {:.4f} | {:.4f} | {:.4f} |".format(
                entity,
                row["tp"],
                row["fp"],
                row["fn"],
                row["precision"],
                row["recall"],
                row["f1"],
                row["ioU_ge_0_5"],
            )
        )
    lines += [
        "",
        "## Acceptance",
        "",
        "| metric | actual | required | passed |",
        "|---|---|---|---|",
    ]
    for key, detail in sorted(report["acceptance"]["details"].items()):
        lines.append(
            "| {} | {:.4f} | {:.4f} | {} |".format(
                key, detail["actual"], detail["required"], detail["passed"]
            )
        )
    lines.append("")
    return "\n".join(lines)
