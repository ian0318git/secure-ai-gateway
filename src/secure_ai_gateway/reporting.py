"""Metadata reporting: JSON/markdown WITHOUT raw content (T-I05 / SR-009).

Every field in the report is metadata: counts, types, categories.
No cell values, no spans' raw text, no token values, no paths beyond
the file basename. A unit test asserts the report JSON contains no
raw values.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from secure_ai_gateway.models import (
    CellDetection,
    DetectionResult,
    Disposition,
    EntityType,
    InjectionFinding,
    ParsedDocument,
    PolicyDecision,
)


@dataclass(frozen=True, slots=True)
class MetadataReport:
    """All report fields are metadata — never raw content."""

    request_id: str
    source_name: str  # basename only
    file_format: str
    encoding: str
    row_count: int
    cell_count: int
    estimated_tokens: int
    neutralised_formula_cells: int
    span_counts: dict[str, int]  # EntityType.value -> count
    injection_findings: tuple[InjectionFinding, ...]
    instruction_findings: tuple[InjectionFinding, ...]
    decision: PolicyDecision
    retained_cells: int
    dropped_cells: int
    tokenised_spans: int = 0  # M2: document spans substituted only

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "source": self.source_name,
            "format": self.file_format,
            "encoding": self.encoding,
            "rows": self.row_count,
            "cells": self.cell_count,
            "estimated_tokens": self.estimated_tokens,
            "neutralised_formula_cells": self.neutralised_formula_cells,
            "span_counts": dict(sorted(self.span_counts.items())),
            "injection_findings": [
                f.log_view() for f in self.injection_findings
            ],
            "instruction_findings": [
                f.log_view() for f in self.instruction_findings
            ],
            "decision": self.decision.log_view(),
            "decision_details": {
                "disposition": self.decision.disposition.value,
                "reason": self.decision.reason,
                "blocked_cells": len(self.decision.blocked_cell_ids),
                "dropped_cells": len(self.decision.dropped_cell_ids),
            },
            "retained_cells": self.retained_cells,
            "dropped_cell_count": self.dropped_cells,
            "tokenised_spans": self.tokenised_spans,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def to_markdown(self) -> str:
        decision = self.decision
        lines = [
            f"# Detection Report — {self.request_id}",
            "",
            f"- Source: `{self.source_name}` ({self.file_format}, "
            f"{self.encoding})",
            f"- Rows: {self.row_count}, Cells: {self.cell_count}, "
            f"Est. tokens: {self.estimated_tokens}",
            f"- Formula cells blocked: {self.neutralised_formula_cells}",
            "",
            "## Spans by entity type",
            "",
            "| Type | Count |",
            "|---|---|",
        ]
        for entity, count in sorted(self.span_counts.items()):
            lines.append(f"| {entity} | {count} |")
        lines += [
            "",
            f"## Policy decision: **{decision.disposition.value}** "
            f"(`{decision.reason}`)",
            "",
            f"- Blocked cells: {len(decision.blocked_cell_ids)}",
            f"- Dropped cells: {len(decision.dropped_cell_ids)}",
            f"- Retained cells: {self.retained_cells}",
            f"- Tokenised spans: {self.tokenised_spans}",
        ]
        if self.injection_findings:
            lines += ["", "## Document injection findings"]
            lines += [f"- {f.log_view()}" for f in self.injection_findings]
        if self.instruction_findings:
            lines += ["", "## Instruction injection findings"]
            lines += [f"- {f.log_view()}" for f in self.instruction_findings]
        return "\n".join(lines) + "\n"


def build_report(
    request_id: str,
    parsed: ParsedDocument,
    detection: DetectionResult,
    decision: PolicyDecision,
    retained_cells: int,
    tokenised_spans: int = 0,
) -> MetadataReport:
    """Assemble a report; counts spans per type (no raw content)."""
    span_counts: dict[str, int] = {}
    for cell in detection.cells:
        for span in cell.spans:
            span_counts[span.entity_type.value] = (
                span_counts.get(span.entity_type.value, 0) + 1
            )
    return MetadataReport(
        request_id=request_id,
        source_name=parsed.stats.file_name,
        file_format=parsed.stats.format,
        encoding=parsed.stats.encoding,
        row_count=parsed.stats.row_count,
        cell_count=parsed.stats.cell_count,
        estimated_tokens=parsed.stats.estimated_tokens,
        neutralised_formula_cells=parsed.stats.neutralised_formula_cells,
        span_counts=span_counts,
        injection_findings=tuple(
            f
            for cell in detection.cells
            for f in cell.injection_findings
        ),
        instruction_findings=detection.instruction_findings,
        decision=decision,
        retained_cells=retained_cells,
        dropped_cells=len(decision.dropped_cell_ids),
        tokenised_spans=tokenised_spans,
    )
