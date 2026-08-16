"""Session pipeline: parse -> detect -> injection -> policy -> minimise.

One ``process_file`` call is one gateway session (docs/DESIGN.md §11).
Fail-closed: ANY exception (parser, detection, policy, unexpected)
becomes a BLOCK decision with reason ``error:<ClassName>`` — nothing
proceeds downstream, nothing is logged raw (T-I05).

Critical injection findings get a dedicated path so the reason and
the findings stay in the report: ``injection:critical``.

M1 stops at minimisation: no tokenisation (M2), no LLM (M3).
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from secure_ai_gateway.detection.engine import DetectionEngine
from secure_ai_gateway.errors import GatewayError
from secure_ai_gateway.injection.detector import detect
from secure_ai_gateway.logging import log_event
from secure_ai_gateway.limits import ResourceLimits
from secure_ai_gateway.minimisation import apply_minimisation
from secure_ai_gateway.models import (
    CellDetection,
    DetectionResult,
    Disposition,
    DocumentCell,
    PolicyDecision,
)
from secure_ai_gateway.parsers import parse_document
from secure_ai_gateway.policy.engine import evaluate
from secure_ai_gateway.policy.templates import resolve_template
from secure_ai_gateway.reporting import MetadataReport, build_report

logger = logging.getLogger("secure_ai_gateway.pipeline")

# Injection semantics (docs/DECISIONS.md):
#   instruction finding              -> BLOCK
#   document cell severity >= 3      -> BLOCK
#   document cell severity < 3       -> DROP cell + flag in report
CRITICAL_INJECTION_SEVERITY = 3


class Pipeline:
    def __init__(
        self,
        engine: DetectionEngine,
        limits: ResourceLimits | None = None,
    ) -> None:
        self._engine = engine
        self._limits = limits if limits is not None else ResourceLimits()

    def process_file(
        self,
        path: str | Path,
        *,
        instruction: str | None = None,
        template_name: str | None = "gross_margin",
        request_id: str | None = None,
    ) -> tuple[PolicyDecision, MetadataReport, tuple[DocumentCell, ...]]:
        """Run one session. Returns (decision, report, retained_cells).

        When the decision is BLOCK, ``retained_cells`` is empty.
        """
        rid = request_id or uuid.uuid4().hex[:12]
        try:
            parsed = parse_document(path, self._limits)
            log_event(
                logger,
                "parsed",
                request_id=rid,
                source=parsed.stats.file_name,
                format=parsed.stats.format,
                encoding=parsed.stats.encoding,
                rows=parsed.stats.row_count,
                cells=parsed.stats.cell_count,
            )
            detection = self._analyze(parsed, instruction)
            decision = evaluate(parsed, detection, resolve_template(template_name))
            if decision.is_blocked():
                return self._finish_blocked(
                    rid, parsed, detection, decision
                )
            retained, _dropped = apply_minimisation(parsed, decision)
            log_event(
                logger,
                "processed",
                request_id=rid,
                retained=len(retained),
                dropped=len(_dropped),
            )
            report = build_report(rid, parsed, detection, decision, len(retained))
            return decision, report, retained
        except _CriticalInjection as exc:
            return self._finish_blocked(
                rid, exc.parsed, exc.detection, exc.decision
            )
        except Exception as exc:  # noqa: BLE001 — fail closed on anything
            reason = f"error:{type(exc).__name__}"
            log_event(
                logger,
                "blocked",
                level=logging.ERROR,
                request_id=rid,
                reason=reason,
            )
            decision = PolicyDecision(
                disposition=Disposition.BLOCK,
                reason=reason,
            )
            report = MetadataReport(
                request_id=rid,
                source_name="",
                file_format="",
                encoding="",
                row_count=0,
                cell_count=0,
                estimated_tokens=0,
                neutralised_formula_cells=0,
                span_counts={},
                injection_findings=(),
                instruction_findings=(),
                decision=decision,
                retained_cells=0,
                dropped_cells=0,
            )
            return decision, report, ()

    # -- internals ----------------------------------------------------------

    def _analyze(self, parsed, instruction: str | None) -> DetectionResult:
        cells: list[CellDetection] = []
        for cell in parsed.cells:
            cell_detection = self._engine.analyze_cell(cell)
            findings = detect(cell.value, cell.cell_id)
            if any(
                f.severity >= CRITICAL_INJECTION_SEVERITY for f in findings
            ):
                cells.append(
                    CellDetection(
                        cell_id=cell.cell_id,
                        spans=cell_detection.spans,
                        injection_findings=findings,
                    )
                )
                raise _CriticalInjection(
                    parsed=parsed,
                    detection=DetectionResult(
                        cells=tuple(cells),
                        instruction_findings=(),
                    ),
                    decision=PolicyDecision(
                        disposition=Disposition.BLOCK,
                        reason="injection:critical",
                        blocked_cell_ids=(cell.cell_id,),
                    ),
                )
            cells.append(
                CellDetection(
                    cell_id=cell.cell_id,
                    spans=cell_detection.spans,
                    injection_findings=findings,
                )
            )

        instruction_findings = ()
        if instruction:
            instruction_findings = detect(instruction, "instruction")
            if instruction_findings:
                raise _CriticalInjection(
                    parsed=parsed,
                    detection=DetectionResult(
                        cells=tuple(cells),
                        instruction_findings=instruction_findings,
                    ),
                    decision=PolicyDecision(
                        disposition=Disposition.BLOCK,
                        reason="injection:instruction",
                        blocked_cell_ids=("instruction",),
                    ),
                )
        return DetectionResult(
            cells=tuple(cells),
            instruction_findings=instruction_findings,
        )

    def _finish_blocked(
        self,
        rid: str,
        parsed,
        detection: DetectionResult,
        decision: PolicyDecision,
    ) -> tuple[PolicyDecision, MetadataReport, tuple[DocumentCell, ...]]:
        log_event(
            logger,
            "blocked",
            request_id=rid,
            reason=decision.reason,
        )
        report = build_report(rid, parsed, detection, decision, 0)
        return decision, report, ()


class _CriticalInjection(GatewayError):
    """Carries the partial detection state for the blocked report."""

    def __init__(
        self,
        parsed,
        detection: DetectionResult,
        decision: PolicyDecision,
    ) -> None:
        self.parsed = parsed
        self.detection = detection
        self.decision = decision
        super().__init__("critical injection detected")
