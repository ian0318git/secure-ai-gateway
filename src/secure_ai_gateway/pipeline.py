"""Session pipeline: parse -> detect -> injection -> policy -> minimise
-> tokenise.

One ``process_file`` call is one gateway session (docs/DESIGN.md §11),
with one session-scoped token vault. Fail-closed: ANY exception
(parser, detection, policy, tokenisation, unexpected) becomes a BLOCK
decision with reason ``error:<ClassName>`` — nothing proceeds
downstream, nothing is logged raw (T-I05).

Critical injection findings get a dedicated path so the reason and
the findings stay in the report: ``injection:critical``.

M2 tokenises TOKENISE cells and protects the instruction channel
(SR-022); no LLM (M3).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from pathlib import Path

from secure_ai_gateway.detection.engine import DetectionEngine
from secure_ai_gateway.errors import GatewayError, InstructionSecretError
from secure_ai_gateway.injection.detector import detect
from secure_ai_gateway.limits import ResourceLimits
from secure_ai_gateway.logging import log_event
from secure_ai_gateway.minimisation import apply_minimisation
from secure_ai_gateway.models import (
    CellDetection,
    DetectionResult,
    Disposition,
    DocumentCell,
    InjectionFinding,
    PolicyDecision,
)
from secure_ai_gateway.parsers import parse_document
from secure_ai_gateway.policy.engine import evaluate
from secure_ai_gateway.policy.templates import resolve_template
from secure_ai_gateway.reporting import MetadataReport, build_report
from secure_ai_gateway.tokenisation.substitution import (
    protect_instruction,
    tokenise_cells,
)
from secure_ai_gateway.tokenisation.vault import SessionTokenVault

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
        *,
        vault_factory: Callable[[], SessionTokenVault] | None = None,
    ) -> None:
        self._engine = engine
        self._limits = limits if limits is not None else ResourceLimits()
        # M6 opt-in: a PersistentSessionVault factory (CLI --vault-store).
        # Keyword-only so every positional call site is unchanged.
        self._vault_factory = vault_factory

    @property
    def engine(self) -> DetectionEngine:
        """The detection engine (M4: response scanning reuses it)."""
        return self._engine

    def process_file(
        self,
        path: str | Path,
        *,
        instruction: str | None = None,
        template_name: str | None = "gross_margin",
        request_id: str | None = None,
    ) -> tuple[PolicyDecision, MetadataReport, tuple[DocumentCell, ...], SessionTokenVault]:
        """Run one session. Returns (decision, report, protected_cells, vault).

        One call = one session = one vault (SR-019). The caller owns the
        vault and releases it at session end; on BLOCK it is empty.
        """
        rid = request_id or uuid.uuid4().hex[:12]
        # Resolved lazily so the M5 token-collision test's monkeypatch
        # of pipeline.SessionTokenVault (test_m5_fail_closed.py) keeps
        # working; the M6 factory path is strictly opt-in (--vault-store).
        vault = (
            self._vault_factory()
            if self._vault_factory is not None
            else SessionTokenVault()
        )
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
                    rid, parsed, detection, decision, vault
                )
            retained, _dropped = apply_minimisation(parsed, decision)
            if instruction is not None:  # SR-022: instruction is protected input
                vault.protected_instruction = protect_instruction(
                    self._engine, instruction, vault
                )
            protected, substituted = tokenise_cells(
                retained, detection, decision, vault
            )
            log_event(
                logger,
                "processed",
                request_id=rid,
                retained=len(protected),
                dropped=len(_dropped),
                substituted=substituted,  # not "tokenised_*": log keys forbid it
            )
            report = build_report(
                rid, parsed, detection, decision, len(protected),
                tokenised_spans=substituted,
            )
            return decision, report, protected, vault
        except _CriticalInjection as exc:
            return self._finish_blocked(
                rid, exc.parsed, exc.detection, exc.decision, vault
            )
        except InstructionSecretError as exc:  # before generic handler
            vault.clear()  # BLOCK: partial session state is destroyed
            decision = PolicyDecision(
                disposition=Disposition.BLOCK,
                reason=f"secret:{exc.entity_type.value}",
            )
            return self._finish_blocked(
                rid, parsed, detection, decision, vault
            )
        except Exception as exc:  # noqa: BLE001 — fail closed on anything
            vault.clear()  # BLOCK: partial session state is destroyed
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
            return decision, report, (), vault

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

        instruction_findings: tuple[InjectionFinding, ...] = ()
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
        vault: SessionTokenVault,
    ) -> tuple[PolicyDecision, MetadataReport, tuple[DocumentCell, ...], SessionTokenVault]:
        log_event(
            logger,
            "blocked",
            request_id=rid,
            reason=decision.reason,
        )
        report = build_report(rid, parsed, detection, decision, 0)
        return decision, report, (), vault


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
