"""Static policy engine — default DENY (DESIGN §14, SR-024).

Layered evaluation, any layer failing closes the request:

1. Template layer: no template / unknown template -> BLOCK.
2. Secret layer: a span of a BLOCK entity type, or a column whose
   header is a secret name -> BLOCK the whole request
   (allowlists can never override secrets).
3. Disposition layer (per cell, only after 1+2 pass):
   - PII / identifier span present -> TOKENISE (executed in M2)
   - column not in the template allowlist -> DROP
   - otherwise -> ALLOW

Table-out entity types -> BLOCK (default deny for unknown types).
"""

from __future__ import annotations

import re

from secure_ai_gateway.models import (
    CellDecision,
    DetectionResult,
    Disposition,
    EntityType,
    ParsedDocument,
    PolicyDecision,
)
from secure_ai_gateway.policy.templates import TaskTemplate

# DESIGN §14: secrets block the request.
_BLOCK_TYPES = frozenset(
    {
        EntityType.SECRET,
        EntityType.API_KEY,
        EntityType.PASSWORD,
        EntityType.JWT,
        EntityType.PRIVATE_KEY,
    }
)
# Everything else we emit is identity PII -> tokenise.
_TOKENISE_TYPES = frozenset(EntityType) - _BLOCK_TYPES

# Secret column names: allowlists can never allow these columns.
_SECRET_COLUMN_RE = re.compile(
    r"(password|passwd|pwd|api[_-]?key|apisecret|secret|"
    r"credential|金鑰|密鑰|密碼|憑證)",
    re.IGNORECASE,
)


def _is_secret_column(label: str) -> bool:
    return bool(_SECRET_COLUMN_RE.search(label))


def _column_allowed(column: str, allowed_columns: tuple[str, ...]) -> bool:
    lowered = column.lower()
    return any(keyword.lower() in lowered for keyword in allowed_columns)


def evaluate(
    parsed: ParsedDocument,
    detection: DetectionResult,
    template: TaskTemplate | None,
) -> PolicyDecision:
    """Evaluate the request. Any failure yields BLOCK."""
    if template is None:
        return PolicyDecision(
            disposition=Disposition.BLOCK,
            reason="error:no_template",
        )

    allowed = template.allowed_columns
    blocked_cells: list[str] = []
    dropped_cells: list[str] = []
    cell_decisions: list[CellDecision] = []

    for cell in parsed.cells:
        if _is_secret_column(cell.column):
            blocked_cells.append(cell.cell_id)
            cell_decisions.append(
                CellDecision(cell.cell_id, Disposition.BLOCK, "secret_column")
            )
            continue
        # Non-critical injection findings: the cell is dropped (never
        # reaches the LLM); critical findings already blocked earlier
        # in the pipeline (docs/DECISIONS.md).
        if detection.findings_for(cell.cell_id):
            dropped_cells.append(cell.cell_id)
            cell_decisions.append(
                CellDecision(cell.cell_id, Disposition.DROP, "injection")
            )
            continue
        spans = detection.spans_for(cell.cell_id)
        block_types = {
            span.entity_type for span in spans if span.entity_type in _BLOCK_TYPES
        }
        unknown_types = {
            span.entity_type
            for span in spans
            if span.entity_type not in _BLOCK_TYPES
            and span.entity_type not in _TOKENISE_TYPES
        }
        if unknown_types:
            blocked_cells.append(cell.cell_id)
            cell_decisions.append(
                CellDecision(
                    cell.cell_id,
                    Disposition.BLOCK,
                    f"unknown_type:{min(t.value for t in unknown_types)}",
                )
            )
            continue
        if block_types:
            blocked_cells.append(cell.cell_id)
            cell_decisions.append(
                CellDecision(
                    cell.cell_id,
                    Disposition.BLOCK,
                    f"secret:{min(t.value for t in block_types)}",
                )
            )
            continue
        if spans:
            cell_decisions.append(
                CellDecision(cell.cell_id, Disposition.TOKENISE, "pii")
            )
            continue
        if not _column_allowed(cell.column, allowed):
            dropped_cells.append(cell.cell_id)
            cell_decisions.append(
                CellDecision(cell.cell_id, Disposition.DROP, "column_not_allowed")
            )
            continue
        cell_decisions.append(
            CellDecision(cell.cell_id, Disposition.ALLOW, "allowed")
        )

    if blocked_cells:
        reason = next(
            d.reason for d in cell_decisions if d.disposition is Disposition.BLOCK
        )
        return PolicyDecision(
            disposition=Disposition.BLOCK,
            reason=reason,
            blocked_cell_ids=tuple(sorted(blocked_cells)),
            dropped_cell_ids=tuple(sorted(dropped_cells)),
            cell_decisions=tuple(cell_decisions),
        )
    return PolicyDecision(
        disposition=Disposition.ALLOW,
        reason="policy_ok",
        dropped_cell_ids=tuple(sorted(dropped_cells)),
        cell_decisions=tuple(cell_decisions),
    )
