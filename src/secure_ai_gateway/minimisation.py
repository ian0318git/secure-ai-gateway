"""Data minimisation (DESIGN §12): keep only policy-approved cells.

M1 implementation: the policy engine already computes a per-cell
disposition; this stage filters the parsed document down to the cells
that may continue downstream (ALLOW / TOKENISE). DROPPED cells never
reach the LLM (M3) and never appear in the retained output.
"""

from __future__ import annotations

from secure_ai_gateway.models import (
    Disposition,
    DocumentCell,
    ParsedDocument,
    PolicyDecision,
)


def apply_minimisation(
    parsed: ParsedDocument,
    decision: PolicyDecision,
) -> tuple[tuple[DocumentCell, ...], tuple[str, ...]]:
    """Return ``(retained_cells, dropped_cell_ids)``.

    Only cells whose per-cell disposition is ALLOW or TOKENISE are
    retained. Anything else (DROP) is removed. A blocked request must
    never reach this function — the pipeline short-circuits first.
    """
    retained: list[DocumentCell] = []
    dropped: list[str] = []
    for cell in parsed.cells:
        disposition = decision.disposition_for(cell.cell_id)
        if disposition in (Disposition.ALLOW, Disposition.TOKENISE):
            retained.append(cell)
        else:
            dropped.append(cell.cell_id)
    return tuple(retained), tuple(dropped)
