"""Span-level token substitution (DESIGN §8: minimisation -> tokenisation).

Detection spans are (start, end) character offsets into the
NFKC-normalised cell text; substitution rebuilds each TOKENISE cell's
value left-to-right over its sorted, non-overlapping spans, so no
offset arithmetic is needed. All results stay inside the trusted
environment (T-I03); nothing here ever logs or serialises raw values
or token mappings.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Protocol

from secure_ai_gateway.errors import InstructionSecretError
from secure_ai_gateway.models import (
    DetectionResult,
    DetectionSpan,
    Disposition,
    DocumentCell,
    EntityType,
    PolicyDecision,
)
from secure_ai_gateway.tokenisation.vault import TokenVault


class _TextAnalyzer(Protocol):
    """Duck-typed DetectionEngine slice used for the instruction."""

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]: ...


# Same set as policy/engine.py:_BLOCK_TYPES; duplicated deliberately,
# mirroring the models.DetectionResult.has_blocking_secret precedent —
# the security test suite pins the two sets to stay equal.
_INSTRUCTION_BLOCK_TYPES = frozenset(
    {
        EntityType.SECRET,
        EntityType.API_KEY,
        EntityType.PASSWORD,
        EntityType.JWT,
        EntityType.PRIVATE_KEY,
    }
)


def tokenise_cells(
    cells: tuple[DocumentCell, ...],
    detection: DetectionResult,
    decision: PolicyDecision,
    vault: TokenVault,
) -> tuple[tuple[DocumentCell, ...], int]:
    """Replace every detection span in TOKENISE cells with its token.

    Returns ``(protected_cells, tokenised_span_count)``. ALLOW cells
    are returned as the SAME instances (identity preserved); TOKENISE
    cells become new DocumentCell instances via ``dataclasses.replace``.
    ``tokenised_span_count`` counts document spans substituted only.
    """
    protected: list[DocumentCell] = []
    substituted = 0
    for cell in cells:
        if decision.disposition_for(cell.cell_id) is not Disposition.TOKENISE:
            protected.append(cell)
            continue
        spans = detection.spans_for(cell.cell_id)
        new_value = _substitute(cell.value, spans, vault)
        if new_value == cell.value:
            protected.append(cell)
            continue
        substituted += sum(1 for s in spans if s.end > s.start)
        protected.append(replace(cell, value=new_value))
    return tuple(protected), substituted


def protect_instruction(
    engine: _TextAnalyzer,
    instruction: str,
    vault: TokenVault,
) -> str:
    """Apply detection + policy + tokenisation to the instruction (SR-022).

    Secret-class spans raise ``InstructionSecretError`` (the pipeline
    turns it into a BLOCK with reason ``secret:<TYPE>``); PII spans are
    substituted through the shared session vault; all other text passes
    through unchanged. Runs AFTER the injection check in the pipeline.
    """
    spans = engine.analyze_text(instruction)
    for span in spans:
        if span.entity_type in _INSTRUCTION_BLOCK_TYPES:
            raise InstructionSecretError(span.entity_type)
    return _substitute(instruction, spans, vault)


def restore_text_with_spans(
    text: str, vault: TokenVault
) -> tuple[str, tuple[tuple[int, int], ...]]:
    """Restore every known token in ``text``, tracking its position.

    Returns ``(restored, spans)`` where each span is ``(start, end)``
    into the RETURNED text (output space — token length differs from
    raw length, so input-space offsets would be wrong). The M4 response
    guard uses the spans to tell authorised restored values from raw
    values the model authored itself. Unknown strings pass through
    unchanged and produce no span. ``re.sub`` cannot accumulate output
    offsets, so the rebuild is a manual left-to-right pass; token
    substring disjointness is pinned by a property test
    (tests/unit/test_vault.py::TestTokenSubstringSafety).
    """
    tokens = vault.tokens()
    if not tokens:
        return text, ()
    ordered = sorted(tokens, key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(t) for t in ordered))
    out: list[str] = []
    spans: list[tuple[int, int]] = []
    pos = 0  # input position
    out_pos = 0  # output position; restored spans live in this space
    for m in pattern.finditer(text):
        raw = vault.restore(m.group(0))
        if raw is None:  # defensive: unknown strings pass through
            continue
        out.append(text[pos : m.start()])
        out.append(raw)
        start = out_pos + (m.start() - pos)
        spans.append((start, start + len(raw)))
        out_pos = start + len(raw)
        pos = m.end()
    out.append(text[pos:])
    return "".join(out), tuple(spans)


def restore_text(text: str, vault: TokenVault) -> str:
    """Restore every known token in ``text`` to its raw value.

    Round-trip tests today; M4 response restoration. Unknown strings
    pass through unchanged.
    """
    return restore_text_with_spans(text, vault)[0]


def _substitute(
    text: str, spans: tuple[DetectionSpan, ...], vault: TokenVault
) -> str:
    """Rebuild ``text`` with each span replaced by its token.

    Spans arrive sorted and non-overlapping (CellDetection ordering
    invariant); degenerate spans (end <= start) are skipped.
    """
    out: list[str] = []
    pos = 0
    for span in spans:
        if span.end <= span.start:  # defensive: skip degenerate spans
            continue
        out.append(text[pos : span.start])
        out.append(vault.token_for(span.entity_type, span.raw_value))
        pos = span.end
    out.append(text[pos:])
    return "".join(out)
