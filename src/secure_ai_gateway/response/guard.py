"""M5 response guard: validate, restore, deliver (DESIGN §17, SR-008/021).

LLM output is untrusted (SR-021). Every response passes through
``ResponseGuard.check`` before it can leave the trusted environment:

1. token validation — every token-shaped string must be an issued
   session token; unknown/hallucinated values are a violation and are
   NEVER restored (POC_PLAN M4 acceptance);
2. task compliance — echoing the request section markers is a
   violation (cheap deterministic proxy for the "output the original
   data" parroting case, T-I06);
3. response-side prompt injection (M5) — the response is scanned with
   the SAME pattern tables as the input detector (mirror rule,
   DECISIONS M5): any pattern the input side treats as an attack is a
   violation when the model authors it. Pre-restore: only the
   model-authored surface (model words + token strings) is checked,
   so an authorised restored vault value can never trigger it. A
   response that quotes or analyses an attack is blocked too
   (conservative — no LLM judge, CLAUDE.md §6.10/6.11);
4. controlled restoration (DECISIONS M2 flag: restore known tokens
   BEFORE the sensitive scan, or tokens re-detect as PII) with output
   -space position tracking;
5. sensitive-data scan on the text that would be delivered: only
   detections fully contained in a restored span are authorised (the
   value came from our own vault); anything else — raw PII, secrets,
   invented reserved-format values — is a violation (fail closed);
6. completeness: ``stop_reason == "max_tokens"`` is a violation by
   decision (the response is truncated; user decision, DECISIONS M4).

Violations return a ``ResponseOutcome`` with status ``"blocked"`` and
an empty ``text`` — nothing is ever returned on a violation. All
violation checks are deterministic and ordered (priority in code).
Exceptions propagate to the session orchestrator, which fails closed
with ``error:<Class>``. This module never logs and never serialises
text (SR-009): the caller owns logging of counts/categories only.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Protocol

from secure_ai_gateway.injection.detector import detect
from secure_ai_gateway.llm.request_builder import (
    DOCUMENT_MARKER,
    INSTRUCTION_MARKER,
)
from secure_ai_gateway.models import DetectionSpan, EntityType
from secure_ai_gateway.tokenisation.substitution import restore_text_with_spans
from secure_ai_gateway.tokenisation.vault import TOKEN_RE, TokenVault

# Same set as policy/engine.py:_BLOCK_TYPES and substitution.py
# _INSTRUCTION_BLOCK_TYPES; duplicated deliberately, mirroring the
# models.DetectionResult.has_blocking_secret precedent — the security
# test suite pins the sets to stay equal.
_RESPONSE_SECRET_TYPES = frozenset(
    {
        EntityType.SECRET,
        EntityType.API_KEY,
        EntityType.PASSWORD,
        EntityType.JWT,
        EntityType.PRIVATE_KEY,
    }
)


class _ResponseAnalyzer(Protocol):
    """Duck-typed DetectionEngine slice used for the response scan."""

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]: ...


@dataclass(frozen=True)
class ResponseOutcome:
    """Result of one response-guard check.

    ``text`` is the restored, delivered text iff ``status == "ok"``;
    it is always empty on ``"blocked"`` (fail closed). ``reason`` is
    machine-readable (``"response:<category>"``), raw-free, and safe
    for logging.
    """

    status: str  # "ok" | "blocked"
    text: str = field(default="", repr=False)  # never in repr
    reason: str = ""


def _contained_in_restored(
    span: DetectionSpan, restored_spans: tuple[tuple[int, int], ...]
) -> bool:
    """True iff ``span`` lies entirely inside one restored span.

    Full containment, not mere overlap: a detection that extends past
    a restored value contains model-authored characters (e.g. NER
    merges a restored name with an adjacent leaked one) and must not
    be authorised. Restored spans are non-overlapping by construction.
    """
    return any(
        r_start <= span.start and span.end <= r_end
        for r_start, r_end in restored_spans
    )


class ResponseGuard:
    """Deterministic response scanner + controlled restorer (DESIGN §17).

    The guard restores internally, scans the text that would be
    delivered, and only returns restored text on ``ok`` — every check
    decision completes before any restored text leaves the guard, so
    DESIGN §17's "scanner before restoration" and the M2 restore-before
    -scan flag are both satisfied (reconciliation in DECISIONS M4).
    """

    def __init__(
        self,
        engine: _ResponseAnalyzer,
        *,
        truncation_is_violation: bool = True,
    ) -> None:
        self._engine = engine
        self._truncation_is_violation = truncation_is_violation

    def check(
        self, text: str, vault: TokenVault, stop_reason: str | None
    ) -> ResponseOutcome:
        """Validate ``text`` and return the restored outcome.

        The response is NFKC-normalised exactly once; every downstream
        step shares that coordinate space (the engine's documented
        span convention, models.py). Any exception propagates to the
        session orchestrator -> ``error:<Class>`` BLOCK (fail closed).
        """
        norm = unicodedata.normalize("NFKC", text)

        # 1. Token validation, pre-restore: unknown/hallucinated tokens
        # are a violation and are never restored (M4 acceptance).
        for m in TOKEN_RE.finditer(norm):
            if vault.restore(m.group(0)) is None:
                return ResponseOutcome("blocked", reason="response:unknown_token")

        # 2. Task compliance: echoing the request markers is a
        # structural violation (markers are ASCII, NFKC- and
        # restore-invariant, so checking pre-restore is exact).
        if INSTRUCTION_MARKER in norm or DOCUMENT_MARKER in norm:
            return ResponseOutcome("blocked", reason="response:marker_echo")

        # 3. Response-side prompt injection (M5, mirror rule): the same
        # pattern tables the input detector uses. Pre-restore, so only
        # the model-authored surface is seen (restored vault values can
        # never match — a real customer named "Bypass Security Policy
        # Co." delivers). Any finding blocks with the first finding's
        # category (detect() sorts deterministically).
        findings = detect(norm, "response")
        if findings:
            return ResponseOutcome(
                "blocked",
                reason=f"response:injection:{findings[0].category.value}",
            )

        # 4. Controlled restoration (M2 flag), tracking output-space
        # positions so the scan can tell authorised values from leaks.
        restored, restored_spans = restore_text_with_spans(norm, vault)

        # 5. Sensitive-data scan on the text that would be delivered.
        # Defensive skips first: stub engines may return spans whose
        # offsets do not fit the response (a real engine cannot) —
        # mirroring the degenerate-span skip in substitution._substitute.
        spans = self._engine.analyze_text(restored)
        qualified = sorted(
            (
                s
                for s in spans
                if s.end - s.start > 0 and s.end <= len(restored)
            ),
            key=lambda s: (s.start, s.end, s.entity_type.value),
        )

        # Secrets take precedence over PII (severity, mirroring the
        # policy engine's _BLOCK_TYPES ordering).
        for s in qualified:
            if _contained_in_restored(s, restored_spans):
                continue  # authorised: value came from our own vault
            if s.entity_type in _RESPONSE_SECRET_TYPES:
                return ResponseOutcome(
                    "blocked",
                    reason=f"response:secret:{s.entity_type.value}",
                )
        for s in qualified:
            if _contained_in_restored(s, restored_spans):
                continue  # authorised (see pass above)
            if s.entity_type in _RESPONSE_SECRET_TYPES:
                continue  # unreachable: handled in the pass above
            return ResponseOutcome(
                "blocked", reason=f"response:pii:{s.entity_type.value}"
            )

        # 6. Completeness: a truncated response is a violation by
        # decision (the text itself passed every scan).
        if self._truncation_is_violation and stop_reason == "max_tokens":
            return ResponseOutcome("blocked", reason="response:truncated")

        return ResponseOutcome("ok", text=restored)
