"""M4 session orchestrator: one pipeline call + one provider call.

One ``Session.run`` is one gateway session (SR-019): the pipeline
produces protected cells and a session vault, the request builder
merges them, the provider is called, the response is parsed, and the
response guard validates + restores it (DESIGN §17, SR-008/021).
The session OWNS the vault and clears it on every path (success,
BLOCK, failure) — mappings are destroyed at session end.

Response violations fail closed: the whole response is blocked
(``SessionResult.decision`` becomes a BLOCK with a machine-readable
``response:<category>`` reason) and nothing is delivered.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from secure_ai_gateway.llm.provider import LLMProvider
from secure_ai_gateway.llm.request_builder import build_request
from secure_ai_gateway.logging import log_event
from secure_ai_gateway.models import Disposition, PolicyDecision
from secure_ai_gateway.pipeline import Pipeline
from secure_ai_gateway.policy.templates import resolve_template
from secure_ai_gateway.reporting import MetadataReport
from secure_ai_gateway.response.guard import ResponseGuard

logger = logging.getLogger("secure_ai_gateway.session")


@dataclass(frozen=True)
class SessionResult:
    request_id: str
    decision: PolicyDecision
    report: MetadataReport
    response_text: str = field(default="", repr=False)  # validated+restored

    @property
    def delivered(self) -> bool:
        return not self.decision.is_blocked() and bool(self.response_text)


class Session:
    """Orchestrates one end-to-end gateway session."""

    def __init__(
        self,
        pipeline: Pipeline,
        provider: LLMProvider | None = None,
    ) -> None:
        self._pipeline = pipeline
        self._provider = provider
        # Eager: a pipeline without an engine fails here, at
        # construction (fail closed), before any session can run.
        self._guard = ResponseGuard(pipeline.engine)

    def run(
        self,
        path: str | Path,
        *,
        instruction: str | None = None,
        template_name: str | None = "gross_margin",
        request_id: str | None = None,
    ) -> SessionResult:
        """Run one session: pipeline -> request -> provider -> parse.

        ``provider=None`` runs the M2 mode (no provider call) and still
        clears the vault.
        """
        rid = request_id or uuid.uuid4().hex[:12]
        decision, report, cells, vault = self._pipeline.process_file(
            path,
            instruction=instruction,
            template_name=template_name,
            request_id=rid,
        )
        if decision.is_blocked():
            # M2 guarantees the vault is already empty on BLOCK paths.
            return SessionResult(rid, decision, report)
        try:
            if self._provider is None:
                return SessionResult(rid, decision, report)  # M2 mode
            # The pipeline already BLOCKed on an unresolvable template,
            # so this lookup cannot be None here.
            template = resolve_template(template_name)
            request = build_request(
                protected_cells=cells,
                protected_instruction=vault.protected_instruction,
                template=template,
            )
            # NOTE: max_tokens is NOT logged — the key contains "token"
            # and log_event rejects it (M2 lesson; DECISIONS.md).
            log_event(
                logger,
                "provider_call",
                request_id=rid,
                model=request.model,
                doc_cells=len(request.document),
            )
            parsed = self._provider.complete(request)
            log_event(
                logger,
                "provider_ok",
                request_id=rid,
                response_chars=len(parsed.text),
            )
            # M4: scan + restore inside the trusted environment, before
            # the vault is cleared (SR-019). Violations fail closed.
            outcome = self._guard.check(
                parsed.text, vault, parsed.stop_reason
            )
            if outcome.status == "blocked":
                log_event(
                    logger,
                    "response_blocked",
                    level=logging.ERROR,
                    request_id=rid,
                    reason=outcome.reason,
                    response_chars=len(parsed.text),
                )
                return SessionResult(
                    rid,
                    PolicyDecision(
                        disposition=Disposition.BLOCK,
                        reason=outcome.reason,
                    ),
                    report,
                )
            return SessionResult(
                rid, decision, report, response_text=outcome.text
            )
        except Exception as exc:  # noqa: BLE001 — fail closed
            reason = f"error:{type(exc).__name__}"
            log_event(
                logger,
                "provider_blocked",
                level=logging.ERROR,
                request_id=rid,
                reason=reason,
            )
            return SessionResult(
                rid,
                PolicyDecision(
                    disposition=Disposition.BLOCK,
                    reason=reason,
                ),
                report,
            )
        finally:
            vault.clear()  # SR-019: mappings destroyed at session end
