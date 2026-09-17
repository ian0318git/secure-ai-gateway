"""Dashboard payload model — the only module that knows the wire shape.

The payload is split into two **structurally separate** channels:

* the **report channel** (``payload["report"]``) is *exactly*
  ``MetadataReport.to_dict()`` — no added keys. It stays raw-free and
  token-free, and stays pinned by the existing security suite
  (tests/security/test_tokens.py, test_m4_response.py,
  tests/unit/test_pipeline.py).
* the **operator channel** carries raw values and the token mapping,
  and lives ONLY under the paths declared in ``RAW_OR_TOKEN_PATHS``.

``redacted_view`` strips the operator channel; that is how the
isolation sweep proves nothing *outside* the declared paths carries
raw content or token values.

This module must never be imported by ``src/secure_ai_gateway``
(one-way dependency; pinned by tests/tools/test_scope.py).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

SCHEMA = "secure-ai-gateway-dashboard/1"

#: The ONLY JSON paths permitted to carry raw document/user content or
#: token values. ``redacted_view`` strips exactly these, and
#: tests/tools/test_payload_isolation.py sweeps the remainder.
#:
#: Adding a field that carries raw content WITHOUT declaring it here is
#: the realistic failure mode of this design (plan §Risks 7). Update
#: this set in the same change that adds such a field.
RAW_OR_TOKEN_PATHS: frozenset[str] = frozenset(
    {
        "instruction.text",
        "instruction.protected",
        "instruction.spans[].raw",
        "cells[].column",
        "cells[].value",
        "cells[].value_protected",
        "cells[].spans[].raw",
        "mapping[].raw",
        "mapping[].token",
        "payload.body",
        "response.raw_text",
        "outcome.restored_text",
    }
)

#: Pipeline stages, in display order.
STAGE_IDS: tuple[str, ...] = (
    "parse",
    "detect",
    "policy",
    "minimise",
    "tokenise",
    "provider",
    "response",
)

#: Sensitive-data policy stages that can only be shown as "running"
#: until the session's report lands (see recorder.note_stage).
STAGE_LABELS: dict[str, str] = {
    "parse": "解析檔案",
    "detect": "偵測敏感內容",
    "policy": "政策引擎",
    "minimise": "最小化",
    "tokenise": "換代號",
    "provider": "送往 LLM",
    "response": "回應檢查與還原",
}


@dataclass
class SessionTrace:
    """Mutable accumulator for one session, filled by the recorder.

    Holds no lock of its own: ``DashboardRecorder`` serialises access
    (one writer thread, N reader threads — see server.py).
    """

    request_id: str
    started_at: float
    status: str = "running"
    status_reason: str = ""
    finished_at: float | None = None
    source: dict[str, Any] = field(default_factory=dict)
    #: The instruction as the caller supplied it (raw, pre-protection).
    instruction: str | None = None
    #: The instruction AFTER ``protect_instruction`` — captured by
    #: ``RecordingVault.clear()``, i.e. just before SR-019 destroys it.
    protected_instruction: str | None = None
    #: Instruction-side detection spans (request phase only).
    instruction_spans: list[dict[str, Any]] = field(default_factory=list)
    #: stage id -> {"status", "detail", "at"}
    stages: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: cell_id -> {"cell_id", "column", "row", "value", "spans"}
    cells: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: (entity_type, raw) -> {"entity_type", "raw", "token"}
    mappings: dict[tuple[str, str], dict[str, str]] = field(
        default_factory=dict
    )
    #: cell_id -> protected value, from the object the provider got
    protected_cells: dict[str, str] = field(default_factory=dict)
    #: cell_id -> {"disposition", "reason"}
    dispositions: dict[str, dict[str, str]] = field(default_factory=dict)
    wire: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    outcome: dict[str, Any] | None = None
    audit: list[dict[str, Any]] = field(default_factory=list)
    report: dict[str, Any] | None = None
    report_markdown: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Payload assembly
# ---------------------------------------------------------------------------


def _stage_list(trace: SessionTrace) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for stage_id in STAGE_IDS:
        record = trace.stages.get(stage_id)
        out.append(
            {
                "id": stage_id,
                "label": STAGE_LABELS.get(stage_id, stage_id),
                "status": record["status"] if record else "pending",
                "detail": record.get("detail", "") if record else "",
                "at": record.get("at") if record else None,
            }
        )
    return out


def _cell_payload(
    record: dict[str, Any], trace: SessionTrace
) -> dict[str, Any]:
    cell_id = record["cell_id"]
    disposition = trace.dispositions.get(cell_id)
    return {
        "cell_id": cell_id,
        "column": record["column"],
        "row": record["row"],
        "value": record["value"],
        "value_protected": trace.protected_cells.get(cell_id),
        "disposition": disposition["disposition"] if disposition else None,
        "reason": disposition["reason"] if disposition else "",
        "spans": [dict(span) for span in record.get("spans", ())],
    }


def _occurrences(raw: str, entity_type: str, trace: SessionTrace) -> list:
    """Locate one (type, raw) pair across the recorded cells.

    Joined in memory — the vault stores no location, and calling
    ``token_for`` again would re-issue on a cleared vault.
    """
    found: list[dict[str, Any]] = []
    for record in trace.cells.values():
        for span in record.get("spans", ()):
            if span["entity_type"] != entity_type:
                continue
            if span["raw"] != raw:
                continue
            found.append(
                {
                    "cell_id": record["cell_id"],
                    "column": record["column"],
                    "row": record["row"],
                    "start": span["start"],
                    "end": span["end"],
                }
            )
    return found


def _mapping_payload(trace: SessionTrace) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for (entity_type, raw), entry in trace.mappings.items():
        out.append(
            {
                "entity_type": entity_type,
                "raw": raw,
                "token": entry["token"],
                "occurrences": _occurrences(raw, entity_type, trace),
            }
        )
    out.sort(key=lambda e: (e["entity_type"], e["token"]))
    return out


def to_payload(trace: SessionTrace) -> dict[str, Any]:
    """Serialise a finished (or running) trace into the wire payload."""
    return {
        "schema": SCHEMA,
        "request_id": trace.request_id,
        "status": trace.status,
        "status_reason": trace.status_reason,
        "started_at": trace.started_at,
        "finished_at": trace.finished_at,
        "source": dict(trace.source),
        "instruction": {
            "text": trace.instruction,
            "protected": trace.protected_instruction,
            "spans": [dict(span) for span in trace.instruction_spans],
        },
        "stages": _stage_list(trace),
        "cells": [_cell_payload(r, trace) for r in trace.cells.values()],
        "mapping": _mapping_payload(trace),
        "payload": trace.wire,
        "response": trace.response,
        "outcome": trace.outcome,
        "audit": list(trace.audit),
        "report": trace.report,
        "report_markdown": trace.report_markdown,
        "error": trace.error,
    }


def state_view(payload: dict[str, Any]) -> dict[str, Any]:
    """Metadata-only projection for the 1 Hz state poll.

    Carries NO raw content and NO token value: the mapping moves only
    on the explicit per-session fetch.
    """
    return {
        "schema": payload["schema"],
        "request_id": payload["request_id"],
        "status": payload["status"],
        "status_reason": payload["status_reason"],
        "source": payload["source"].get("name", ""),
        "stages": [
            {"id": s["id"], "status": s["status"]}
            for s in payload["stages"]
        ],
    }


def session_brief(payload: dict[str, Any]) -> dict[str, Any]:
    """One row of the session picker — metadata only."""
    return {
        "request_id": payload["request_id"],
        "status": payload["status"],
        "status_reason": payload["status_reason"],
        "source": payload["source"].get("name", ""),
        "started_at": payload["started_at"],
    }


def state_envelope(
    sessions: list[dict[str, Any]],
    current: dict[str, Any] | None,
    revision: int,
) -> dict[str, Any]:
    """Body of ``/api/state`` — the 1 Hz poll.

    Metadata only: no raw content, no token value. The mapping moves
    ONLY on the explicit per-session fetch. ``redacted_view`` must leave
    this unchanged, which is what pins the claim (plan §S/§Tests).
    """
    return {
        "schema": SCHEMA,
        "revision": revision,
        "sessions": sessions,
        "current": current,
    }


def to_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False)


def state_json(payload: dict[str, Any]) -> str:
    return json.dumps(state_view(payload), ensure_ascii=False)


# ---------------------------------------------------------------------------
# Redaction (the isolation sweep)
# ---------------------------------------------------------------------------


def redacted_view(payload: dict[str, Any]) -> dict[str, Any]:
    """Copy of ``payload`` with every declared raw/token path removed.

    Kept in this module (not in the test) so the declared path list and
    the stripper cannot drift apart.
    """
    return _strip(payload, "")


def _strip(node: Any, path: str) -> Any:
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            child = f"{path}.{key}" if path else key
            if child in RAW_OR_TOKEN_PATHS:
                continue
            if f"{child}[]" in RAW_OR_TOKEN_PATHS:
                continue
            out[key] = _strip(value, child)
        return out
    if isinstance(node, list):
        return [_strip(item, f"{path}[]") for item in node]
    return node
