"""Core data models shared across the pipeline.

Security contract (CLAUDE.md §6): raw document content lives ONLY in
memory. Fields holding raw text are marked ``repr=False`` and must
never appear in ``__repr__``, ``__str__``, ``log_view()``, or any
serialisation path. The unit tests in ``tests/unit/test_models.py``
assert this.

Span coordinate space: all spans are (start, end) character offsets
into the NFKC-normalised cell text (see docs/BENCHMARK.md §3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator, Optional


class EntityType(str, Enum):
    """Entity classes the detection engine can emit.

    Format entities are produced by deterministic recognisers;
    NER entities by the Chinese NLP backend (plus deterministic
    helpers). See docs/BENCHMARK.md §4.1.
    """

    # Format entities
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    TW_ID = "TW_ID"
    CREDIT_CARD = "CREDIT_CARD"
    API_KEY = "API_KEY"
    JWT = "JWT"
    PRIVATE_KEY = "PRIVATE_KEY"
    PASSWORD = "PASSWORD"
    SECRET = "SECRET"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    CUSTOMER_ID = "CUSTOMER_ID"
    EMPLOYEE_ID = "EMPLOYEE_ID"
    TOKEN_PATTERN = "TOKEN_PATTERN"
    # NER entities
    PERSON = "PERSON"
    ADDRESS = "ADDRESS"
    LOCATION = "LOCATION"
    ORGANIZATION = "ORGANIZATION"
    COMPANY_NAME = "COMPANY_NAME"


class Disposition(str, Enum):
    """Policy disposition per docs/DESIGN.md §14.

    M1 emits the decision only; tokenisation (M2) executes TOKENISE.
    """

    BLOCK = "BLOCK"  # request is rejected, nothing further happens
    TOKENISE = "TOKENISE"  # value will be replaced by an opaque token (M2)
    DROP = "DROP"  # column/cell is removed
    ALLOW = "ALLOW"  # may pass through unchanged


class SpanSource(str, Enum):
    """Provenance of a detection span (for debugging and reporting)."""

    NER = "NER"  # Chinese NLP backend
    PATTERN = "PATTERN"  # deterministic regex recogniser
    FALLBACK = "FALLBACK"  # deterministic helper recogniser
    COMPOSITE = "COMPOSITE"  # merged NER + pattern evidence


class InjectionCategory(str, Enum):
    """Prompt-injection pattern categories (docs/DESIGN.md §11)."""

    OVERRIDE_DIRECT = "OVERRIDE_DIRECT"  # "ignore previous instructions"
    OVERRIDE_SYSTEM = "OVERRIDE_SYSTEM"  # "you are now ..." role swaps
    REVEAL = "REVEAL"  # "output the original customer names"
    DELIMITER = "DELIMITER"  # fake delimiters, "" > SYSTEM ...
    TOKEN_PROBE = "TOKEN_PROBE"  # attempts to dump tokens/mappings
    ROLE_HIJACK = "ROLE_HIJACK"  # pretend to be the system/admin
    POLICY_MANIP = "POLICY_MANIP"  # "bypass the policy", "no restrictions"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DetectionSpan:
    """A detected sensitive span inside one cell.

    ``raw_value`` is the matched text. It exists only in memory:
    ``repr=False`` and never rendered by ``log_view()``.
    """

    entity_type: EntityType
    start: int
    end: int
    score: float
    source: SpanSource
    raw_value: str = field(repr=False, compare=False)
    checksum_valid: Optional[bool] = None  # TW_ID only: True/False/None

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError(
                f"invalid span bounds [{self.start}:{self.end}]"
            )
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"score out of range: {self.score}")
        if self.checksum_valid is not None and not isinstance(
            self.checksum_valid, bool
        ):
            raise ValueError("checksum_valid must be bool or None")

    def log_view(self) -> str:
        """Sanitised representation: no raw value, no length info leaks."""
        return (
            f"DetectionSpan(type={self.entity_type.value}, "
            f"span=[{self.start}:{self.end}], score={self.score:.3f}, "
            f"source={self.source.value})"
        )


@dataclass(frozen=True, slots=True)
class InjectionFinding:
    """A prompt-injection pattern match in an instruction or a cell."""

    category: InjectionCategory
    severity: int  # 2 or 3 (3 = critical)
    location: str  # "instruction" or a cell_id
    pattern_id: str
    matched_text: str = field(repr=False, compare=False)  # memory only

    def __post_init__(self) -> None:
        if self.severity not in (2, 3):
            raise ValueError(f"severity must be 2 or 3, got {self.severity}")

    def log_view(self) -> str:
        return (
            f"InjectionFinding(category={self.category.value}, "
            f"severity={self.severity}, location={self.location!r}, "
            f"pattern={self.pattern_id})"
        )


@dataclass(frozen=True, slots=True)
class CellDetection:
    """Detection outcome for a single cell."""

    cell_id: str
    spans: tuple[DetectionSpan, ...] = ()
    injection_findings: tuple[InjectionFinding, ...] = ()

    def __post_init__(self) -> None:
        # Deterministic ordering invariant (BENCHMARK.md §7).
        spans = tuple(
            sorted(
                self.spans,
                key=lambda s: (s.start, s.end, s.entity_type.value, -s.score),
            )
        )
        object.__setattr__(self, "spans", spans)


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Detection outcome for a full document plus the instruction."""

    cells: tuple[CellDetection, ...] = ()
    instruction_findings: tuple[InjectionFinding, ...] = ()

    def spans_for(self, cell_id: str) -> tuple[DetectionSpan, ...]:
        for cell in self.cells:
            if cell.cell_id == cell_id:
                return cell.spans
        return ()

    def findings_for(self, cell_id: str) -> tuple[InjectionFinding, ...]:
        for cell in self.cells:
            if cell.cell_id == cell_id:
                return cell.injection_findings
        return ()

    def iter_cells(self) -> Iterator[CellDetection]:
        return iter(self.cells)

    def has_blocking_secret(self) -> bool:
        """True if any span is a disposition-BLOCK entity type.

        Kept model-side so the policy engine stays a pure table lookup
        over ``DetectionResult``.
        """
        block_types = {
            EntityType.API_KEY,
            EntityType.JWT,
            EntityType.PRIVATE_KEY,
            EntityType.PASSWORD,
            EntityType.SECRET,
        }
        return any(
            span.entity_type in block_types
            for cell in self.cells
            for span in cell.spans
        )


# ---------------------------------------------------------------------------
# Parsed document
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DocumentCell:
    """One cell of a parsed document (NFKC-normalised at parse time)."""

    cell_id: str
    column: str  # header or positional label ("col_3"); never raw content
    value: str  # NFKC-normalised cell text
    row: int  # 0-based

    @property
    def empty(self) -> bool:
        return not self.value


@dataclass(frozen=True, slots=True)
class ParseStats:
    """Non-raw statistics about a parsed document."""

    file_name: str  # basename only
    file_size_bytes: int
    encoding: str
    format: str  # "csv" | "xlsx" | "text"
    row_count: int
    cell_count: int
    column_count: int
    estimated_tokens: int
    neutralised_formula_cells: int = 0
    skipped_empty_cells: int = 0


@dataclass(frozen=True, slots=True)
class ParsedDocument:
    """Result of parsing one input file."""

    stats: ParseStats
    cells: tuple[DocumentCell, ...]
    headers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if len(self.cells) != self.stats.cell_count:
            raise ValueError(
                "cell count mismatch between stats and cells"
            )

    def iter_cells(self) -> Iterator[DocumentCell]:
        return iter(self.cells)


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CellDecision:
    """Per-cell policy outcome (disposition + machine-readable reason)."""

    cell_id: str
    disposition: Disposition
    reason: str  # e.g. "pii", "secret:API_KEY", "column_not_allowed"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Outcome of the policy evaluation (docs/DESIGN.md §14)."""

    disposition: Disposition
    reason: str  # machine-readable, e.g. "secret:API_KEY", "error:<Class>"
    blocked_cell_ids: tuple[str, ...] = ()
    dropped_cell_ids: tuple[str, ...] = ()
    cell_decisions: tuple[CellDecision, ...] = ()

    def disposition_for(self, cell_id: str) -> Disposition | None:
        for cell in self.cell_decisions:
            if cell.cell_id == cell_id:
                return cell.disposition
        return None

    def is_blocked(self) -> bool:
        return self.disposition is Disposition.BLOCK

    def log_view(self) -> str:
        return (
            f"PolicyDecision(disposition={self.disposition.value}, "
            f"reason={self.reason!r}, blocked_cells={len(self.blocked_cell_ids)}, "
            f"dropped_cells={len(self.dropped_cell_ids)})"
        )
