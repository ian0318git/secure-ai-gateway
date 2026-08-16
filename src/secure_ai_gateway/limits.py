"""Resource limits enforced at parse time (T-D02, docs/POC_PLAN §4 M1).

Every limit maps to ``ResourceLimitError`` at the point of violation
so the pipeline can fail closed. Defaults are PoC-scale; they are
deliberately strict.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    max_file_bytes: int = 10 * 1024 * 1024  # 10 MB on disk
    max_rows: int = 100_000
    max_cells: int = 1_000_000
    max_cell_chars: int = 10_000
    max_decompressed_bytes: int = 200 * 1024 * 1024  # xlsx zip payload
    max_archive_members: int = 10_000


def estimate_tokens(char_count: int) -> int:
    """Heuristic token estimate: ~2 chars per token (CJK heavy).

    Documented heuristic for the token-count limit only; not an
    accurate tokeniser. Mirrors common CJK ~0.5 tokens/char practice.
    """
    return max(1, math.ceil(char_count / 2))
