"""Stratified 80/20 train/test split (BENCHMARK.md §5.1, normative).

Records are ordered per class by the stable digest of ``record_id``
(hashlib.sha256); the last 20% per class form the test set. The split
is fixed and never re-randomised; ``split()`` is deterministic.

INJECTION and CLEAN records are NOT part of the split: they are scored
separately on the full set (BENCHMARK.md §5.4).
"""

from __future__ import annotations

import hashlib

from benchmark.generate import Corpus, Record

TEST_FRACTION = 0.2


def _rank(record: Record) -> bytes:
    return hashlib.sha256(record.record_id.encode("utf-8")).digest()


def split(corpus: Corpus) -> tuple[tuple[Record, ...], tuple[Record, ...]]:
    """Return (train, test), each a tuple sorted by record_id."""
    split_candidates = [
        r for r in corpus.records if r.kind not in ("INJECTION", "CLEAN")
    ]
    classes = sorted({r.primary_class for r in split_candidates})
    train: list[Record] = []
    test: list[Record] = []
    for cls in classes:
        members = [r for r in split_candidates if r.primary_class == cls]
        ordered = sorted(members, key=lambda r: (_rank(r), r.record_id))
        cut = int(len(ordered) * (1.0 - TEST_FRACTION))
        train.extend(ordered[:cut])
        test.extend(ordered[cut:])
    train.sort(key=lambda r: r.record_id)
    test.sort(key=lambda r: r.record_id)
    return tuple(train), tuple(test)
