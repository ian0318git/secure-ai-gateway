"""Split stability + stratified proportions (BENCHMARK.md §5.1)."""

from __future__ import annotations

from benchmark.generate import CORPUS_COMPOSITION, generate
from benchmark.split import TEST_FRACTION, split


def test_split_stable_across_runs() -> None:
    corpus = generate(42)
    train_a, test_a = split(corpus)
    train_b, test_b = split(corpus)
    assert [r.record_id for r in train_a] == [r.record_id for r in train_b]
    assert [r.record_id for r in test_a] == [r.record_id for r in test_b]
    assert train_a and test_a


def test_split_covers_all_records_exactly_once() -> None:
    corpus = generate(42)
    train, test = split(corpus)
    ids = [r.record_id for r in train] + [r.record_id for r in test]
    # INJECTION / CLEAN records are scored separately (§5.4)
    split_ids = sorted(
        r.record_id for r in corpus.records if r.kind not in ("INJECTION", "CLEAN")
    )
    assert sorted(ids) == split_ids
    assert len(ids) == len(set(ids))


def test_split_excludes_injection_and_clean() -> None:
    corpus = generate(42)
    train, test = split(corpus)
    all_split_ids = {r.record_id for r in train} | {r.record_id for r in test}
    for record in corpus.records:
        if record.kind in ("INJECTION", "CLEAN"):
            assert record.record_id not in all_split_ids


def test_per_class_80_20() -> None:
    """Every class lands 80% train / 20% test (exact)."""
    corpus = generate(42)
    train, test = split(corpus)
    for cls in CORPUS_COMPOSITION:
        if cls == "INJECTION":
            continue
        train_n = sum(1 for r in train if r.primary_class == cls)
        test_n = sum(1 for r in test if r.primary_class == cls)
        total = train_n + test_n
        # matches split(): cut = int(total * (1 - fraction))
        expected_test = total - int(total * (1.0 - TEST_FRACTION))
        assert test_n == expected_test, (
            f"{cls}: test {test_n} != {expected_test} of {total}"
        )
        assert test_n >= 20, f"{cls}: test split too small: {test_n}"


def test_multi_primary_class_counts() -> None:
    """Multi-entity records split under their first entity's class."""
    corpus = generate(42)
    train, test = split(corpus)
    multi_train = sum(1 for r in train if r.kind == "MULTI")
    multi_test = sum(1 for r in test if r.kind == "MULTI")
    assert multi_train + multi_test == 300
