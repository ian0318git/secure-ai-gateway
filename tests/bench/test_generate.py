"""Corpus generator: determinism, composition, value/recogniser alignment."""

from __future__ import annotations

import re
from collections import Counter

from benchmark.generate import (
    CLEAN_CONTROL_COUNT,
    CORPUS_COMPOSITION,
    MULTI_ENTITY_COUNT,
    generate,
)
from secure_ai_gateway.detection.recognizers import (
    _ADDRESS_RE,
    _API_KEY_RE,
    _COMPANY_ZH_RE,
    _CREDIT_CARD_RE,
    _CUSTOMER_ID_RE,
    _EMAIL_RE,
    _EMPLOYEE_ID_RE,
    _JWT_RE,
    _jwt_header_ok,
    _luhn_ok,
    _PHONE_RE,
    _SECRET_KV_RE,
    _SECRET_ZH_RE,
    _TW_ID_RE,
    _tw_id_checksum,
)
from secure_ai_gateway.injection.detector import detect


def test_determinism() -> None:
    """BENCHMARK.md §7: two runs produce identical records."""
    a = generate(42)
    b = generate(42)
    assert len(a.records) == len(b.records)
    for r1, r2 in zip(a.records, b.records):
        assert r1.record_id == r2.record_id
        assert r1.cell_text == r2.cell_text
        assert r1.kind == r2.kind
        assert [
            (s.start, s.end, s.entity_type.value) for s in r1.gt_spans
        ] == [(s.start, s.end, s.entity_type.value) for s in r2.gt_spans]
        if r1.injection is not None:
            assert r1.injection == r2.injection


def test_composition_counts() -> None:
    corpus = generate(42)
    counts = Counter(r.kind for r in corpus.records)
    for cls, expected in CORPUS_COMPOSITION.items():
        assert counts[cls] == expected, f"{cls}: {counts[cls]} != {expected}"
    assert counts["MULTI"] == MULTI_ENTITY_COUNT
    assert counts["CLEAN"] == CLEAN_CONTROL_COUNT
    assert corpus.positives > 0 and corpus.negatives == CORPUS_COMPOSITION["NEGATIVE"]
    assert corpus.injections == CORPUS_COMPOSITION["INJECTION"]


def test_major_classes_at_least_1000() -> None:
    """BENCHMARK.md §2.2: all major classes >= 1000."""
    major = ("PERSON", "ADDRESS", "TW_ID", "EMAIL", "PHONE",
             "CUSTOMER_ID", "EMPLOYEE_ID")
    counts = Counter(r.kind for r in generate(42).records)
    for cls in major:
        assert counts[cls] >= 1000, cls


def test_records_sorted_and_ids_unique() -> None:
    corpus = generate(42)
    ids = [r.record_id for r in corpus.records]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))


def test_tw_id_checksum_invalid_by_construction() -> None:
    """BENCHMARK.md §2.1: every generated TW ID is checksum-INVALID."""
    corpus = generate(42)
    for record in corpus.by_class("TW_ID"):
        match = re.search(r"[A-Z][12]\d{8}", record.cell_text)
        assert match is not None
        raw = match.group(0)
        assert not _tw_id_checksum(raw[0], raw[1:]), f"valid TW ID: {raw}"


def test_values_match_recogniser_patterns() -> None:
    """Generator<->recogniser contract: every value is detectable.

    Searches the full cell text (embedded contexts included) with the
    recogniser's own regex — if this fails, the corpus would measure
    generator drift, not detector quality.
    """
    corpus = generate(42)
    checks = (
        ("EMAIL", _EMAIL_RE),
        ("PHONE", _PHONE_RE),
        ("TW_ID", _TW_ID_RE),
        ("CUSTOMER_ID", _CUSTOMER_ID_RE),
        ("EMPLOYEE_ID", _EMPLOYEE_ID_RE),
        ("API_KEY", _API_KEY_RE),
        ("JWT", _JWT_RE),
    )
    for cls, regex in checks:
        for record in corpus.by_class(cls):
            assert regex.search(record.cell_text), (
                f"{cls} value not matched: {record.cell_text!r}"
            )
    # special cases with validation
    for record in corpus.by_class("ADDRESS"):
        assert _ADDRESS_RE.search(record.cell_text), (
            f"address not matched: {record.cell_text!r}"
        )
    for record in corpus.by_class("ORGANIZATION"):
        assert _COMPANY_ZH_RE.search(record.cell_text), (
            f"company not matched: {record.cell_text!r}"
        )
    for record in corpus.by_class("CREDIT_CARD"):
        match = _CREDIT_CARD_RE.search(record.cell_text)
        assert match is not None
        digits = re.sub(r"[-\s]", "", match.group(0))
        assert _luhn_ok(digits), f"card fails Luhn: {record.cell_text!r}"
    for record in corpus.by_class("JWT"):
        match = _JWT_RE.search(record.cell_text)
        assert match is not None
        header, _, _ = match.group(0).partition(".")
        assert _jwt_header_ok(header), f"JWT header invalid: {record.cell_text!r}"
    for record in corpus.by_class("SECRET"):
        assert _SECRET_KV_RE.search(record.cell_text) or _SECRET_ZH_RE.search(
            record.cell_text
        ), f"secret not matched: {record.cell_text!r}"


def test_english_person_names() -> None:
    corpus = generate(42)
    english = [
        r for r in corpus.by_class("PERSON") if re.search(r"[A-Za-z]+ [A-Za-z]+", r.cell_text)
    ]
    total = len(corpus.by_class("PERSON"))
    ratio = len(english) / total if total else 0.0
    assert 0.35 <= ratio <= 0.45, f"english person share: {ratio:.2f}"


def test_multi_entity_cells_have_two_spans() -> None:
    corpus = generate(42)
    multi = [r for r in corpus.records if r.kind == "MULTI"]
    assert len(multi) == MULTI_ENTITY_COUNT
    for record in multi:
        assert len(record.gt_spans) == 2
        a, b = record.gt_spans
        assert a.entity_type is not b.entity_type
        # spans must not overlap
        assert a.end <= b.start or b.end <= a.start


def test_injection_strings_trigger_expected_patterns() -> None:
    """BENCHMARK.md §5.4: each injection string hits its (category, severity)."""
    corpus = generate(42)
    for record in corpus.by_class("INJECTION"):
        assert record.injection is not None
        findings = detect(record.cell_text, location=f"bench:{record.record_id}")
        matched = any(
            f.category is record.injection.category
            and f.severity == record.injection.severity
            for f in findings
        )
        assert matched, (
            f"{record.record_id} expected "
            f"{record.injection.category.value}/{record.injection.severity}, "
            f"got {[(f.category.value, f.severity) for f in findings]}"
        )


def test_clean_control_zero_findings() -> None:
    """BENCHMARK.md §5.4: the clean control set produces ZERO findings."""
    corpus = generate(42)
    for record in corpus.by_class("CLEAN"):
        findings = detect(record.cell_text, location=f"bench:{record.record_id}")
        assert not findings, f"{record.record_id}: {[f.pattern_id for f in findings]}"
