# Secure AI Gateway — Detection Benchmark Methodology

Version: 0.3
Status: Approved (M1 planning)

This document defines the detection benchmark scoring rules BEFORE
implementation, as required by `docs/POC_PLAN.md` M1 Acceptance:

> span-level vs entity-level scoring defined before implementation

All definitions here are normative. The implementation
(`benchmark/` and `scripts/check_acceptance.py`) must follow them
exactly. Threshold calibration and detection rules may be tuned; the
scoring rules and acceptance thresholds in this document may NOT be
changed to make the benchmark pass (`docs/DESIGN.md` §9).

---

# 1. Purpose

Measure the sensitive-data detection pipeline (Presidio + explicitly
configured Chinese NLP backend + deterministic recognisers) on a fully
synthetic corpus, and verify M1 acceptance criteria.

The benchmark guards against two failure modes:

- **Undetected PII** (low recall) — confidential data reaches the LLM.
- **Excessive masking** (low precision) — legitimate business data is
  needlessly masked, defeating the purpose of the gateway.

A high recall achieved through excessive false positives does NOT pass.

---

# 2. Corpus

## 2.1 Source

All data is synthetic. Taiwan ID-like values are generated with an
invalid checksum BY CONSTRUCTION (the check digit is derived then
incremented modulo 10). The generator asserts checksum invalidity for
every generated value before writing it.

No real personal, company, or financial data is used.

## 2.2 Composition (train + test, before split)

| Class | Count | Notes |
|---|---|---|
| PERSON | 1500 | 60% Chinese, 40% English |
| ADDRESS | 1200 | Chinese addresses |
| TW_ID | 1000 | checksum-invalid by construction |
| EMAIL | 1000 | |
| PHONE | 1000 | TW / CN / +886 formats |
| CUSTOMER_ID | 1000 | CUST_ prefixed |
| EMPLOYEE_ID | 1000 | EMP_ prefixed |
| ORGANIZATION | 800 | Chinese company names |
| CREDIT_CARD | 300 | Luhn-valid; no real card numbers |
| API_KEY | 150 | sk- / AIza / ghp_ / AKIA patterns |
| JWT | 150 | three-segment base64url |
| SECRET | 150 | key=value style deny-list values |
| NEGATIVE | 2500 | see 2.3 |
| INJECTION | 200 | scored separately, see 5.4 |

Per-major-class counts: all "major" classes (PERSON, ADDRESS, TW_ID,
EMAIL, PHONE, CUSTOMER_ID, EMPLOYEE_ID) are >= 1000, satisfying the
M1 acceptance requirement.

## 2.3 Negative samples

Normal financial terms, ordinary column names, geographic terms that
must not be classified as personal data, common Chinese/English words,
and normal financial values (numbers, amounts, dates, percentages).

## 2.4 Contextual embedding

- 60% of positive records: the entity appears as the sole content of
  its cell.
- 40%: the entity is embedded in a financial-context sentence (tests
  NER in context).
- 300 additional records: cells containing MULTIPLE entities of
  different types (tests span matching and overlap resolution).

## 2.5 Record identity and generation

- Global random seed: `BENCHMARK_SEED = 42`.
- All randomness goes through one injected `random.Random(42)` — never
  the global random module.
- Every generated record has a stable `record_id` (e.g.
  `person_000001`). All iteration over generated data is in sorted
  order of `record_id`.
- The generator is deterministic: running it twice produces
  byte-identical output (verified by a test).

---

# 3. Coordinate Space

- Detection input: a single cell's text after NFKC normalisation
  (`unicodedata.normalize("NFKC", ...)`).
- Normalisation happens ONCE at parse time; the pipeline and the
  benchmark share the same coordinate space.
- Ground truth spans and predicted spans are both `(cell_id, start,
  end)` character offsets (Python string slicing semantics: `text[start:end]`).
- `cell_id` is unique per cell in a parsed document.

---

# 4. Scoring Rules

## 4.1 Entity classes

**Format entities** (deterministic recognisers):

EMAIL, PHONE, TW_ID, CREDIT_CARD, API_KEY, JWT, PRIVATE_KEY,
PASSWORD, SECRET, BANK_ACCOUNT, CUSTOMER_ID, EMPLOYEE_ID,
TOKEN_PATTERN

**NER entities** (Chinese NLP + deterministic helpers):

PERSON, ADDRESS, LOCATION, ORGANIZATION, COMPANY_NAME

## 4.2 True positive (TP) definition

- **Format entities:** predicted span must have the SAME entity type
  and an EXACT span match (start AND end equal) with a ground-truth
  span.
- **NER entities:** predicted span must have the SAME entity type and
  >= 1 character of overlap with a ground-truth span. A secondary
  metric, IoU >= 0.5 (intersection over union), is reported
  separately and does NOT affect acceptance.

## 4.3 Matching procedure

- Greedy one-to-one matching: predictions are processed in descending
  confidence order; each prediction may match at most one ground-truth
  span and each ground-truth span at most one prediction.
- A prediction matching a ground-truth span of a DIFFERENT type counts
  as FP (and the ground-truth span counts as FN) — no cross-type
  credit.

## 4.4 Negatives

A prediction on any NEGATIVE record is a FP.

## 4.5 Aggregate metric

Micro-aggregate: sum TP / FP / FN across all classes, then compute
precision and recall from the totals. F1 = harmonic mean.

## 4.6 Per-entity reporting

TP / FP / FN / Precision / Recall / F1 reported per entity class,
where practical.

---

# 5. Evaluation Protocol

## 5.1 Split

- Stratified 80/20 train/test split: records are ordered by stable
  hash of `record_id` (e.g. `hashlib.sha256(record_id).digest()`), and
  the last 20% per class form the test set.
- The split is fixed and never re-randomised.
- The benchmark test asserts split stability across runs.

## 5.2 Threshold calibration (train split only)

- Default confidence threshold: 0.5.
- Per-entity thresholds are calibrated on the TRAIN split by grid
  search over 0.40–0.90 in steps of 0.05, maximising F1 per entity
  class (minimum bound 0.40).
- Calibrated thresholds are recorded in the report (reproducibility).

## 5.3 Final metrics (test split only)

- Final reported metrics come from the held-out TEST split.
- Reporting calibration metrics on the test split is not allowed.

## 5.4 Injection strings

The 200 injection strings are scored separately from detection: the
benchmark asserts the injection detector (not the PII detector)
classifies each string as injected with its expected category and
severity. A clean-financial-sentence control set (>= 100 strings) must
produce zero injection findings.

---

# 6. Acceptance Thresholds

Applied to the TEST split:

| Metric | Threshold |
|---|---|
| Aggregate recall | >= 90% |
| Aggregate precision | >= 80% |
| PERSON recall / precision | >= 85% / >= 80% |
| ADDRESS recall / precision | >= 85% / >= 80% |
| Identifier entities (TW_ID, EMAIL, PHONE, CUSTOMER_ID, EMPLOYEE_ID) recall / precision | >= 85% / >= 80% |
| F1 | reported (aggregate and per-entity) |

`scripts/check_acceptance.py` reads the benchmark report JSON and
asserts every threshold. Any violation fails the milestone.

If the benchmark does not meet acceptance, the detection rules and
thresholds are adjusted — the acceptance thresholds are NOT lowered
(docs/DESIGN.md §9).

---

# 7. Determinism Requirements

- Same environment + same code => byte-identical report JSON.
- All iteration orders are sorted; no reliance on dict/set ordering.
- spaCy inference is single-threaded (`max_workers=1`) in the engine.
- No global `random` state is touched by the generator or engine.
- The benchmark test suite asserts: generator determinism, TW_ID
  checksum invalidity (100% of generated values), split stability,
  and scoring correctness on hand-crafted mini-cases.

---

# 8. Report Format

`bench_reports/benchmark_report.json` (gitignored):

```json
{
  "seed": 42,
  "generated_at": "...",
  "corpus": {"positive": N, "negative": M, "injection": K},
  "calibrated_thresholds": {"PERSON": 0.5, "...": 0.55},
  "aggregate": {"tp": 0, "fp": 0, "fn": 0, "precision": 0.0,
                "recall": 0.0, "f1": 0.0},
  "per_entity": {
    "PERSON": {"tp": 0, "fp": 0, "fn": 0, "precision": 0.0,
               "recall": 0.0, "f1": 0.0, "ioU_ge_0_5": 0.0}
  },
  "acceptance": {"passed": true, "details": {"...": {"actual": 0.0,
                 "required": 0.9, "passed": true}}}
}
```

A markdown human-readable table is generated alongside.
