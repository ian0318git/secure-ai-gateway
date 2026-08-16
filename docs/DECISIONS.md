# Secure AI Gateway — Decision Log

Records of significant decisions and the reason for each.
Reverse-chronological.

---

## 2026-08-16 — M1 Planning Decisions

- **Chinese NLP backend: spaCy `zh_core_web_lg`** (user decision).
  Chosen over `md` and Stanza: `lg` = 575MB model, OntoNotes 18
  labels (PERSON/ORG/GPE/LOC), best accuracy among spaCy zh models;
  Stanza rejected for the PoC (extra dependency, slower; may be
  revisited after M1 if NER floors are not met).
- **Dependency pins** (verified against PyPI metadata):
  `presidio-analyzer==2.2.364` requires
  `spacy>=3.4.4,!=3.7.0,<4.0.0`; `zh-core-web-lg==3.6.0` requires
  `spacy>=3.6.0,<3.7.0`. Chosen pair: `spacy==3.6.1` +
  `zh-core-web-lg==3.6.0`. Installation order matters: pin spacy
  BEFORE installing presidio so pip does not resolve spacy 3.7/3.8.
  Fallback pair if 3.6.1 fails: `spacy==3.7.1` + `zh-core-web-lg==3.7.0`
  (presidio excludes only 3.7.0 exactly).
- **Chinese lemma limitation**: spaCy Chinese produces no lemmas, so
  presidio's `LemmaContextAwareEnhancer` is ineffective for zh.
  Replaced by a custom deterministic column-header context boost
  (pure rules, unit-testable).
- **English-only fallback prohibited**: the AnalyzerEngine is
  configured with `supported_languages=["zh"]` and NO default
  English recognisers; all recognisers are custom zh variants
  (including EMAIL/PHONE/CREDIT_CARD). An engine test asserts
  `supported_languages == ["zh"]`.
- **Injection semantics**: instruction finding -> block the whole
  request; document-cell finding with severity >= 3 -> block the
  whole request (fail closed); severity < 3 -> drop the cell and flag
  it in the report.
- **Benchmark scoring**: format entities require exact span + same
  type; NER entities require >= 1 char overlap + same type (IoU >= 0.5
  reported as a secondary metric only). Greedy one-to-one matching in
  descending confidence order. Micro-aggregate; thresholds calibrated
  on the train split only; final metrics from the held-out test split.
  Fixed seed 42. See `docs/BENCHMARK.md` (normative).
- **TW IDs**: checksum-invalid values are still detected and flagged
  (with a `checksum_valid` flag). The benchmark generator asserts
  checksum invalidity by construction — never rejected.
- **M1 has no CLI**: entry point is the `process_file()` API plus
  tests; the interactive demo arrives at M3.

## 2026-08-16 — M0 Decisions (recorded at v0.3 approval)

- **Project name**: secure-ai-gateway (user decision).
- **License**: Apache-2.0 (user decision).
- **Detection acceptance**: aggregate recall >= 90% / precision >= 80%
  plus per-entity floors (PERSON / ADDRESS / identifier entities:
  recall >= 85%, precision >= 80%); F1 reported (user decision).
- **Session scope**: one gateway invocation (one instruction + one
  document) = one session; token mappings destroyed at session end.
- **Policy**: static, code-level, default DENY — secrets block the
  request, PII is tokenised, non-required columns are dropped.
- **Response violations**: blocked (fail closed); unknown or
  hallucinated token values are never restored.
- **Prompt injection**: deterministic/pattern-based detector
  (no LLM-based detection).
- **Docker**: optional, CI-only in the PoC.
- **Prompt caching**: MUST be disabled for all provider calls.
- **Data**: PoC uses synthetic data only.
