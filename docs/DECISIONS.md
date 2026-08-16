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
  `spacy>=3.4.4,!=3.7.0,<4.0.0`; `zh_core_web_lg==3.6.0` requires
  `spacy>=3.6.0,<3.7.0`. Chosen pair: `spacy==3.6.1` +
  `zh_core_web_lg==3.6.0`. Installation order matters: pin spacy
  BEFORE installing presidio so pip does not resolve spacy 3.7/3.8.
  Fallback pair if 3.6.1 fails: `spacy==3.7.1` + `zh_core_web_lg==3.7.0`
  (presidio excludes only 3.7.0 exactly).
- **Dependency pins — FINAL** (2026-08-16, recorded after install
  failure): `spacy==3.6.1` + `thinc==8.1.12` have no cp312 wheels;
  thinc 8.1.12 builds from source via Cython and the build failed
  (`Cython.Compiler.Errors.CompileError: thinc/backends/numpy_ops.pyx`,
  no C toolchain on this machine). The planned fallback pair became
  the primary: **`spacy==3.7.2` + `zh_core_web_lg==3.7.0`** (spacy 3.7.2
  depends on thinc>=8.2.2, which has cp312 wheels; presidio allows it;
  model 3.7.0 requires spacy>=3.7.0,<3.8.0).
- **Model distribution**: `zh_core_web_lg` (~575MB) is NOT published
  to PyPI (PyPI per-file size limit is 100MB). Large spaCy model
  wheels are hosted on the explosion/spacy-models GitHub releases;
  pyproject references the wheel URL directly. This was discovered at
  install time (resolver error "package not found in registry").
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
- **presidio 2.2.364 API (spike-verified 2026-08-16)**: the
  AnalyzerEngine constructor no longer accepts `default_recognizers`
  or `allow_overlap`. The zh-only engine is built with a custom
  `RecognizerRegistry(supported_languages=["zh"])` +
  `add_nlp_recognizer()`; presidio only loads its predefined
  (English) recognisers when the registry is EMPTY, so a registry
  containing just the spaCy zh NER recogniser never loads them.
  Overlapping spans of different types are kept by default
  (`remove_duplicates` only collapses same-type containment).
  `supported_languages` is an attribute, not a method.
- **NER label mapping**: presidio's SpacyRecognizer filters NER labels
  against the mapping VALUES and emits the raw spaCy label as the
  entity type — so the mapping is IDENTITY for the four adopted labels
  (PERSON/GPE/LOC/ORG) with an explicit ignore list for DATE/TIME/
  MONEY/PERCENT/CARDINAL/NORP/...; DATE etc. are filtered out, never
  crash the gateway entity-type conversion.
- **Pattern validation side effect**: presidio sets MAX_SCORE (1.0)
  when `validate_result` returns True, overriding the pattern score.
  Recognisers whose validation is a no-op (TW_ID, BANK_ACCOUNT) ship
  WITHOUT validate_result to preserve their designed scores (0.8 /
  0.55 + context boost). Functional validators (Luhn, entropy, JWT
  header, person deny-list) stay, so validated matches legitimately
  score 1.0.
- **Context enhancement replaced**: `LemmaContextAwareEnhancer` cannot
  work for zh (no lemmas) and is replaced by an explicit no-op
  enhancer; column-header context boost (context.py) is the only
  context mechanism.
- **Spike observation**: zh_core_web_lg PERSON recall is partial
  (e.g. `業務員王小明與...張太太簽約。` yields PERSON only for
  張). The surname fallback recogniser and the benchmark's honest
  measurement exist precisely for this; expected risk #1 in the M1
  plan.
- **run_id determinism**: the benchmark report's run_id is derived
  from a corpus fingerprint (sha256 of the generated records), NOT
  wall-clock time, so two runs produce byte-identical reports
  (BENCHMARK.md §7).
