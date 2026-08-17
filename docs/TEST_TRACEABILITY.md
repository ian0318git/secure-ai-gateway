# Test Traceability Matrix — M5 Security Test Suite

M5 (docs/POC_PLAN.md §M5) requires tests for the 20 items below.
Every item maps to ≥ 1 passing test (SR-018 traceability). M5 is an
additive milestone: M1–M4 tests are untouched; rows marked "existing"
point at tests written in earlier milestones, rows marked "new (M5)"
at the M5 suite (tests/security/test_m5_*).

Verification: `grep -rn "<test>" tests/` resolves every reference.

| # | M5 item (POC_PLAN) | CLAUDE.md §10 | SR | Control | Tests (existing → new M5) |
|---|---|---|---|---|---|
| 1 | Raw PII leakage | PII detection | SR-002/008 | detection + policy + response scan | existing: `tests/security/test_m3_llm.py::test_no_raw_pii_on_wire`, `tests/unit/test_response_guard.py::TestSensitiveScan::test_raw_pii_blocked`, `tests/security/test_m4_response.py::TestSensitiveResponsesBlocked::test_raw_pii_in_response_blocks`; new: `tests/security/test_m5_fail_closed.py::TestFailClosedSweep` (vault/empty-text assertions) |
| 2 | Email leakage | raw-data leakage | SR-002 | EMAIL recogniser + response scan | existing: `tests/unit/test_recognizers.py` (EMAIL); new: `tests/security/test_m5_response_injection.py::TestEmailLeakChannel::test_raw_email_in_response_blocks` |
| 3 | Secret leakage | secret leakage | SR-002/011 | policy _BLOCK_TYPES + response secret scan | existing: `tests/security/test_m3_llm.py::test_document_secret_blocks_and_provider_never_called`, `tests/security/test_m4_response.py::TestSensitiveResponsesBlocked::test_secret_in_response_blocks`; new: `tests/security/test_m5_fail_closed.py::TestFailClosedSweep::test_fail_closed[secret_span]` |
| 4 | Token mapping leakage | token mapping isolation | SR-002/009/019 | vault isolation + log/report rules | existing: `tests/security/test_tokens.py::test_logs_contain_no_raw_and_no_token`, `tests/security/test_m3_llm.py::test_every_token_on_wire_is_a_live_reverse_map_key`, `tests/security/test_m4_response.py::TestFailClosedAccounting::test_report_never_carries_response`; new: `tests/security/test_m5_audit.py::TestNoRawInEvents` |
| 5 | Direct prompt injection | prompt injection | SR-010 | detector + policy | existing: `tests/unit/test_injection.py::test_known_patterns_detected`; new: `tests/security/test_m5_policy_bypass.py::TestDirectInjectionNarrative`, `tests/security/test_m5_fail_closed.py::TestFailClosedSweep::test_fail_closed[instruction_injection]` |
| 6 | Indirect prompt injection | indirect prompt injection | SR-010/021 | detector (doc cells) + response guard | new: `tests/security/test_m5_indirect_injection.py` (TestIndirectInjectionE2E, TestNovelPhrasingResidual, TestMarkerInDataPinned) |
| 7 | Response leakage | response leakage | SR-021 | response guard (scan + injection) | existing: `tests/security/test_m4_response.py::TestSensitiveResponsesBlocked::test_leaked_known_value_blocks`; new: `tests/security/test_m5_response_injection.py::TestHostileProviderBlocked`, `tests/security/test_m5_policy_bypass.py::TestResponseChannel` |
| 8 | Log leakage | log leakage | SR-009 | log_event allow-list | existing: `tests/security/test_threats.py::test_log_events_never_carry_raw_values`, `tests/security/test_tokens.py::test_log_event_rejects_token_and_mapping_keys`; new: `tests/security/test_m5_audit.py::TestNoRawInEvents` |
| 9 | Policy bypass | policy bypass | SR-010 | fail-closed policy engine | new: `tests/security/test_m5_policy_bypass.py` (all five channel classes) |
| 10 | Fail-open behaviour | fail-open behaviour | SR-010/017 | session + guard fail closed | existing: `tests/unit/test_session.py::test_blocked_session_never_calls_provider`; new: `tests/security/test_m5_fail_closed.py::TestFailClosedSweep` (22-row property sweep) |
| 11 | File size/resource limits | resource limits | SR-010 | parser limits + xlsx preflight | existing: `tests/unit/test_parsers_xlsx.py::test_decompressed_size_limit`, `tests/security/test_threats.py::test_decompressed_size_limit_blocks`; new: `tests/security/test_m5_fail_closed.py::TestFailClosedSweep::test_fail_closed[row_limit]`, `[cell_char_limit]`, `[zip_bomb]` |
| 12 | Token lifecycle violations | token lifecycle | SR-019 | session-owned vault, cleared on every path | existing: `tests/security/test_tokens.py::test_clear_destroys_mappings`, `test_blocked_session_leaves_no_state`, `tests/unit/test_session.py::test_m2_mode_no_provider_still_clears_vault`, `tests/security/test_m4_response.py::TestFailClosedAccounting::test_vault_destroyed_after_response_block`; new: `tests/security/test_m5_fail_closed.py` (vault-empty assertion per row) |
| 13 | Chinese PII detection | Chinese PII detection | SR-013 | Presidio + Chinese backend + regex recognisers | existing: `tests/unit/test_parsers_csv.py::test_gbk_encoded_chinese`, `tests/security/test_threats.py::test_gbk_csv_chinese_name_still_detected`; new: `tests/security/test_m5_benchmark_evidence.py::TestBenchmarkEvidence` (Chinese corpus report re-check, per-entity floors) |
| 14 | Detection precision/recall/F1 | precision/recall/F1 | SR-015 | normative check() re-derivation | new: `tests/security/test_m5_benchmark_evidence.py::TestBenchmarkEvidence::test_committed_report_passes_normative_check`, `test_aggregate_thresholds_are_the_documented_floors`, `test_per_entity_thresholds_are_the_documented_floors` |
| 15 | Instruction-channel leakage | raw identifiers in instruction | SR-002/022 | detect(instruction) + protect_instruction | existing: `tests/security/test_tokens.py::test_instruction_pii_tokenised`, `test_instruction_secret_blocks_request`, `tests/security/test_m3_llm.py::test_raw_instruction_identifier_absent_and_token_shared`; new: `tests/security/test_m5_policy_bypass.py::TestChannelDisclosureAttempts`, `tests/security/test_m5_fail_closed.py::TestFailClosedSweep::test_fail_closed[instruction_secret]` |
| 16 | Unknown/hallucinated token responses | unknown tokens | SR-021 | guard token validation (pre-restore) | existing: `tests/security/test_m4_response.py::TestUnknownTokens`; new: `tests/security/test_m5_fail_closed.py::TestFailClosedSweep::test_fail_closed[guard_unknown_token]`, `tests/security/test_m5_indirect_injection.py::TestNovelPhrasingResidual::test_obedient_provider_invents_token_blocks` |
| 17 | Token-namespace collision | token namespace | SR-019 | bounded retry → TokenCollisionError | existing: `tests/unit/test_vault.py::test_collision_retries_then_fails_closed`, `tests/security/test_tokens.py::test_generated_tokens_never_match_reserved_regex`; new: `tests/security/test_m5_fail_closed.py::TestFailClosedSweep::test_fail_closed[token_collision_exhaustion]` |
| 18 | Encoding handling (GBK/UTF-16) | encoding | SR-025 | strict decode, fail closed | existing: `tests/unit/test_encoding.py::test_gbk`, `tests/security/test_threats.py::test_utf16_csv_email_detected`, `test_utf16_xlsx_fails_closed`; new: `tests/security/test_m5_fail_closed.py::TestFailClosedSweep::test_fail_closed[utf16_xlsx]` |
| 19 | Spreadsheet formula injection | formula injection | SR-010 | formula neutralisation (parsers) | existing: `tests/unit/test_parsers_xlsx.py::test_formula_cell_never_enters_pipeline`, `tests/unit/test_parsers_csv.py::test_formula_cell_neutralised`, `tests/security/test_threats.py::test_formula_prefix_never_reaches_detection` |
| 20 | Policy default-deny paths | policy default-deny | SR-010 | template allowlist + column allowlist | existing: `tests/unit/test_policy.py`; new: `tests/security/test_m5_fail_closed.py::TestFailClosedSweep::test_fail_closed[template_none]`, `[template_admin_panel]`, `[nothing_to_send]`, `[secret_column_header]`, `tests/security/test_m5_policy_bypass.py::TestTemplateChannel` |

## M5 acceptance (DECISIONS 2026-08-17)

1. Every one of the 20 items above maps to ≥ 1 passing test recorded
   in this matrix (all references resolvable by grep).
2. Response-side injection detection blocks with
   `response:injection:<CATEGORY>`; a clean analysis response delivers
   (clean-control FP = 0 — `test_clean_prose_delivers` unit + e2e).
3. Every single control-failure path → `is_blocked()` + empty
   response; failures before the provider → zero provider calls;
   vault destroyed on every path (`TestFailClosedSweep`, 22 rows).
4. Security events carry `request_id` + `reason` (where applicable) +
   timestamp, never raw/secrets/tokens (`tests/security/test_m5_audit.py`).
5. The committed benchmark report passes the normative re-check; the
   thresholds are pinned as documented floors and never lowered
   (`tests/security/test_m5_benchmark_evidence.py`).
6. Existing M1–M4 suites remain green and untouched (full suite
   passes with M5 commits additive).

## Limitations (recorded, pinned)

- **No user identifier in audit events**: the PoC has no auth layer,
  so events are request-scoped, not user-scoped (pinned in
  `tests/security/test_m5_audit.py::TestUserIdentifierLimitation`).
  An identity layer is an MVP concern.
- **Novel-phrasing residual**: an injection phrased outside the 13
  pattern tables passes the input detector and reaches the provider
  as data; the response side is the second net (marker echo / unknown
  token / classic phrasing all block — `TestNovelPhrasingResidual`).
  Recorded in POC_PLAN §10; not solved in this milestone.
- **Marker-shaped data**: a literal `<<<INSTRUCTION>>>` in a document
  cell passes as data by design (data, not instructions); echoing it
  is blocked by the marker-echo check (pinned in
  `TestMarkerInDataPinned`). Zero changes to detector/request builder.
- **Quoting an attack is blocked**: a response that quotes or
  analyses an attack triggers the mirror rule (conservative; no LLM
  judge — CLAUDE.md §6.10/6.11). Pinned in the guard unit suite.
- **NER context merging** (M4, unchanged): a restored value merged
  with adjacent text by NER causes a conservative false-positive
  block — acceptable, fail closed.

## M6 — Persistent token store (DECISIONS 2026-08-18, SR-019/026)

| # | Threat | Requirement | Control | Verification |
|---|---|---|---|---|
| 1 | At-rest disclosure of token mappings (T-I10) | SR-026 | Fernet authenticated encryption; env-only key | `tests/security/test_m6_persistent_store.py::TestAtRestProtection::test_store_file_is_opaque_ciphertext` (byte-level: no raw, no token, no JSON structure); `tests/unit/test_persistent_vault.py::TestKeyLoading` (7 key tests) |
| 2 | Store tampering (T-T05) | SR-026 | Fernet HMAC + version/shape validation + atomic write | `test_tampered_ciphertext_fails_closed`, `test_truncated_file_fails_closed`, `test_empty_file_fails_closed`, `test_wrong_key_fails_closed`, `test_non_json_plaintext_fails_closed`, `test_wrong_version_fails_closed`, `test_bad_mappings_shape_fails_closed` |
| 3 | Store master key compromise (T-I11) | SR-011/026 | env-var-only key, never logged/committed | `tests/unit/test_cli_vault_store.py::test_vault_store_missing_key_exits_2`, `test_vault_store_invalid_key_exits_2`; `test_vault_store_open_log_has_no_content` (no raw, no `mappings` key in log) |
| 4 | Store replacement / rollback (T-T06) | SR-026 | (residual: filesystem access control; no fingerprint — DECISIONS D6) | design review; residual recorded |
| 5 | Store growth exhaustion (T-D04) | — | (residual: no cap/compaction — DECISIONS D6) | design review; residual recorded |
| 6 | Previous-session token in response (D1) | SR-019/021/026 | restore() stays session-scoped; store is token_for supplier only | `tests/security/test_m6_persistent_store.py::TestCrossSessionSemantics::test_previous_session_token_in_response_blocks` (`response:unknown_token`), `test_same_session_token_delivers`, `test_pipeline_factory_shared_store_reuses_tokens` |
| 7 | Cross-session identity reuse (opt-in) | SR-026 | `--vault-store` + PersistentSessionVault token_for order | `tests/unit/test_cli_vault_store.py::test_vault_store_reuses_tokens_across_runs` (store decrypted to prove same token); `tests/unit/test_persistent_vault.py` (reuse without rewrite, collision guard, clear-keeps-store) |
| 8 | Store file never committed | SR-002/026 | `.gitignore` | `tests/security/test_m6_persistent_store.py::TestRepoHygiene::test_gitignore_excludes_vault_stores` |
| 9 | Blocked session leaves store unchanged | SR-010/026 | commits only after policy pass | `tests/unit/test_cli_vault_store.py::test_vault_store_blocked_session_leaves_store_unchanged` (byte comparison); `test_vault_store_tampered_fails_closed` (fail closed at startup, exit 2, no session ran) |

## M6 acceptance (DECISIONS 2026-08-18)

1. Full suite green: 752 tests (706 pre-M6 + 46 new; zero existing
   tests modified).
2. At-rest opacity: the store file bytes contain no raw value, no
   token, and no JSON structure (`test_store_file_is_opaque_ciphertext`).
3. Every store failure path fails closed (tamper / truncate / empty /
   wrong key / non-JSON / wrong version / wrong shape), and every key
   failure fails closed (missing / invalid env var) — never a silent
   reset or partial load.
4. D1 pinned: a previous-session token in a response is still
   `response:unknown_token`; same-session restoration still delivers.
5. Opt-in semantics pinned: without `--vault-store`, default
   session-only behaviour is unchanged (706 pre-M6 tests untouched
   and green).
