# Secure AI Gateway — Final PoC Report

Version: 1.4
Date: 2026-09-17
Milestones covered: M0 – M6 (all complete)
Tag: v0.4.0

---

# 1. Summary

The Secure AI Gateway PoC is complete end-to-end. The gateway detects
sensitive data (including Chinese PII), tokenises protected
identifiers, enforces a default-deny policy, keeps token mappings
inside the trusted environment, and — opt-in only — persists token
identities in a Fernet-encrypted store.

Final status:

- 753 automated tests green (571 unit / 153 security / 29 benchmark)
- detection benchmark PASS (normatively re-checked)
- 66 commits; milestones M0–M6 complete and pushed
- `[REVIEW_PASSED]` at every milestone (evidence-based review)

---

# 2. Milestone Acceptance

| M | Deliverable | Status | Evidence |
|---|---|---|---|
| M0 | Design & security review (CLAUDE.md, DESIGN, SR, threat model, plan) | PASS | design package approved before any implementation; `8bd47d5 docs: add v0.3 design package (M0 complete)` |
| M1 | Detection — Presidio + Chinese NLP, custom/deterministic recognisers, injection detector, static policy, minimisation, encoding, formula safety, limits | PASS | benchmark: recall 0.9738 / precision 0.8458 / F1 0.9053 (floors 0.90/0.80); per-entity floors all PASS (see §4); policy default-deny + encoding + formula pins in unit/security tests |
| M2 | Tokenisation — session-scoped vault, random opaque tokens, mapping isolation, collision handling | PASS | round-trip, non-sequential tokens, namespace-collision, no persistence across sessions — `tests/unit/test_vault.py`, `tests/security/test_tokens.py` |
| M3 | LLM integration — provider interface, protected request builder, response parser | PASS | raw PII/secrets/mappings absent from requests; instruction identifiers sanitised; provider error bodies never logged; caching disabled — `tests/security/test_m3_llm.py` |
| M4 | Response protection — scan, unknown-token detection, task compliance, controlled restoration | PASS | violations fail closed with `response:<category>`; unknown tokens never restored — `tests/security/test_m4_response.py` |
| M5 | Security test suite — 20 POC_PLAN items, fail-closed sweep, audit events, normative benchmark re-check | PASS | full traceability matrix (`docs/TEST_TRACEABILITY.md`), 22-row fail-closed sweep, clean-control FP = 0 |
| M6 | Persistent token store (opt-in, approved 2026-08-18) — Fernet-encrypted JSON, env-only key, fail closed, supplier-only | PASS | at-rest opacity, 8 store + 2 key failure paths fail closed, previous-session token → `response:unknown_token` — `tests/security/test_m6_persistent_store.py` |

---

# 3. Security Acceptance Criteria (POC_PLAN §6)

All 18 criteria are satisfied; each maps to at least one automated
test (see `docs/TEST_TRACEABILITY.md`):

- Raw PII not present in LLM requests — PASS
- Token mappings not present in LLM requests — PASS
- API keys not present in prompts or logs — PASS
- Sensitive information not written to logs — PASS
- Direct prompt injection tests pass — PASS
- Indirect prompt injection tests pass — PASS
- Response leakage tests pass — PASS
- Policy failures default to deny — PASS
- Token restoration works correctly — PASS
- PII detection recall >= 90% — PASS (0.9738)
- PII detection precision >= 80% — PASS (0.8458)
- F1 reported — PASS (0.9053)
- Chinese NLP backend explicitly configured and documented — PASS
  (zh_core_web_lg + deterministic recognisers, DESIGN §9/§10)
- Token mappings session-scoped and destroyed at session end — PASS
  (default; M6 opt-in persistence is an approved exception)
- Raw identifiers in the user instruction do not reach the LLM — PASS
- Policy defaults to deny — PASS
- PERSON/ADDRESS/ID per-entity floors met — PASS (see §4)
- No real company confidential data used — PASS (synthetic only)

---

# 4. Detection Benchmark (committed report, normatively re-checked)

Corpus: 12,250 synthetic samples — 9,550 positive / 2,500 negative /
200 injection-control. Fixed seed; span-level scoring (IoU >= 0.5).

| Metric | Required | Actual | Status |
|---|---|---|---|
| Aggregate recall | >= 0.90 | 0.9738 | PASS |
| Aggregate precision | >= 0.80 | 0.8458 | PASS |
| Aggregate F1 | reported | 0.9053 | PASS |
| PERSON recall / precision | >= 0.85 / 0.80 | 0.8525 / 0.8475 | PASS |
| ADDRESS recall / precision | >= 0.85 / 0.80 | 1.0 / 1.0 | PASS |
| TW_ID recall / precision | >= 0.85 / 0.80 | 1.0 / 1.0 | PASS |
| CUSTOMER_ID / EMAIL / PHONE / EMPLOYEE_ID | >= 0.85 / 0.80 | 1.0 / 1.0 | PASS |

Per-entity sample sizes (positive spans): PERSON 339, ADDRESS 248,
TW_ID 210, CUSTOMER_ID 208, EMAIL 219, PHONE 226, CREDIT_CARD 67.
Entity types with no benchmark samples (LOCATION, ORGANIZATION,
BANK_ACCOUNT, PASSWORD, PRIVATE_KEY, TOKEN_PATTERN) report F1 = 0.0
as a convention; they are not part of the acceptance floors.

The committed report is re-verified by
`scripts/check_acceptance.py` (imports the check, re-derives every
metric from raw tp/fp/fn, never trusts the report's own verdict) —
pinned in `tests/security/test_m5_benchmark_evidence.py`.

---

# 5. Test Inventory

| Suite | Count |
|---|---|
| `tests/unit/` | 571 |
| `tests/security/` | 153 |
| `tests/benchmark/` (marked `benchmark`, slow) | 29 |
| **Total** | **753** |

Run: `.venv/bin/pytest tests -q` (full suite, ~4 s excluding
benchmark), plus `.venv/bin/pytest -m benchmark tests/benchmark/`
for the detection benchmark.

---

# 6. Technology Stack

Runtime dependencies (pinned in `pyproject.toml`), all wheels — no
build toolchain required on the machine:

| Layer | Technology | Version | Role |
|---|---|---|---|
| Detection | Presidio Analyzer | 2.2.364 | PII detection framework (rule + ML recognisers) |
| Detection | spaCy + `zh_core_web_lg` | 3.7.2 (575MB model) | Chinese NLP backend wired into Presidio — person / org / address NER (SR-006: Presidio alone is not sufficient) |
| Detection | custom regex recognisers | built-in | deterministic format rules: TW ID numbers, phone numbers, Chinese name heuristics |
| Processing | charset-normalizer | 3.3.2 | encoding detection (mojibake hides PII — T-I09) |
| Processing | pandas / openpyxl | >=2.2 / >=3.1.2 | tabular data, .xlsx parsing |
| Processing | defusedxml | 0.7.1 | safe XML parsing (XXE protection) |
| Storage (M6) | cryptography (Fernet) | >=50,<51 | authenticated encryption for the opt-in persistent token store (SR-026) |

Deliberately absent: no web framework, no database, no
`requests`/`httpx` — the LLM call uses stdlib `urllib.request` behind
an https-only guard (SR-001); tokens come from stdlib `secrets`
(never sequential). This claim is scoped to the **gateway package**
(`src/secure_ai_gateway`): the local debug dashboard in `tools/`
does bring up a loopback HTTP server, built on stdlib `http.server`
with no third-party web framework and no new dependency (SR-027).
Dev tooling (all `[dev]` extras, enforced by the
pre-commit gate and CI): pytest 9.x, ruff, mypy, bandit, pip-audit.

### 6.1 What each technology does during a run

The same six pipeline steps as the README worked example, with the
technology doing the work:

1. **Parse** — `charset-normalizer` detects the file encoding (a wrong
   guess turns Chinese into mojibake and blinds the detectors);
   `openpyxl` + `defusedxml` open .xlsx safely (XXE protection);
   `unicodedata` unifies full/half-width forms (NFKC) so matching and
   token offsets stay consistent.
2. **Detect** — three detectors look in turn: the spaCy Chinese model
   marks words as person/org/address; Presidio organises that into an
   "is this PII" score, using context hints (ContextAwareEnhancer —
   e.g. a 客戶 header); custom regex recognisers match fixed formats
   (TW ID numbers, phone numbers) with 100% determinism.
3. **Policy** — the static policy engine (deterministic code, not an
   LLM) stamps each cell: secret -> block the whole request, PII ->
   tokenise, allowlisted column -> pass. The rules cannot be talked
   out of them (SR-024).
4. **Tokenise** — stdlib `secrets.token_hex` mints the random token
   (`CUSTOMER_4f8a21`); the mapping lives in memory only;
   `cryptography`/Fernet appears only for the opt-in M6 vault store
   (SR-026).
5. **Analyse** — stdlib `urllib.request` sends the HTTPS POST
   (https-only enforced, SR-001); the LLM sees tokens only.
6. **Restore** — the response guard validates every token in the reply
   against this session's vault (unknown -> refused,
   `response:unknown_token`), scans for leaked sensitive content, then
   substitutes the real names back (SR-010).

Every step is pinned by the 753-test suite; per-claim traceability in
`docs/TEST_TRACEABILITY.md`.

### 6.2 What is PII?

PII (personally identifiable information) is any data that identifies
a specific person or company. The gateway's entity catalogue
(`models.py` EntityType) covers: PERSON, ADDRESS, TW_ID, EMAIL, PHONE,
CUSTOMER_ID, EMPLOYEE_ID, CREDIT_CARD, LOCATION, ORGANIZATION,
BANK_ACCOUNT.

Treatment is tiered and hard-coded in the policy engine (never decided
by an LLM, never by the user):

- **PII** -> tokenised (`CUSTOMER_4f8a21`), restored only within the
  issuing session;
- **secrets** (SECRET, API_KEY, PASSWORD, JWT, PRIVATE_KEY) -> not PII
  but more sensitive: any occurrence blocks the whole request (fail
  closed, SR-024);
- **ordinary figures** (revenue `8.4M`, margin `32%`) -> neither, pass
  through untouched.

Which tier a value falls into is decided by the three-layer detector —
Presidio, the spaCy Chinese NLP backend, and custom regex recognisers
(§6).

---

# 7. Security Claims vs Evidence

| Claim | Control | Evidence |
|---|---|---|
| Raw PII never crosses the trust boundary | detection + tokenisation + policy (fail closed) | `test_no_raw_pii_on_wire`, fail-closed sweep |
| Secrets never cross the trust boundary | secret recognisers + block | `test_document_secret_blocks_and_provider_never_called` |
| Token mappings never appear in prompts/responses/requests/logs/Git | vault isolation + allow-listed logging + .gitignore | `test_logs_contain_no_raw_and_no_token`, `test_every_token_on_wire_is_a_live_reverse_map_key`, M6 at-rest opacity + repo-hygiene pins |
| Store at rest is opaque (M6) | Fernet authenticated encryption | `test_store_file_is_opaque_ciphertext` (byte-level) |
| Every store/key failure fails closed (M6) | VaultKeyError / VaultStoreError | 10 failure paths in unit + security suites; CLI exit 2 |
| Previous-session tokens are never restored (M6) | supplier-only persistent layer, session-scoped restore | `test_previous_session_token_in_response_blocks` |
| Prompt injection (direct + indirect) is mitigated | detector + separation + response validation + fail closed | 200/200 injection-control hits; zero clean-control FPs; e2e suites |
| Policy cannot be bypassed | server-side enforcement, default deny | 5-channel policy-bypass suite |
| LLM output is untrusted | response guard (scan, unknown token, marker echo) | `TestSensitiveResponsesBlocked`, `TestUnknownTokens`, `TestHostileProviderBlocked` |
| Audit events carry no raw content | log_event key rejection | `test_log_event_rejects_token_and_mapping_keys`, M5 audit battery |
| Detection accuracy is measured, not assumed | committed benchmark + normative re-check | `test_committed_report_passes_normative_check` |
| Chinese PII is detected, not assumed | zh_core_web_lg + deterministic recognisers + benchmark floors | GBK/UTF-16 tests, per-entity floors |

---

# 8. Recorded Residuals and Limitations

The PoC does NOT guarantee (POC_PLAN §10, THREAT_MODEL §6, DECISIONS):

- complete PII detection; complete prompt-injection detection
  (novel phrasing outside the 13-pattern table passes the input
  detector; the response side is the second net)
- protection against inference (tokenisation is pseudonymisation, not
  anonymity)
- security of the external LLM provider
- factual correctness of LLM-generated analysis
- production-grade anything: no SSO/RBAC, no HA, no KMS, no SIEM,
  no multi-tenancy, no compliance certification

M6 residuals (DECISIONS D6, all MVP candidates — OQ-003):

- unbounded store growth (no cap/compaction/retention — T-D04)
- single-process assumption (concurrent writers risk lost updates,
  never corruption)
- no key rotation (rotating orphans existing stores, fail closed)
- no store fingerprint (valid-store replacement undetectable — T-T06)
- no key derivation (raw 32-byte base64 env var used directly)

Other recorded limitations: audit events are request-scoped (no auth
layer); quoting an attack is conservatively blocked; NER context
merging can cause conservative false-positive blocks.

---

# 9. Reproduction

```bash
.venv/bin/pytest tests -q                          # full suite (753)
.venv/bin/pytest -m benchmark tests/benchmark/     # detection benchmark
.venv/bin/python scripts/check_acceptance.py       # normative re-check

# CLI smoke test (offline)
.venv/bin/python -m secure_ai_gateway.cli --file tmp/demo.csv \
    --instruction "請分析每位客戶的營收" --provider fake

# Persistent store (M6, opt-in — run twice, same tokens)
export VAULT_MASTER_KEY=$(.venv/bin/python -c \
    "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
.venv/bin/python -m secure_ai_gateway.cli --file tmp/demo.csv \
    --provider fake --vault-store tmp/demo.vault
```

---

# 10. Repository Facts

- 66 commits on `main` (M0 `8bd47d5` … latest docs); M0–M6 pushed,
  the 2026-09-18 dashboard commits are local
- tag `v0.4.0` (`536f0ba`, 53 commits) marks the end of the PoC
- synthetic data only; no real PII, secrets, or company documents
- dependencies kept minimal: cryptography added at M6 (the only
  runtime dependency beyond the detection stack)
