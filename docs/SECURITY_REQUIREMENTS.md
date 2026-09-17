# Secure AI Gateway — Security Requirements

Version: 0.3
Status: Draft

---

# SR-001 — External Data Boundary

Raw confidential or restricted data MUST NOT be sent to an external
LLM unless explicitly permitted by policy.

---

# SR-002 — Token Mapping Protection

Token mappings MUST remain inside the trusted environment.

Token mappings MUST NOT appear in:

- LLM requests
- LLM responses
- external API calls
- client-side code
- application logs
- Git repositories

---

# SR-003 — Sensitive Data Detection

The gateway MUST inspect input data for known sensitive data types
before external transmission.

---

# SR-004 — Secret Detection

API keys, passwords, credentials, tokens, and other secrets MUST be
detected and blocked or protected before external transmission.

---

# SR-005 — Data Minimisation

The gateway SHOULD remove data that is not required for the requested
LLM task.

---

# SR-006 — Untrusted Document Content

Uploaded documents MUST be treated as untrusted content.

Document content MUST NOT automatically override system or security
instructions.

---

# SR-007 — Prompt Injection

The gateway MUST consider:

- direct prompt injection
- indirect prompt injection through documents

---

# SR-008 — Response Validation

LLM responses MUST be treated as untrusted.

Responses MUST be inspected before being returned to the user.

---

# SR-009 — Logging

Sensitive data MUST NOT appear in application logs.

Secrets MUST NOT appear in logs.

---

# SR-010 — Fail Closed

Security-control failures MUST NOT result in raw data being sent to
an external LLM.

---

# SR-011 — Credentials

LLM API credentials MUST NOT be:

- hard-coded
- committed to Git
- exposed to clients
- included in prompts
- written to logs

---

# SR-012 — Authentication

The PoC may use simplified authentication.

The architecture MUST allow proper authentication to be introduced
during MVP.

---

# SR-013 — Authorisation

Policy enforcement MUST occur on the trusted server side.

Client-side checks MUST NOT be considered a security boundary.

---

# SR-014 — Synthetic Data

The PoC MUST use synthetic data only.

No real company confidential data may be used.

---

# SR-015 — Detection Accuracy

The PoC MUST measure sensitive-data detection performance using a
synthetic benchmark dataset.

Initial acceptance targets (aggregate):

- PII recall >= 90%
- PII precision >= 80%

Per-entity floors for high-risk entities:

- PERSON, ADDRESS, and identifier entities (including Taiwan ID-like
  values): recall >= 85%, precision >= 80%

F1 score MUST also be reported.

The benchmark SHOULD include:

- Chinese names
- Chinese addresses
- synthetic Taiwan ID-like identifiers
- phone numbers
- email addresses
- company names
- English names
- English addresses
- synthetic customer identifiers
- synthetic employee identifiers

The test dataset MUST contain synthetic values only.

A high recall achieved by excessive false positives MUST NOT be
considered sufficient.

The detection system must maintain sufficient precision to preserve
the usefulness of sanitised data for downstream LLM analysis.

Benchmark results SHOULD be reported separately for major entity
types where practical.

Benchmark methodology:

- span-level vs entity-level scoring MUST be defined before implementation
- the dataset MUST contain at least 1000 records per major entity class
- a fixed train/test split and a fixed random seed MUST be used
- results MUST be reported per major entity type
- synthetic Taiwan ID-like values MUST use checksum-invalid patterns so
  they cannot collide with real identifiers

---

# SR-016 — Auditability

Security-relevant decisions SHOULD generate audit events containing:

- request ID
- timestamp
- user identifier or pseudonymous identifier
- policy decision
- security event
- processing result

Audit events MUST NOT contain raw confidential payloads.

---

# SR-017 — No Silent Security Downgrade

If a security control cannot operate correctly, the system MUST NOT
silently bypass the control.

The request should be blocked or require explicit administrative
handling.

---

# SR-018 — Testability

Each security requirement SHOULD have one or more automated tests.

Security requirements must be traceable to:

Requirement
    ->
Threat
    ->
Design control
    ->
Implementation
    ->
Test

---

# SR-019 — Token Lifecycle

PoC token mappings MUST be scoped to a single session. For the PoC, a
session is one gateway invocation (one instruction and one document
processed end-to-end).

Mappings MUST be destroyed at session end: released from scope with no
persistence.

Cross-session token identity persistence MUST NOT be implemented unless
explicitly approved.

Explicit approval was granted 2026-08-18 for an OPT-IN encrypted
persistent store (M6, SR-026): persistence activates only with
`--vault-store PATH` plus a valid `VAULT_MASTER_KEY`. Without the
flag, this requirement's behaviour is unchanged (session-only).
The persistent layer is a token_for supplier only; restore() remains
session-scoped (SR-026).

---

# SR-020 — Chinese NLP Configuration

The PoC MUST explicitly configure and document the Chinese NLP backend.

Claude Code MUST NOT silently fall back to an English-only NLP model
for Chinese PII detection.

---

# SR-021 — Untrusted LLM Output

LLM-generated content MUST be treated as untrusted data and MUST pass
through response validation before being returned to the user.

---

# SR-022 — Instruction Channel Protection

User-provided instruction text is protected input.

Raw identifiers, secrets, or confidential values in the user's
instruction MUST NOT reach an external LLM without passing through the
same detection, tokenisation, and policy pipeline as document content.

---

# SR-023 — Opaque Token Identifiers

Token identifiers MUST be randomly generated per session.

Sequential or predictable token identifiers MUST NOT be used: they allow
the LLM or an attacker to infer entity order and count.

---

# SR-024 — Policy Default Deny

The policy engine MUST default to DENY.

The PoC policy MUST define a disposition for every entity class:

- secrets -> block the entire request (fail closed)
- PII -> tokenise
- columns not required by the task -> drop
- all other content -> allow after tokenisation

---

# SR-025 — Document Encoding and Formula Safety

The gateway MUST detect and normalise non-UTF-8 document encodings
(GBK/Big5/UTF-16) before detection, so that encoded content cannot
evade PII detection through mojibake.

Spreadsheet cells beginning with formula prefixes (=, +, -, @) MUST be
neutralised or blocked before processing.

---

# SR-026 — Persistent Token Store Protection

The opt-in persistent token store (M6, `--vault-store PATH`) MUST
protect token mappings at rest and fail closed:

- mappings at rest MUST be authenticated-encrypted (Fernet:
  AES-128-CBC + HMAC-SHA256)
- the master key comes from the `VAULT_MASTER_KEY` environment
  variable only (urlsafe base64 of 32 random bytes); it MUST never be
  hard-coded, committed, or logged
- a missing or invalid key MUST fail closed before any session runs
- a tampered, truncated, or incompatible store MUST fail closed
  (never a silent reset or partial load)
- the store file MUST never be committed to Git (`.gitignore`)
- the persistent layer is a token_for supplier only: restore() stays
  session-scoped, so a token issued in an earlier session is never
  restored (fail closed, response guard step 1)

---

# SR-027 — Local Debug Dashboard (`tools/dashboard`)

The local debug dashboard is a **development tool, not a security
control**. It exists to make the gateway's behaviour inspectable
(stage-by-stage dispositions, and the complete raw → token mapping)
and it is authorised only under the constraints below.

This requirement **relaxes SR-002 and SR-019 for this tool**, and the
relaxation is recorded deliberately rather than inferred:

- **SR-002 ("client-side code")** — the dashboard serves token
  mappings to a browser. Permitted **only** because the page is served
  over loopback from the operator's own machine and the mappings in
  question are that same operator's own session data.
- **SR-019 ("mappings MUST be destroyed at session end")** — the
  recorder holds a copy that outlives `Session.run`, so a running
  dashboard's mapping lifetime is the process lifetime. The packaged
  gateway (`src/secure_ai_gateway`) is unaffected: `vault.clear()`
  still destroys the real mapping on every path. This is a genuine
  relaxation of a stated guarantee.

The dashboard MUST:

- bind loopback only (`127.0.0.1`; never a wildcard address)
- require a per-run 128-bit path token; a missing or wrong token MUST
  return 404, never 403 (a probe must not confirm the service exists)
- reject any `Host` outside the loopback allow-list, and any `Origin`
  that is not its own
- send no CORS header on any response, including `OPTIONS`
- send `no-store` on every response and serve GET/HEAD only
- never write to disk: no dump, cache, report, or exported mapping
- never call `log_event`; it may only READ the sanitised log stream
  through a `logging.Handler`
- keep `payload["report"]` byte-identical to `MetadataReport.to_dict()`,
  and confine raw values and tokens to the paths declared in
  `tools/dashboard/model.RAW_OR_TOKEN_PATHS`
- render with `createElement`/`textContent` only, under a nonce-based
  CSP, with no external resource of any kind
- never see provider credentials (it wraps the provider interface, not
  the transport, so `x-api-key` is unreachable)
- use synthetic data only (SR-014 applies unchanged)

The tool MUST NOT be treated as a control in any threat-mitigation
claim. Its documented residuals (browser extensions, terminal
scrollback, loopback not being per-user isolation, port forwarding, no
TLS, non-zeroised memory, unbounded growth) are recorded in
`DECISIONS.md` (2026-09-18, D12) and in the tool's README.
