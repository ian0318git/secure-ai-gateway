# Secure AI Gateway

**English** | [繁體中文](README.zh-TW.md)

## Why this project

Employees often use personal AI accounts (ChatGPT, Claude, Gemini, ...)
to analyse business documents — and in doing so, upload confidential
files straight to an external provider's servers. No enterprise policy,
no approval, no minimisation: the raw document, PII included, crosses
the trust boundary untouched.

This project is a **data protection gateway** that sits between the
user and the external LLM. Before anything leaves your environment, the
gateway:

- **blocks** the whole request when secrets are found (API keys,
  passwords, JWTs, private keys, credentials);
- **tokenises** PII and identifiers (names, IDs, phones, emails,
  addresses, customer numbers) into random, session-scoped opaque
  tokens — the LLM never sees the raw values, and the token mapping
  never leaves the trusted environment;
- **drops** columns the current task does not require;
- **protects the instruction** the same way it protects the document:
  raw identifiers in the prompt are detected and tokenised too.

The LLM therefore receives a minimised, tokenised view of the data,
and a blocked request sends nothing at all.

### What this project does — and does not — solve

It substantially reduces the exposure of using personal AI accounts:

- ✅ Raw PII and secrets never reach the provider; the mapping stays
  inside the trusted environment and is destroyed at session end.
- ✅ The risk drops from "the whole confidential file leaks" to "only
  the non-sensitive content the gateway allows".

It does **not** replace enterprise governance:

- ❌ Account-level risks remain: chat-history retention, the
  provider's data-use policy, and account compromise are outside the
  gateway's reach.
- ❌ It only protects traffic that passes through it — a user pasting
  raw data into a chat directly is a policy and training problem, not
  something a gateway can fix.
- ❌ Non-PII confidential content (revenue figures, strategy text) in
  allowed columns still goes to the LLM. Tokenisation protects PII,
  not "all secrets".
- ❌ The security boundary is the trusted environment itself: whoever
  controls the gateway can read the mapping (covered by the threat
  model).
- ❌ LLM output may still contain sensitive content — response
  protection is milestone M4.

## Status

- Phase: **M2 — tokenisation (implemented)**
- M0 design review: done (v0.3)
- M1 detection: done — benchmark acceptance PASS (aggregate
  precision 0.8458 / recall 0.9738; see `docs/DECISIONS.md`)
- M2 tokenisation: implemented — session-scoped vault, span-level
  substitution, instruction protection, security test suite
- M3 (LLM integration) begins only after M2 acceptance and human
  approval (see `docs/POC_PLAN.md`)

## How it works

```
User instruction + document
        |
        v
Detection (Presidio + Chinese NLP backend) -> injection detection
        -> data minimisation -> tokenisation -> policy check
        |
        v
        External LLM (sanitised data only)
        |
        v
Response scanner -> token restoration (internal) -> final result
```

Token mappings are random, non-sequential, scoped to one gateway
invocation, and destroyed at session end. They never appear in LLM
requests, logs, reports, or client-visible surfaces.

## Documents

- `CLAUDE.md` — Claude Code project instructions (security rules, milestone gates)
- `docs/DESIGN.md` — architecture and design specification
- `docs/SECURITY_REQUIREMENTS.md` — security requirements (SR-001 … SR-025)
- `docs/THREAT_MODEL.md` — STRIDE threat model (20 threats)
- `docs/POC_PLAN.md` — milestones M0–M5 and acceptance criteria
- `docs/DECISIONS.md` — decision log (M0/M1/M2)

## Decisions (recorded at M0, v0.3)

- **Project name:** secure-ai-gateway
- **License:** Apache-2.0
- **Detection acceptance:** aggregate recall >= 90% / precision >= 80%;
  PERSON / ADDRESS / ID per-entity recall >= 85% / precision >= 80%; F1 reported
- **Session:** one gateway invocation (one instruction + one document);
  token mappings are random, non-sequential, and destroyed at session end
- **Policy:** default-deny; secrets block the request, PII is tokenised,
  non-required columns are dropped
- **Response violations:** blocked (fail closed); unknown tokens are never restored
- **PoC uses synthetic data only**

## PoC Limitations

This PoC does not claim:

- complete PII detection
- complete prompt-injection prevention
- complete protection from inference attacks
- production security
- regulatory compliance (ISO 27001, SOC 2, GDPR, Australian Privacy Act)
- enterprise-scale availability
- cross-session identity correlation

Even sanitised content is sent to an external LLM provider and is
subject to the provider's data handling and retention. Tokenisation is
pseudonymisation, not mathematical anonymity.

## Development

Python >= 3.12. Dependencies include the Chinese spaCy model
`zh_core_web_lg` (~575MB download).

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"   # or: uv pip install -p .venv -e ".[dev]"
.venv/bin/pytest tests/unit tests/security
.venv/bin/pytest -m benchmark tests/benchmark/   # slow: full detection benchmark
.venv/bin/python scripts/check_acceptance.py     # M1 acceptance gates
```

Benchmark outputs go to `bench_reports/` (gitignored).

## License

Apache-2.0 — see [LICENSE](LICENSE).
