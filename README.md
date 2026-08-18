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
- ❌ LLM output may still contain sensitive content — the response
  guard mitigates it: sensitive or policy-violating responses are
  blocked (fail closed), unknown tokens are never restored.

## Status

- Phase: **PoC complete (M0–M6, v0.4.0)** — see `docs/FINAL_REPORT.md`
- M0 design review: done (v0.3)
- M1 detection: done — benchmark acceptance PASS (aggregate
  precision 0.8458 / recall 0.9738; see `docs/DECISIONS.md`)
- M2 tokenisation: done — session-scoped vault, span-level
  substitution, instruction protection, security test suite
- M3 LLM integration: done — Anthropic provider (stdlib, zero new
  dependencies), protected request builder, session orchestrator,
  interactive CLI
- M4 response protection: done — response guard (sensitive-data scan
  reusing the detection engine, unknown/hallucinated token detection,
  marker-echo task-compliance check, controlled token restoration);
  violations fail closed with machine-readable `response:<category>`
  reasons; truncation (`stop_reason: max_tokens`) blocks
- M5 security test suite: done — all 20 POC_PLAN items map to
  passing tests (`docs/TEST_TRACEABILITY.md`); response-side prompt
  injection detection (mirror rule, `response:injection:<CAT>`);
  exhaustive fail-closed sweep (22 failure paths, zero provider calls
  before the boundary); SR-016 audit-event battery; benchmark
  evidence re-checked normatively against the documented thresholds
- M6 persistent token store: done (opt-in) — `--vault-store PATH` +
  `VAULT_MASTER_KEY` keeps token identities stable across sessions in
  a Fernet-encrypted JSON store (SR-026); default sessions stay
  session-only; restore() stays session-scoped (a previous-session
  token in a response still blocks, fail closed); 752 tests green

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
Response guard: token validation -> marker check -> restore known
tokens -> sensitive-data scan -> controlled restoration (final result)
```

Token mappings are random, non-sequential, scoped to one gateway
invocation, and destroyed at session end. They never appear in LLM
requests, logs, reports, or client-visible surfaces.

### Worked example

The finance team asks an AI to analyse this CSV:

```
客戶,營業收入,毛利率
Aurora Motors AU,8.4M,32%
```

Instruction: `請分析這份文件的營業收入`

1. **Parse** — the gateway reads the file and normalises encoding.
2. **Detect** — `Aurora Motors AU` is flagged as an identifier; a
   formula prefix or an injected instruction would be caught here too.
3. **Policy (default deny)** — a secret blocks the whole request; PII
   is tokenised; columns outside the allowlist are dropped.
4. **Tokenise** — the LLM sees only
   `CUSTOMER_4f8a21, 8.4M, 32%`. The mapping is random, lives for this
   invocation only, and is destroyed at session end.
5. **Analyse** — the external LLM never learns the real customer name.
6. **Restore** — the answer is delivered as
   `Aurora Motors AU 毛利率 32%…`. A token this session never issued is
   refused (`response:unknown_token`); mappings never cross the trust
   boundary.

The instruction itself is protected input: raw identifiers inside it
pass through the same pipeline before reaching the LLM. A full visual
walkthrough lives at
[docs/gateway_example.html](docs/gateway_example.html).

### What is PII?

PII (personally identifiable information) is any data that identifies a
specific person or company — names, addresses, ID numbers, phone
numbers, emails, customer/employee IDs, credit cards. The gateway
tokenises these. Secrets (API keys, passwords, JWTs, private keys) are
not PII but are more sensitive: their presence blocks the whole request
(fail closed). Ordinary figures (revenue, margins) are neither and pass
through. The three-layer detector — Presidio, the Chinese NLP backend,
and custom regex recognisers — decides which is which.

Try the demo:

```bash
export ANTHROPIC_API_KEY=sk-...          # real API call
.venv/bin/python -m secure_ai_gateway.cli --file data.csv \
    --instruction "請分析毛利率趨勢"       # --provider fake = offline demo
```

Persistent token store (M6, opt-in — run twice, same tokens):

```bash
export VAULT_MASTER_KEY=$(.venv/bin/python -c \
    "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
.venv/bin/python -m secure_ai_gateway.cli --file data.csv \
    --provider fake --vault-store tmp/demo.vault
.venv/bin/python -m secure_ai_gateway.cli --file data.csv \
    --provider fake --vault-store tmp/demo.vault   # same tokens again
```

## Technology stack

Core detection:

| Technology | Version | Role |
|---|---|---|
| Presidio Analyzer | 2.2.364 | PII detection framework (rule + ML recognisers) |
| spaCy + `zh_core_web_lg` | 3.7.2 (575MB model) | Chinese NLP backend wired into Presidio — person / org / address NER |
| custom regex recognisers | built-in | deterministic rules: TW ID numbers, phone numbers, Chinese name heuristics |

Processing & storage:

| Technology | Version | Role |
|---|---|---|
| charset-normalizer | 3.3.2 | encoding detection (mojibake hides PII) |
| pandas / openpyxl | >=2.2 / >=3.1.2 | tabular data, .xlsx parsing |
| defusedxml | 0.7.1 | safe XML parsing (XXE protection) |
| cryptography (Fernet) | >=50 | encrypted persistent token store (M6, opt-in) |

Deliberately absent: no web framework, no database, no `requests`/`httpx`
— the LLM call uses stdlib `urllib.request` behind an https-only guard
(SR-001); tokens come from stdlib `secrets`. Dev tooling: pytest, ruff,
mypy, bandit, pip-audit, enforced by the pre-commit gate and CI.

### What each technology does during a run

The same six steps as the worked example, with the technology doing the
work:

1. **Parse** — `charset-normalizer` detects the file encoding (a wrong
   guess turns Chinese into mojibake and blinds the detectors);
   `openpyxl` + `defusedxml` open .xlsx safely (XXE protection);
   `unicodedata` unifies full/half-width forms (NFKC).
2. **Detect** — three detectors look in turn: the spaCy Chinese model
   marks words as person/org/address; Presidio organises that into an
   "is this PII" score, using context hints like a 客戶 header; custom
   regex recognisers match fixed formats (TW ID numbers, phone
   numbers) with 100% determinism.
3. **Policy** — the static policy engine (written code, not AI) stamps
   each cell: secret -> block the whole request, PII -> tokenise,
   allowlisted column -> pass. The rules cannot be talked out of it.
4. **Tokenise** — stdlib `secrets.token_hex` mints the random token
   (`CUSTOMER_4f8a21`); the mapping lives in memory only
   (`cryptography`/Fernet appears only for the opt-in M6 vault store).
5. **Analyse** — stdlib `urllib.request` sends the HTTPS POST
   (https-only enforced, SR-001); the LLM sees tokens only.
6. **Restore** — the response guard validates every token in the reply
   against this session's vault (unknown -> refused), scans for leaked
   sensitive content, then substitutes the real names back.

Every step above is pinned by the 753-test suite.

## Documents

- `docs/FINAL_REPORT.md` — final PoC report (acceptance, evidence, residuals)
- `docs/gateway_example.html` — visual walkthrough (open in a browser)
- `CLAUDE.md` — Claude Code project instructions (security rules, milestone gates)
- `docs/DESIGN.md` — architecture and design specification
- `docs/SECURITY_REQUIREMENTS.md` — security requirements (SR-001 … SR-026)
- `docs/THREAT_MODEL.md` — STRIDE threat model (25 threats)
- `docs/POC_PLAN.md` — milestones M0–M6 and acceptance criteria
- `docs/DECISIONS.md` — decision log (M0/M1/M2/M5/M6)

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

### Pre-commit gate

A fail-closed pre-commit hook runs ruff, mypy, bandit and the full
test suite on staged Python files (and refuses to commit `*.vault`
token-store files). Enable it per clone:

```bash
git config core.hooksPath .githooks
```

Requires the dev tools (`uv pip install -e ".[dev]"`). Skip only in
emergency with `git commit --no-verify` — do not weaken the gate.

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
