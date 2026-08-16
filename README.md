# Secure AI Gateway

An enterprise-oriented AI data protection gateway: use external LLMs
(ChatGPT, Claude, Gemini, ...) for analysis of business documents
without exposing confidential data.

**Non-negotiable boundary:** raw confidential data and token mappings
must never cross the external LLM trust boundary.

## Status

- Phase: M0 — design review (v0.3)
- Implementation: not started. Work begins at M1 (see `docs/POC_PLAN.md`)
  only after human approval.

## Documents

- `CLAUDE.md` — Claude Code project instructions (security rules, milestone gates)
- `docs/DESIGN.md` — architecture and design specification
- `docs/SECURITY_REQUIREMENTS.md` — security requirements (SR-001 … SR-025)
- `docs/THREAT_MODEL.md` — STRIDE threat model (20 threats)
- `docs/POC_PLAN.md` — milestones M0–M5 and acceptance criteria

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

## License

Apache-2.0 — see [LICENSE](LICENSE).
