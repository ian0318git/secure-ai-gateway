# Local Debug Dashboard

**This is a development tool. It is not a security control, and it must
never be cited as one.** See `docs/SECURITY_REQUIREMENTS.md` SR-027 and
`docs/DECISIONS.md` (2026-09-18).

## What it does

Runs the **real** gateway session — the same `Session.run` the CLI runs,
not a re-implementation — and shows, per session:

- the input document: every cell, raw value, protected value, and the
  spans the detector found
- what each stage did, stage by stage: parse → detect → policy →
  minimise → tokenise → provider → response
- the per-cell policy disposition (`TOKENISE` / `DROP` / `ALLOW` /
  `BLOCK`)
- **the complete raw → token mapping**, including every cell and column
  each entry occurred in
- the exact outbound wire body, the raw response, and the restored text
- the sanitised audit log lines for that session

The mapping table is the point: a false positive the detector produced
in a real run (`營收` → `LOCATION_d2195995`) was invisible in the CLI
output and obvious here.

## Running it

```bash
.venv/bin/python -m tools.dashboard --file tmp/demo.csv --provider fake
```

| Flag | Meaning |
|---|---|
| `--file PATH` | document to analyse (repeatable — one session each) |
| `--instruction TEXT` | user instruction, protected like the document |
| `--template NAME` | report template (default `gross_margin`) |
| `--provider fake\|anthropic` | `fake` (default) is offline; `anthropic` is a **real** API call |
| `--port N` | loopback port; `0` (default) picks a free one |
| `--no-open` | print the URL instead of launching a browser |
| `--max-sessions N` | keep at most N sessions in memory (default 20) |
| `--purge-after SECONDS` | drop a finished session's data after this long |

The URL printed at startup contains a per-run 128-bit token. **Treat
that URL as a secret for as long as the process runs** — it is the only
thing standing between the mapping and any other process on the machine.

Default to `--provider fake`. Synthetic data only (SR-014).

## Security design

Bounds the tool is built to stay inside. Each is pinned by a test in
`tests/tools/`.

- Binds `127.0.0.1` only — never a wildcard address. `_LOOPBACK_HOSTS`
  is asserted at runtime, and the source is AST-scanned for a wildcard.
- Guard order: `Host` allow-list → own-`Origin`-only → 128-bit path
  token → method → route. A wrong or missing token returns **404, not
  403** — a probe cannot confirm the dashboard exists.
- No CORS header on any response, including `OPTIONS`. `no-store`,
  `nosniff`, `no-referrer`, and a nonce-based CSP on every response.
  GET/HEAD only.
- **Never writes to disk** — no dump, cache, report, or exported
  mapping. The repo tree is byte-identical after a run and after a
  served request, with every write path patched to raise.
- **Never calls `log_event`.** The gateway's `log_event` blocks
  forbidden field *names*, so a raw value passed under an innocuous key
  would sail past it. `tools/` only *reads* the sanitised stream
  through a `logging.Handler`.
- `payload["report"]` is byte-identical to `MetadataReport.to_dict()`.
  Raw values and tokens live only under the paths declared in
  `model.RAW_OR_TOKEN_PATHS`, and `redacted_view()` strips exactly
  those.
- The page is rendered with `createElement` + `textContent` only, under
  a per-run CSP nonce. No `innerHTML`, no `<script src>`, no CDN, no
  `WebSocket`, no `EventSource` — no exfiltration path and no HTML sink.
- Wraps the **provider interface, not the transport**, so
  `ANTHROPIC_API_KEY` is unreachable from the tool (there is nothing to
  redact because it never arrives).
- `tools/` is outside the packaged distribution. Nothing under `src/`
  imports it, and it imports only the stdlib plus `secure_ai_gateway` —
  zero new dependencies.

### The two relaxations

Both are recorded, not inferred:

1. **SR-002** forbids token mappings in "client-side code". This tool
   serves them to a loopback browser. Permitted only because it is the
   operator's own machine and their own session data.
2. **SR-019** requires mappings destroyed at session end. `Session.run`
   still does that — the recorder holds a *separate* in-memory copy, so
   the mapping's lifetime is the dashboard process's lifetime. This is
   a genuine relaxation of the stated guarantee, not a reinterpretation.

## Residual risks — accepted, not mitigated

Also recorded in `docs/DECISIONS.md` (2026-09-18, D12) and
`docs/THREAT_MODEL.md` (T-I12, T-D05).

1. **The browser is a raw-data sink.** Extensions, screenshot/OCR
   tools, clipboard managers, profile readers. `no-store` prevents
   caching; it does not sandbox an extension.
2. **Any same-user process can win.** The URL is printed to the
   terminal — scrollback, `/proc/<pid>/cmdline`, shell history and tmux
   buffers all leak it.
3. **Loopback is not per-user isolation on Linux.** On a shared host or
   CI runner, the 128-bit token is the only barrier.
4. **Port forwarding defeats the bind.** `ssh -L`, dev-container
   proxies, `GatewayPorts`. The code cannot enforce this.
5. **SR-019 is relaxed** (above).
6. **Memory is not zeroised and can be paged out.** Swap, hibernation,
   core dumps — the exposure window is the whole process lifetime.
7. **The isolation sweep is evidence, not proof.** An undeclared field
   is caught only when it holds a fixture-known value or a `TOKEN_RE`
   match. Adding a field that carries raw data **without** declaring it
   in `model.RAW_OR_TOKEN_PATHS` is the realistic failure mode — update
   that set in the same change.
8. **No TLS, no auth beyond the path token.** A privileged local
   sniffer sees everything.
9. **Unbounded in-memory growth**, bounded by `--max-sessions` /
   `--purge-after` rather than eliminated.
10. **`--provider anthropic` sends real data to a real API.** The
    `fake` default mitigates; it does not prevent.
11. **The tool is outside the PoC's audited claims.** It gets ruff,
    mypy, bandit and the full test suite, but no `pip-audit`, no
    packaging, and no existing SR. Only SR-027 covers it.

### The blur toggle is cosmetic

「隱藏原始值」visually blurs raw values for screen sharing. The data is
still in the page and in browser memory. It is not a protection and it
does not replace turning off the screen share. The UI says so too.

## Tests

```bash
.venv/bin/pytest tests/tools -q
```

Uses a stub analyzer throughout — the 575 MB spaCy model never loads —
but exercises the **real** `Session.run`, since a dashboard that
observes a stubbed session would prove nothing about the real one.
