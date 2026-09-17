"""Local debug dashboard for the Secure AI Gateway.

A loopback-only browser view of one gateway session: the input
document, every pipeline stage, the exact outbound payload, and the
full raw -> token mapping.

**This tool deliberately displays token mappings in a browser.** That
is a recorded, user-approved relaxation of CLAUDE.md §2
("client-side code") and SR-019 ("mappings destroyed at session end")
— for this tool ONLY. The packaged gateway is unchanged. Read
docs/DECISIONS.md (2026-09-18) and tools/dashboard/README.md before
using it.

It is a DEBUG tool, not a security control: SR-013 already states that
client-side checks are not a security boundary. Synthetic data only
(SR-014).
"""
