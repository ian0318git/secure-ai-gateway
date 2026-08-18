"""Interactive demo CLI (M4).

``python -m secure_ai_gateway.cli --file data.csv --instruction "..."``

Runs one full gateway session: parse -> detect -> policy -> minimise
-> tokenise -> provider call -> response guard (DESIGN §17).

``--provider fake`` runs an offline demo (no network, no API key):
the fake answers with a canned analysis referencing the protected
values through their tokens, so the demo exercises the real scan +
restore path — tokens are restored where authorised, violations are
blocked.

The response is validated and restored by the M4 response guard; a
violation fails closed and the CLI prints the machine-readable
``response:<category>`` reason.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secure_ai_gateway.detection.engine import DetectionEngine
from secure_ai_gateway.errors import (
    ProviderConfigurationError,
    VaultKeyError,
    VaultStoreError,
)
from secure_ai_gateway.llm.provider import AnthropicProvider, LLMProvider
from secure_ai_gateway.llm.request_builder import LLMRequest
from secure_ai_gateway.llm.response_parser import ParsedResponse
from secure_ai_gateway.pipeline import Pipeline
from secure_ai_gateway.session import Session
from secure_ai_gateway.tokenisation.persistent import (
    PersistentSessionVault,
    PersistentTokenStore,
    load_master_key,
)


class EchoProvider:
    """Offline demo provider: answers with a canned natural-language
    analysis that references each protected value through its token.
    No network, no API key.

    A real provider returns prose, not the prompt structure — echoing
    the protected JSON back would send NER haywire (quotes and column
    names merge with entities). The canned analysis therefore walks
    the same M4 scan + restore path a real response does: tokens are
    restored where authorised, violations are blocked.
    """

    def complete(self, request: LLMRequest) -> ParsedResponse:
        lines: list[str] = []
        if request.instruction:
            lines.append(f"關於「{request.instruction}」的初步分析：")
        for cell in sorted(request.document, key=lambda c: (c.row, c.cell_id)):
            lines.append(f"{cell.column} 的數值為 {cell.value}，已納入分析。")
        return ParsedResponse(text="\n".join(lines), stop_reason="end_turn")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure-ai-gateway",
        description=(
            "Secure AI Gateway demo — run one protected LLM session"
        ),
    )
    parser.add_argument("--file", required=True, help="document to analyse")
    parser.add_argument("--instruction", default=None, help="user instruction")
    parser.add_argument("--template", default="gross_margin")
    parser.add_argument(
        "--provider",
        choices=("anthropic", "fake"),
        default="anthropic",
        help=(
            "anthropic = real API (requires ANTHROPIC_API_KEY); "
            "fake = offline demo, echoes the protected message"
        ),
    )
    parser.add_argument(
        "--vault-store",
        metavar="PATH",
        default=None,
        help=(
            "M6 opt-in: persistent encrypted token store — reuse token "
            "identities across runs. Requires VAULT_MASTER_KEY (base64 "
            "of 32 random bytes). Default: session-only vault (PoC "
            "behaviour)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    vault_factory = None
    if args.vault_store:
        # Fail closed before any session: missing/invalid key and
        # unloadable stores exit 2, mirroring ProviderConfigurationError.
        try:
            key = load_master_key()
            store = PersistentTokenStore(Path(args.vault_store), key)
        except (VaultKeyError, VaultStoreError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"vault store: {args.vault_store} — {len(store)} entries")
        vault_factory = lambda: PersistentSessionVault(store=store)
    pipeline = Pipeline(DetectionEngine(), vault_factory=vault_factory)
    provider: LLMProvider
    if args.provider == "fake":
        print("offline demo: --provider fake, no provider called")
        provider = EchoProvider()
    else:
        try:
            provider = AnthropicProvider()
        except ProviderConfigurationError as exc:
            print(
                f"error: {exc}. Set ANTHROPIC_API_KEY, or use "
                "--provider fake for an offline demo.",
                file=sys.stderr,
            )
            return 2
    result = Session(pipeline, provider).run(
        args.file,
        instruction=args.instruction,
        template_name=args.template,
    )
    report = result.report
    print(f"request_id: {result.request_id}")
    print(f"status:     {'DELIVERED' if result.delivered else result.decision.reason}")
    print(f"source:     {report.source_name} ({report.file_format}, {report.encoding})")
    print(f"rows:       {report.row_count}  cells: {report.cell_count}")
    print(
        f"retained:   {report.retained_cells}  dropped: "
        f"{report.dropped_cells}  tokenised_spans: {report.tokenised_spans}"
    )
    if result.delivered:
        print("\n--- LLM response ---")
        print(result.response_text)
        return 0
    print(f"blocked: {result.decision.reason}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
