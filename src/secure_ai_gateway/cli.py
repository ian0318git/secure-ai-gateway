"""Interactive demo CLI (M3).

``python -m secure_ai_gateway.cli --file data.csv --instruction "..."``

Runs one full gateway session: parse -> detect -> policy -> minimise
-> tokenise -> provider call -> response.

``--provider fake`` runs an offline demo (no network, no API key):
the fake echoes the exact protected message that would be sent to the
provider.

The response is printed as-is; it is NOT response-scanned (response
protection is milestone M4).
"""

from __future__ import annotations

import argparse
import sys

from secure_ai_gateway.detection.engine import DetectionEngine
from secure_ai_gateway.errors import ProviderConfigurationError
from secure_ai_gateway.llm.provider import AnthropicProvider
from secure_ai_gateway.llm.request_builder import LLMRequest
from secure_ai_gateway.llm.response_parser import ParsedResponse
from secure_ai_gateway.pipeline import Pipeline
from secure_ai_gateway.session import Session


class EchoProvider:
    """Offline demo provider: returns the protected message exactly as
    it would be sent to the provider. No network, no API key."""

    def complete(self, request: LLMRequest) -> ParsedResponse:
        content = request.to_body()["messages"][0]["content"]
        assert isinstance(content, str)
        return ParsedResponse(text=content, stop_reason="end_turn")


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    pipeline = Pipeline(DetectionEngine())
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
        print("--- response not scanned (M4) ---")
        return 0
    print(f"blocked: {result.decision.reason}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
