"""Interactive demo CLI (M4).

``python -m secure_ai_gateway.cli --file data.csv --instruction "..."``

Runs one full gateway session: parse -> detect -> policy -> minimise
-> tokenise -> provider call -> response guard (DESIGN §17).

``--provider fake`` runs an offline demo (no network, no API key):
the fake "responds" with the protected message minus its framing
markers, so the demo exercises the real scan + restore path — tokens
are restored where authorised, violations are blocked.

The response is validated and restored by the M4 response guard; a
violation fails closed and the CLI prints the machine-readable
``response:<category>`` reason.
"""

from __future__ import annotations

import argparse
import sys

from secure_ai_gateway.detection.engine import DetectionEngine
from secure_ai_gateway.errors import ProviderConfigurationError
from secure_ai_gateway.llm.provider import AnthropicProvider
from secure_ai_gateway.llm.request_builder import (
    DOCUMENT_MARKER,
    INSTRUCTION_MARKER,
    LLMRequest,
)
from secure_ai_gateway.llm.response_parser import ParsedResponse
from secure_ai_gateway.pipeline import Pipeline
from secure_ai_gateway.session import Session


class EchoProvider:
    """Offline demo provider: returns the protected message exactly as
    it would be sent to the provider, minus the framing marker lines.
    No network, no API key.

    A real provider never echoes the prompt structure back, so the
    demo strips the marker lines here — the response then goes through
    the full M4 scan + restore path like any other response.
    """

    def complete(self, request: LLMRequest) -> ParsedResponse:
        content = request.to_body()["messages"][0]["content"]
        assert isinstance(content, str)
        lines = [
            line
            for line in content.splitlines()
            if line.strip() not in (INSTRUCTION_MARKER, DOCUMENT_MARKER)
        ]
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
        return 0
    print(f"blocked: {result.decision.reason}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
