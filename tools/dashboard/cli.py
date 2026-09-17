"""CLI: ``python -m tools.dashboard --file doc.csv --provider fake``

Runs the **real** ``Session.run`` — the same code path the packaged CLI
uses — with four recording seams attached (see recorder.py), and serves
the captured trace to a loopback-only browser page.

What this process does to the machine: it binds one TCP port on
``127.0.0.1`` and publishes a URL on it. It does not touch the
firewall, routing, DNS, ``/etc/hosts``, proxies, or any network
interface, it does not need root, and it installs nothing. Stopping the
process (Ctrl+C) releases the port immediately.

``--provider`` defaults to ``fake``: offline, no API key, no spend —
and still exercises the real response guard and restore path.
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
import time
import uuid
import webbrowser
from pathlib import Path

from secure_ai_gateway.cli import EchoProvider
from secure_ai_gateway.detection.engine import DetectionEngine
from secure_ai_gateway.errors import ProviderConfigurationError
from secure_ai_gateway.llm.provider import AnthropicProvider, LLMProvider
from secure_ai_gateway.pipeline import Pipeline
from secure_ai_gateway.session import Session, SessionResult
from tools.dashboard.recorder import (
    DashboardRecorder,
    RecordingProvider,
    make_vault_factory,
    wrap_engine,
)
from tools.dashboard.server import (
    DashboardHTTPServer,
    DashboardRequestHandler,
    load_page,
)

_HOST = "127.0.0.1"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.dashboard",
        description=(
            "Local debug dashboard: run real gateway sessions and show "
            "every stage, the exact outbound payload, and the full "
            "raw -> token mapping in a browser (loopback only)."
        ),
    )
    parser.add_argument(
        "--file",
        action="append",
        required=True,
        metavar="PATH",
        help="document to analyse (repeatable; runs one session each)",
    )
    parser.add_argument("--instruction", default=None, help="user instruction")
    parser.add_argument("--template", default="gross_margin")
    parser.add_argument(
        "--provider",
        choices=("fake", "anthropic"),
        default="fake",
        help=(
            "fake = offline demo, no network, no API key (default); "
            "anthropic = REAL API call with REAL credentials"
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="loopback port; 0 (default) picks a free one",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="do not launch a browser; just print the URL",
    )
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=20,
        help="keep at most this many sessions in memory (default: 20)",
    )
    parser.add_argument(
        "--purge-after",
        type=float,
        default=None,
        metavar="SECONDS",
        help=(
            "drop a finished session's captured data this long after it "
            "ends (default: keep until exit, bounded by --max-sessions)"
        ),
    )
    return parser


def _build_provider(name: str) -> LLMProvider:
    if name == "fake":
        print("provider: fake (offline, no network, no API key)")
        return EchoProvider()
    provider = AnthropicProvider()  # raises ProviderConfigurationError
    print("provider: anthropic — REAL API call with REAL credentials")
    return provider


def _run_sessions(
    session: Session,
    recorder: DashboardRecorder,
    paths: list[str],
    instruction: str | None,
    template: str,
) -> int:
    """Run every requested file through the real session path.

    Returns a process exit code: 0 if every session delivered, 1 if any
    blocked or failed (mirrors the packaged CLI).
    """
    exit_code = 0
    for index, path in enumerate(paths, start=1):
        rid = uuid.uuid4().hex[:12]
        print(f"\n[{index}/{len(paths)}] {path} — request_id {rid}")
        recorder.begin_session(rid, instruction)
        try:
            with recorder.capture_logs():
                result: SessionResult = session.run(
                    path,
                    instruction=instruction,
                    template_name=template,
                    request_id=rid,
                )
        except Exception as exc:  # noqa: BLE001 — report, never crash
            recorder.abort(rid, f"error:{type(exc).__name__}")
            print(f"  error: {type(exc).__name__}: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        recorder.finish(result)
        if result.delivered:
            print("  status: DELIVERED")
        else:
            print(f"  status: BLOCKED — {result.decision.reason}")
            exit_code = 1
    return exit_code


def _start_purger(
    recorder: DashboardRecorder, purge_after: float | None
) -> None:
    if purge_after is None:
        return

    def loop() -> None:
        while True:
            time.sleep(min(purge_after, 5.0))
            recorder.purge_finished_before(time.time() - purge_after)

    threading.Thread(target=loop, daemon=True, name="purge").start()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    # Presidio chatters about recogniser loading at INFO; the gateway's
    # own audit lines are the interesting ones here.
    logging.getLogger("presidio-analyzer").setLevel(logging.WARNING)

    missing = [p for p in args.file if not Path(p).is_file()]
    if missing:
        for path in missing:
            print(f"error: no such file: {path}", file=sys.stderr)
        return 2

    try:
        provider = _build_provider(args.provider)
    except ProviderConfigurationError as exc:
        print(
            f"error: {exc}. Set ANTHROPIC_API_KEY, or use --provider fake.",
            file=sys.stderr,
        )
        return 2

    recorder = DashboardRecorder(max_sessions=args.max_sessions)
    try:
        server = DashboardHTTPServer(
            (_HOST, args.port),
            DashboardRequestHandler,
            recorder=recorder,
            page_template=load_page(),
        )
    except OSError as exc:
        print(f"error: cannot bind {_HOST}:{args.port} — {exc}", file=sys.stderr)
        return 2

    # Bind and publish the URL BEFORE the detector loads: the spaCy
    # Chinese model is ~575 MB and takes seconds, and the page should
    # already be answering in the meantime.
    # flush=True: stdout is block-buffered when redirected, so without
    # it the URL would stay invisible for the whole model load.
    print(f"\n  dashboard: {server.url}", flush=True)
    print(
        "  (loopback only — this URL holds the access token; do not share it)",
        flush=True,
    )
    print(f"  bound to {_HOST}:{server.server_port}; Ctrl+C stops it\n", flush=True)

    threading.Thread(
        target=server.serve_forever, daemon=True, name="dashboard-http"
    ).start()
    _start_purger(recorder, args.purge_after)
    if not args.no_open:
        webbrowser.open(server.url)

    print("loading detection model (first run can take several seconds)…")
    pipeline = Pipeline(
        wrap_engine(recorder, DetectionEngine()),
        vault_factory=make_vault_factory(recorder),
    )
    exit_code = _run_sessions(
        Session(pipeline, RecordingProvider(recorder, provider)),
        recorder,
        args.file,
        args.instruction,
        args.template,
    )

    print(f"\n  dashboard still serving: {server.url}")
    print("  Ctrl+C to stop (the port is released when this process exits)")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        print("\nstopped; port released.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
