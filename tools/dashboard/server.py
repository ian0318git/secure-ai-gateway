"""Loopback-only HTTP server for the dashboard — stdlib only.

Threat model for a localhost debug server:

* **Other machines on the LAN** must not reach it. The socket binds
  ``127.0.0.1``, never ``0.0.0.0`` (pinned by test_server_security.py).
* **Web pages the operator visits while the dashboard runs** must not
  reach it. Browsers happily issue cross-origin requests; ``Host`` and
  ``Origin`` are checked, and **no CORS header is ever sent**, so a
  foreign page can neither read a response nor preflight one.
* **DNS rebinding** must not reach it. A rebound hostname resolves to
  ``127.0.0.1`` but still arrives with the attacker's ``Host`` header →
  rejected. This is independent of the path token.
* **Any other local process** can reach ``127.0.0.1:<port>`` — loopback
  is not per-user isolation on Linux. That is what the 128-bit path
  token is for, and it is the load-bearing control.

Guard order in ``_route``: Host → Origin → path token → method → route.
Wrong or missing token returns **404, not 403** — a 403 would confirm
that a dashboard is listening and let an attacker probe token shapes.

Reads of ``DashboardRecorder`` hold its lock only long enough to build
a payload dict; ``json.dumps`` runs outside it, so a slow client cannot
stall the session worker.
"""

from __future__ import annotations

import hmac
import json
import secrets
import socketserver
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any, cast
from urllib.parse import urlsplit

from tools.dashboard.model import (
    session_brief,
    state_envelope,
    state_view,
    to_json,
    to_payload,
)
from tools.dashboard.recorder import DashboardRecorder

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")

#: Placeholder in page.html, replaced per run with the CSP nonce.
_NONCE_PLACEHOLDER = "__CSP_NONCE__"

#: Everything is inline and local: no network origin is permitted at
#: all, and ``connect-src 'self'`` is exactly our own JSON endpoints.
#: A nonce (not 'unsafe-inline') means an injected inline <script>
#: would not execute even if a future edit introduced an HTML sink.
_CSP = (
    "default-src 'none'; "
    "script-src 'nonce-{nonce}'; "
    "style-src 'nonce-{nonce}'; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)

_MAX_REQUEST_ID = 128


def load_page() -> str:
    """Read page.html from the installed module — never from disk at
    runtime, never written back out."""
    return (
        files("tools.dashboard").joinpath("page.html").read_text("utf-8")
    )


class DashboardHTTPServer(ThreadingHTTPServer):
    """``ThreadingHTTPServer`` (a browser opens several connections)
    with the localhost hardening this tool needs."""

    daemon_threads = True
    #: A busy port must fail loudly rather than silently sharing with
    #: whatever else holds it.
    allow_reuse_address = False

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        recorder: DashboardRecorder,
        page_template: str,
        path_token: str | None = None,
    ) -> None:
        self.recorder = recorder
        self.path_token = path_token or secrets.token_hex(16)
        #: Compared as bytes: ``http.server`` decodes the request line as
        #: latin-1, and ``hmac.compare_digest`` rejects non-ASCII ``str``.
        self.path_token_bytes = self.path_token.encode("ascii")
        self.nonce = secrets.token_urlsafe(16)
        self.page_html = page_template.replace(_NONCE_PLACEHOLDER, self.nonce)
        super().__init__(address, handler)
        # Built AFTER binding, from the port actually in use: with
        # --port 0 the requested port is 0 and an allow-list built from
        # it would reject every request.
        bound_port = self.server_address[1]
        self.allowed_hosts: frozenset[str] = frozenset(
            f"{host}:{bound_port}" for host in _LOOPBACK_HOSTS
        )
        self.allowed_origins: frozenset[str] = frozenset(
            f"http://{host}" for host in self.allowed_hosts
        )

    def server_bind(self) -> None:
        """Bind without ``HTTPServer``'s ``socket.getfqdn()``.

        The base implementation performs a reverse-DNS lookup on every
        start: it can stall for seconds behind a slow resolver, and it
        is a name-resolution call this tool has no reason to make.
        """
        socketserver.TCPServer.server_bind(self)
        host = self.server_address[0]
        self.server_name = host if isinstance(host, str) else bytes(host).decode()
        self.server_port = self.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{self.server_name}:{self.server_port}/{self.path_token}/"


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Single handler for every method — routing decides, not dispatch,
    so an unauthenticated request is rejected identically whatever its
    method (S9)."""

    protocol_version = "HTTP/1.0"
    server_version = "SecureAIGatewayDashboard"
    sys_version = ""  # S13: the banner must not leak the Python version

    @property
    def _dash(self) -> DashboardHTTPServer:
        return cast(DashboardHTTPServer, self.server)

    # -- logging (S11) ------------------------------------------------------

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:
        """Silenced.

        The base implementation renders ``self.requestline``, which
        contains the path token — and the token is the whole control.
        ``_respond`` logs the safe subset (method, route name, status)
        instead, so the token never reaches a terminal, a log file, or
        a scrollback buffer.
        """

    def _log(self, route: str, code: int) -> None:
        if route == "state" and code == 200:
            return  # a 1 Hz poll would drown the operator's terminal
        print(f"{self.command} {route} -> {code}", file=sys.stderr)

    # -- dispatch -----------------------------------------------------------

    def do_GET(self) -> None:
        self._dispatch()

    def do_HEAD(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_PUT(self) -> None:
        self._dispatch()

    def do_DELETE(self) -> None:
        self._dispatch()

    def do_PATCH(self) -> None:
        self._dispatch()

    def do_OPTIONS(self) -> None:
        # Reaches here only if the request also passed the Host/token
        # gates; a CORS preflight then gets 405 with no CORS headers,
        # which is what makes the browser refuse the cross-origin call.
        self._dispatch()

    def _dispatch(self) -> None:
        try:
            self._route()
        except Exception:  # noqa: BLE001 — never leak a traceback
            # A traceback can echo request-line fragments; nothing
            # escapes this handler.
            self._respond(
                500, "text/plain; charset=utf-8", b"internal error\n", "error"
            )

    def _route(self) -> None:
        if self.headers.get("Host", "") not in self._dash.allowed_hosts:
            # S4/S5: covers DNS rebinding — the rebound request carries
            # the attacker's Host even though it resolved to loopback.
            self._respond(403, "text/plain; charset=utf-8", b"forbidden\n",
                          "host")
            return

        origin = self.headers.get("Origin")
        if origin is not None and origin not in self._dash.allowed_origins:
            self._respond(403, "text/plain; charset=utf-8", b"forbidden\n",
                          "origin")
            return

        path = urlsplit(self.path).path
        parts = [p for p in path.split("/") if p]
        if not parts or not hmac.compare_digest(
            parts[0].encode("utf-8", "surrogateescape"),
            self._dash.path_token_bytes,
        ):
            # S2/S12: 404, not 403 — never confirm the token's shape.
            self._respond(404, "text/plain; charset=utf-8", b"not found\n",
                          "token")
            return

        if len(parts) == 1 and not path.endswith("/"):
            # The page fetches relative URLs; without the trailing slash
            # the browser resolves them against "/" and loses the token.
            self._respond(
                301,
                "text/plain; charset=utf-8",
                b"",
                "redirect",
                extra={"Location": path + "/"},
            )
            return

        if self.command not in ("GET", "HEAD"):
            self._respond(
                405,
                "text/plain; charset=utf-8",
                b"method not allowed\n",
                "method",
                extra={"Allow": "GET, HEAD"},
            )
            return

        self._serve(parts[1:])

    # -- routes -------------------------------------------------------------

    def _serve(self, route: list[str]) -> None:
        if not route:
            self._respond(
                200,
                "text/html; charset=utf-8",
                self._dash.page_html.encode("utf-8"),
                "page",
            )
            return
        if route == ["api", "state"]:
            self._serve_state()
            return
        if len(route) == 3 and route[:2] == ["api", "session"]:
            self._serve_session(route[2])
            return
        self._respond(404, "text/plain; charset=utf-8", b"not found\n", "route")

    def _serve_state(self) -> None:
        recorder = self._dash.recorder
        current = recorder.current()
        if current is None:
            current_view = None
        else:
            current_view = state_view(to_payload(current))
        briefs = [
            session_brief(to_payload(trace))
            for trace in (
                recorder.trace(rid) for rid in recorder.request_ids()
            )
            if trace is not None
        ]
        body = json.dumps(
            state_envelope(briefs, current_view, recorder.revision),
            ensure_ascii=False,
        ).encode("utf-8")
        self._respond(200, "application/json; charset=utf-8", body, "state")

    def _serve_session(self, request_id: str) -> None:
        if len(request_id) > _MAX_REQUEST_ID:
            self._respond(404, "text/plain; charset=utf-8", b"not found\n",
                          "session")
            return
        trace = self._dash.recorder.trace(request_id)
        if trace is None:
            self._respond(404, "text/plain; charset=utf-8", b"not found\n",
                          "session")
            return
        body = to_json(to_payload(trace)).encode("utf-8")
        self._respond(
            200, "application/json; charset=utf-8", body, "session"
        )

    # -- responses ----------------------------------------------------------

    def _respond(
        self,
        code: int,
        content_type: str,
        body: bytes,
        route: str,
        *,
        extra: dict[str, str] | None = None,
    ) -> None:
        """The single exit point — so ``Content-Length`` is always
        accurate (HTTP/1.1 and keep-alive clients hang without it) and
        the security headers cannot be forgotten on an error path."""
        self._log(route, code)
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy", _CSP.format(nonce=self._dash.nonce)
        )
        self.send_header("Connection", "close")
        for header, value in (extra or {}).items():
            self.send_header(header, value)
        self.end_headers()
        self.close_connection = True
        if self.command != "HEAD" and body:
            self.wfile.write(body)
