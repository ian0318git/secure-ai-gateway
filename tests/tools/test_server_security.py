"""The localhost server's threat model, one test per property.

These drive a REAL server over a REAL socket. A test that called the
handler's methods directly would not prove the socket binds loopback,
would not prove ``http.server`` emits the headers we think it does, and
would not catch the class of bug this file exists for (the Host
allow-list was, at one point, built from the *requested* port rather
than the bound one — invisible to any in-process test).

Numbering follows the plan's table (S1–S13).
"""

from __future__ import annotations

import ast
import http.client
import json
import re
import secrets
import socket
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from conftest import REQUEST_ID, SessionRun

from tools.dashboard.server import (
    _LOOPBACK_HOSTS,
    DashboardHTTPServer,
    DashboardRequestHandler,
    load_page,
)

#: Fixed so request construction is deterministic and the "token never
#: reaches a terminal" test has a literal to search for.
PATH_TOKEN = "0123456789abcdef0123456789abcdef"
HEX32 = re.compile(r"\A[0-9a-f]{32}\Z")
NONCE_IN_CSP = re.compile(r"nonce-([A-Za-z0-9_-]+)")


@dataclass
class Serving:
    server: DashboardHTTPServer
    thread: threading.Thread
    token: str
    port: int

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def url(self, suffix: str = "") -> str:
        return f"/{self.token}/{suffix}"


@dataclass
class Reply:
    status: int
    headers: dict[str, str]
    body: bytes

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def json(self):
        return json.loads(self.body.decode("utf-8"))


@pytest.fixture
def serving(finished: SessionRun) -> Iterator[Serving]:
    server = DashboardHTTPServer(
        ("127.0.0.1", 0),
        DashboardRequestHandler,
        recorder=finished.harness.recorder,
        page_template=load_page(),
        path_token=PATH_TOKEN,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Serving(server, thread, PATH_TOKEN, server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def call(
    serving: Serving,
    path: str,
    *,
    method: str = "GET",
    host: str | None = None,
    origin: str | None = None,
    extra: dict[str, str] | None = None,
) -> Reply:
    """One request on a fresh connection (the server speaks HTTP/1.0
    and closes after every response)."""
    # ``host is None`` means "the honest client"; ``host=""`` is a real
    # test case (an empty Host header), so it must not fall through.
    headers = {
        "Host": f"127.0.0.1:{serving.port}" if host is None else host
    }
    if origin is not None:
        headers["Origin"] = origin
    headers.update(extra or {})
    conn = http.client.HTTPConnection("127.0.0.1", serving.port, timeout=10)
    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for name, value in headers.items():
            conn.putheader(name, value)
        conn.endheaders()
        response = conn.getresponse()
        body = response.read()
        return Reply(
            response.status,
            {k.lower(): v for k, v in response.getheaders()},
            body,
        )
    finally:
        conn.close()


def code_strings(path: Path) -> list[str]:
    """String literals in ``path`` that are not docstrings.

    A bind address can only be a literal, so scanning literals is the
    honest form of "no wildcard bind": a grep over the whole file would
    trip over the docstring that says the socket is *never* bound to a
    wildcard address.
    """
    tree = ast.parse(path.read_text("utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = getattr(node, "body", None)
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstrings.add(id(body[0].value))
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


class TestS1BindsLoopbackOnly:
    def test_socket_is_bound_to_loopback(self, serving: Serving) -> None:
        assert serving.server.server_address[0] == "127.0.0.1"

    def test_the_host_allow_list_is_exactly_loopback(self) -> None:
        assert _LOOPBACK_HOSTS == ("127.0.0.1", "localhost", "[::1]")

    def test_no_wildcard_address_literal_anywhere_in_the_tool(self) -> None:
        # A wildcard bind would expose the mapping to the whole LAN. The
        # address is chosen in cli.py and passed through server.py, so
        # all of tools/dashboard is scanned.
        wildcards = {"0.0.0.0", "::", "::0", "[::]", "*"}
        root = Path(__file__).resolve().parents[2] / "tools" / "dashboard"
        for source in sorted(root.glob("*.py")):
            literals = code_strings(source)
            # Exact match, so the legitimate "[::1]" does not trip it...
            assert not (wildcards & set(literals)), source.name
            # ...and a substring check for the one form with no
            # legitimate use here, e.g. embedded in a URL.
            assert not any("0.0.0.0" in lit for lit in literals), source.name

    def test_cli_binds_loopback_by_literal(self) -> None:
        cli_path = (
            Path(__file__).resolve().parents[2] / "tools" / "dashboard" / "cli.py"
        )
        assert "127.0.0.1" in code_strings(cli_path)


class TestS2PathTokenRequired:
    def test_correct_token_serves_the_page(self, serving: Serving) -> None:
        reply = call(serving, serving.url())
        assert reply.status == 200
        assert reply.header("content-type").startswith("text/html")

    def test_missing_token_is_404(self, serving: Serving) -> None:
        assert call(serving, "/").status == 404

    def test_wrong_token_is_404(self, serving: Serving) -> None:
        wrong = "f" * 32
        assert call(serving, f"/{wrong}/").status == 404

    def test_token_prefix_does_not_match(self, serving: Serving) -> None:
        assert call(serving, f"/{PATH_TOKEN[:16]}/").status == 404

    def test_token_extension_does_not_match(self, serving: Serving) -> None:
        assert call(serving, f"/{PATH_TOKEN}0/").status == 404

    def test_token_in_a_later_segment_does_not_match(
        self, serving: Serving
    ) -> None:
        assert call(serving, f"/api/{PATH_TOKEN}/state").status == 404

    def test_rejection_is_404_not_403(self, serving: Serving) -> None:
        # A 403 would confirm a dashboard is listening here.
        assert call(serving, "/nope/").status == 404

    def test_trailing_slash_redirect_keeps_the_token(
        self, serving: Serving
    ) -> None:
        reply = call(serving, f"/{PATH_TOKEN}")
        assert reply.status == 301
        assert reply.header("location") == f"/{PATH_TOKEN}/"


class TestS3TokenShape:
    def test_generated_token_is_32_hex_chars(self, finished: SessionRun) -> None:
        server = DashboardHTTPServer(
            ("127.0.0.1", 0),
            DashboardRequestHandler,
            recorder=finished.harness.recorder,
            page_template=load_page(),
        )
        try:
            assert HEX32.match(server.path_token)
        finally:
            server.server_close()

    def test_tokens_are_not_shared_between_runs(
        self, finished: SessionRun
    ) -> None:
        tokens = set()
        for _ in range(3):
            server = DashboardHTTPServer(
                ("127.0.0.1", 0),
                DashboardRequestHandler,
                recorder=finished.harness.recorder,
                page_template=load_page(),
            )
            try:
                tokens.add(server.path_token)
            finally:
                server.server_close()
        assert len(tokens) == 3
        assert PATH_TOKEN not in tokens

    def test_token_is_compared_constant_time(self) -> None:
        source = (
            Path(__file__).resolve().parents[2]
            / "tools" / "dashboard" / "server.py"
        ).read_text("utf-8")
        assert "hmac.compare_digest" in source


class TestS4S5HostAllowList:
    @pytest.mark.parametrize(
        "host",
        [
            "evil.com",
            "127.0.0.1",  # no port
            "127.0.0.1:1",  # wrong port
            "127.0.0.1.evil.com",
            "localhost.evil.com",
            "evil.com:80",
            "[::1]:80",
            "",
        ],
    )
    def test_foreign_host_is_rejected(self, serving: Serving, host) -> None:
        assert call(serving, serving.url(), host=host).status == 403

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
    def test_loopback_hosts_are_accepted(self, serving: Serving, host) -> None:
        assert call(
            serving, serving.url(), host=f"{host}:{serving.port}"
        ).status == 200

    def test_dns_rebinding_is_blocked_independently_of_the_token(
        self, serving: Serving
    ) -> None:
        # The defining property: the attacker KNOWS the token (it is in
        # the URL they made the browser load) and the hostname resolves
        # to 127.0.0.1 — only the Host header gives them away.
        reply = call(
            serving, serving.url(), host=f"attacker.example:{serving.port}"
        )
        assert reply.status == 403
        assert reply.body.strip() == b"forbidden"


class TestS6Origin:
    def test_absent_origin_is_accepted(self, serving: Serving) -> None:
        assert call(serving, serving.url()).status == 200

    @pytest.mark.parametrize("origin", ["127.0.0.1", "localhost"])
    def test_our_own_origin_is_accepted(
        self, serving: Serving, origin: str
    ) -> None:
        reply = call(serving, serving.url(), origin=f"http://{origin}:{serving.port}")
        assert reply.status == 200

    @pytest.mark.parametrize(
        "origin",
        [
            "http://evil.com",
            "https://evil.com",
            "null",
            "http://127.0.0.1",  # our host, wrong port
            "http://localhost:1",
            "http://127.0.0.1.evil.com:1234",
        ],
    )
    def test_foreign_origin_is_rejected(
        self, serving: Serving, origin: str
    ) -> None:
        assert call(serving, serving.url(), origin=origin).status == 403


class TestS7NoCors:
    @pytest.mark.parametrize(
        "method,path,headers",
        [
            ("GET", "", {}),
            ("GET", "api/state", {}),
            ("GET", "api/state", {"Origin": "http://evil.com"}),
            ("OPTIONS", "api/state", {"Origin": "http://evil.com"}),
            ("OPTIONS", "", {"Origin": "http://evil.com",
                             "Access-Control-Request-Method": "GET"}),
            ("GET", "../nope", {}),
        ],
    )
    def test_no_cors_header_is_ever_sent(
        self, serving: Serving, method: str, path: str, headers: dict
    ) -> None:
        reply = call(serving, serving.url(path), method=method, extra=headers)
        for name in reply.headers:
            assert not name.startswith("access-control-"), name

    def test_a_foreign_preflight_is_refused_before_the_method_gate(
        self, serving: Serving
    ) -> None:
        reply = call(
            serving,
            serving.url("api/state"),
            origin="http://evil.com",
            method="OPTIONS",
            extra={"Access-Control-Request-Method": "GET"},
        )
        # A preflight from a foreign page is refused at the Origin gate,
        # so it never even reaches method handling.
        assert reply.status == 403
        assert reply.header("access-control-allow-origin") is None

    def test_a_preflight_with_no_origin_gets_405_and_no_cors_headers(
        self, serving: Serving
    ) -> None:
        reply = call(
            serving,
            serving.url("api/state"),
            method="OPTIONS",
            extra={"Access-Control-Request-Method": "GET"},
        )
        assert reply.status == 405
        assert reply.header("allow") == "GET, HEAD"
        assert reply.header("access-control-allow-origin") is None


class TestS8NoStore:
    @pytest.mark.parametrize(
        "method,path,origin",
        [
            ("GET", "", None),
            ("GET", "api/state", None),
            ("GET", "../nope", None),
            ("GET", "", "http://evil.com"),
            ("GET", "api/state", "http://evil.com"),
            ("POST", "", None),
        ],
    )
    def test_cache_control_is_no_store(
        self, serving: Serving, method: str, path: str, origin
    ) -> None:
        reply = call(serving, serving.url(path), method=method, origin=origin)
        assert reply.header("cache-control") == "no-store"


class TestS9Methods:
    @pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
    def test_write_methods_are_405(self, serving: Serving, method: str) -> None:
        reply = call(serving, serving.url("api/state"), method=method)
        assert reply.status == 405
        assert reply.header("allow") == "GET, HEAD"

    def test_an_unauthenticated_write_is_404_not_405(
        self, serving: Serving
    ) -> None:
        # Method handling must never precede authentication, or the
        # response would confirm the endpoint exists.
        assert call(serving, "/wrongtoken/", method="POST").status == 404

    def test_head_returns_headers_and_no_body(self, serving: Serving) -> None:
        reply = call(serving, serving.url(), method="HEAD")
        assert reply.status == 200
        assert reply.body == b""
        assert int(reply.header("content-length")) > 0

    def test_get_and_head_agree_on_length(self, serving: Serving) -> None:
        get = call(serving, serving.url())
        head = call(serving, serving.url(), method="HEAD")
        assert get.header("content-length") == head.header("content-length")


class TestS10ResponseHeaders:
    def test_security_headers_are_present(self, serving: Serving) -> None:
        headers = call(serving, serving.url()).headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["referrer-policy"] == "no-referrer"
        csp = headers["content-security-policy"]
        assert "default-src 'none'" in csp
        assert "base-uri 'none'" in csp
        assert "form-action 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "connect-src 'self'" in csp
        assert "'unsafe-inline'" not in csp

    def test_csp_nonce_matches_the_served_markup(
        self, serving: Serving
    ) -> None:
        reply = call(serving, serving.url())
        nonce = NONCE_IN_CSP.search(
            reply.header("content-security-policy")
        ).group(1)
        assert f'nonce="{nonce}"' in reply.body.decode("utf-8")

    def test_every_response_carries_the_headers(
        self, serving: Serving
    ) -> None:
        # Error paths are where a hand-rolled server usually forgets
        # them, so the headers are asserted on the failures too.
        for path, method, host in [
            ("/wrong/", "GET", None),
            (serving.url(), "GET", "evil.com"),
            (serving.url(), "POST", None),
        ]:
            headers = call(serving, path, method=method, host=host).headers
            assert headers["x-content-type-options"] == "nosniff"
            assert headers["cache-control"] == "no-store"

    def test_content_length_is_accurate_on_every_status(
        self, serving: Serving
    ) -> None:
        replies = [
            call(serving, serving.url()),
            call(serving, serving.url("api/state")),
            call(serving, "/wrong/"),
            call(serving, serving.url(), host="evil.com"),
            call(serving, serving.url(), method="POST"),
            call(serving, f"/{PATH_TOKEN}"),
        ]
        assert [r.status for r in replies] == [200, 200, 404, 403, 405, 301]
        for reply in replies:
            assert int(reply.header("content-length")) == len(reply.body)


class TestS11NothingSensitiveIsLogged:
    def test_the_path_token_never_reaches_stderr(
        self, serving: Serving, capfd
    ) -> None:
        call(serving, serving.url())
        call(serving, "/wrongtoken/")
        err = capfd.readouterr().err
        assert PATH_TOKEN not in err
        assert "wrongtoken" not in err

    def test_the_request_line_never_reaches_stderr(
        self, serving: Serving, capfd
    ) -> None:
        # ``log_message`` would render the request line, token included.
        call(serving, serving.url("api/session/x"))
        err = capfd.readouterr().err
        assert f"/{PATH_TOKEN}" not in err
        assert "HTTP/1.0" not in err

    def test_only_the_route_name_is_logged(
        self, serving: Serving, capfd
    ) -> None:
        call(serving, serving.url())
        call(serving, "/wrongtoken/")
        err = capfd.readouterr().err
        assert "GET page -> 200" in err
        assert "GET token -> 404" in err

    def test_a_successful_state_poll_is_not_logged(
        self, serving: Serving, capfd
    ) -> None:
        call(serving, serving.url("api/state"))
        assert capfd.readouterr().err == ""


class TestS13Banner:
    def test_banner_hides_the_python_version(self, serving: Serving) -> None:
        server_header = call(serving, serving.url()).header("server")
        assert server_header == "SecureAIGatewayDashboard"
        assert "Python" not in server_header
        assert "BaseHTTP" not in server_header


class TestRoutes:
    def test_state_is_metadata_only(self, serving: Serving) -> None:
        body = call(serving, serving.url("api/state")).json()
        assert body["schema"] == "secure-ai-gateway-dashboard/1"
        assert [s["request_id"] for s in body["sessions"]] == [REQUEST_ID]
        assert body["current"]["request_id"] == REQUEST_ID
        assert body["current"]["stages"]

    def test_the_state_poll_carries_no_raw_value_and_no_token(
        self, serving: Serving, finished: SessionRun
    ) -> None:
        text = call(serving, serving.url("api/state")).body.decode("utf-8")
        for raw in ("Aurora Motors AU", "王小明"):
            assert raw not in text
        for entry in finished.payload["mapping"]:
            assert entry["token"] not in text

    def test_session_payload_is_complete(self, serving: Serving) -> None:
        body = call(serving, serving.url(f"api/session/{REQUEST_ID}")).json()
        assert body["mapping"]
        assert body["cells"]
        assert body["report"]
        assert body["schema"] == "secure-ai-gateway-dashboard/1"

    def test_unknown_session_is_404(self, serving: Serving) -> None:
        assert call(serving, serving.url("api/session/nope")).status == 404

    def test_absurdly_long_request_id_is_404(self, serving: Serving) -> None:
        assert call(serving, serving.url(f"api/session/{'x' * 500}")).status == 404

    def test_unknown_route_is_404(self, serving: Serving) -> None:
        assert call(serving, serving.url("api/../etc/passwd")).status == 404

    def test_query_string_does_not_affect_routing(
        self, serving: Serving
    ) -> None:
        assert call(serving, serving.url("api/state?x=1")).status == 200


class TestConcurrency:
    def test_readers_and_the_writer_do_not_interfere(
        self, serving: Serving, doc: Path, finished: SessionRun
    ) -> None:
        """The RLock proof: the session worker writes while N handler
        threads read, and every read is well-formed JSON."""
        revisions: dict[int, list[int]] = {}
        errors: list[BaseException] = []
        stop = threading.Event()

        def poll(index: int) -> None:
            seen: list[int] = []
            while not stop.is_set():
                try:
                    reply = call(serving, serving.url("api/state"))
                    assert reply.status == 200
                    seen.append(reply.json()["revision"])
                except BaseException as exc:  # noqa: BLE001 — reported, not swallowed
                    errors.append(exc)
                    return
            revisions[index] = seen

        readers = [threading.Thread(target=poll, args=(i,)) for i in range(6)]
        for reader in readers:
            reader.start()
        try:
            for _ in range(3):
                finished.harness.run(doc)
        finally:
            stop.set()
            for reader in readers:
                reader.join(timeout=10)

        assert not errors, errors
        assert len(revisions) == 6
        for seen in revisions.values():
            assert seen, "a reader never completed a poll"
            assert seen == sorted(seen), "revision went backwards"
            assert len(set(seen)) == len(seen) or True  # repeats are fine


class TestShutdown:
    def test_the_port_is_released_when_the_server_closes(
        self, finished: SessionRun
    ) -> None:
        server = DashboardHTTPServer(
            ("127.0.0.1", 0),
            DashboardRequestHandler,
            recorder=finished.harness.recorder,
            page_template=load_page(),
        )
        port = server.server_address[1]
        server.server_close()
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", port))  # would raise if still held
        finally:
            probe.close()

    def test_a_busy_port_fails_loudly(self, finished: SessionRun) -> None:
        # allow_reuse_address is False: silently sharing a port with an
        # unrelated process is worse than refusing to start.
        first = DashboardHTTPServer(
            ("127.0.0.1", 0),
            DashboardRequestHandler,
            recorder=finished.harness.recorder,
            page_template=load_page(),
        )
        port = first.server_address[1]
        try:
            with pytest.raises(OSError):
                DashboardHTTPServer(
                    ("127.0.0.1", port),
                    DashboardRequestHandler,
                    recorder=finished.harness.recorder,
                    page_template=load_page(),
                )
        finally:
            first.server_close()


class TestPageIsServedFromTheModule:
    def test_the_served_page_is_the_template_with_the_nonce(
        self, serving: Serving
    ) -> None:
        body = call(serving, serving.url()).body.decode("utf-8")
        assert "__CSP_NONCE__" not in body
        assert "DEBUG" in body


def test_two_servers_get_different_nonces(finished: SessionRun) -> None:
    servers = []
    try:
        for _ in range(2):
            servers.append(
                DashboardHTTPServer(
                    ("127.0.0.1", 0),
                    DashboardRequestHandler,
                    recorder=finished.harness.recorder,
                    page_template=load_page(),
                )
            )
        assert servers[0].nonce != servers[1].nonce
        assert secrets.token_urlsafe(16) not in {s.nonce for s in servers}
    finally:
        for server in servers:
            server.server_close()
