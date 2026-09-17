"""Scope containment: the tool cannot widen the gateway's attack surface.

Three claims, each of which would be a silent architectural change if it
stopped holding:

**C3 — the tool never emits to the log stream.** ``log_event`` is
fail-loud about forbidden field *names* (``logging.py``), so a caller
that passes raw data under an innocuous key defeats it. ``tools/``
therefore never calls it at all — it only *reads* the sanitised stream
through a ``logging.Handler``.

**C4 — nothing is written.** No dump file, no cache, no report on disk.
The repo tree is byte-for-byte identical after a full session and a
served request, with every write path made to fail loudly.

**C6 — the gateway cannot depend on the tool.** ``tools/`` sits outside
the packaged distribution, and nothing under ``src/`` imports it, so
the one-way dependency is structural rather than a convention.
"""

from __future__ import annotations

import ast
import builtins
import io
import os
import sys
import threading
import tomllib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest
from conftest import Harness, SessionRun, span

from secure_ai_gateway.models import EntityType
from tools.dashboard.server import (
    DashboardHTTPServer,
    DashboardRequestHandler,
    load_page,
)

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "tools"
SRC = REPO / "src"

#: Every API that EMITS a record. ``addHandler``/``setLevel`` are not
#: here: attaching a tap and restoring a level change what happens to
#: records, not what records exist.
EMITTERS = frozenset(
    {
        "debug",
        "info",
        "warning",
        "warn",
        "error",
        "exception",
        "critical",
        "fatal",
        "log",
    }
)

#: Generated directories that a Python process is entitled to touch.
IGNORED_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".hypothesis",
    }
)


def python_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.py"))


def tree(root: Path) -> ast.Module:
    return ast.parse(root.read_text("utf-8"), filename=str(root))


def calls(node: ast.Module) -> list[ast.Call]:
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)]


def called_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


class TestC3NoLogEmission:
    def test_tools_never_calls_log_event(self) -> None:
        for path in python_files(TOOLS):
            offenders = [
                call
                for call in calls(tree(path))
                if called_name(call) == "log_event"
            ]
            assert not offenders, f"{path} calls log_event"

    def test_tools_never_imports_log_event(self) -> None:
        # Imported by name, it could be called from anywhere; the
        # gateway's log_event is fail-loud about forbidden field NAMES
        # only, so a raw value under an innocuous key would sail past it.
        for path in python_files(TOOLS):
            for node in ast.walk(tree(path)):
                if isinstance(node, ast.Import):
                    assert all(
                        not alias.name.endswith("log_event")
                        for alias in node.names
                    ), path
                elif isinstance(node, ast.ImportFrom):
                    assert all(
                        alias.name != "log_event" for alias in node.names
                    ), path

    def test_tools_never_emits_to_any_logger(self) -> None:
        for path in python_files(TOOLS):
            for call in calls(tree(path)):
                name = called_name(call)
                if name in EMITTERS and isinstance(call.func, ast.Attribute):
                    raise AssertionError(
                        f"{path}:{call.lineno} emits via .{name}()"
                    )

    def test_the_recorder_reads_the_stream_without_writing_it(self) -> None:
        source = (TOOLS / "dashboard" / "recorder.py").read_text("utf-8")
        assert "logging.getLogger" in source
        assert "addHandler" in source  # attaching the tap
        assert "removeHandler" in source  # and detaching it
        assert "setLevel" in source  # restoring the level on exit

    def test_cli_only_touches_logging_to_quiet_a_third_party(self) -> None:
        # The one other logging contact: Presidio chatters about
        # recogniser loading, which would bury the gateway's own audit
        # lines. It configures; it does not emit.
        source = (TOOLS / "dashboard" / "cli.py").read_text("utf-8")
        assert 'logging.getLogger("presidio-analyzer")' in source
        assert "logging.basicConfig(" in source
        assert "stream=sys.stderr" in source  # never a file

    def test_no_module_installs_a_file_handler(self) -> None:
        for path in python_files(TOOLS):
            source = path.read_text("utf-8")
            assert "FileHandler" not in source, path
            assert "RotatingFileHandler" not in source, path


class TestNoUndeclaredDependencies:
    ALLOWED = frozenset({"secure_ai_gateway", "tools", "__future__"})

    @pytest.mark.parametrize(
        "path", python_files(TOOLS), ids=lambda p: p.name
    )
    def test_only_stdlib_and_the_gateway_are_imported(self, path: Path) -> None:
        roots: set[str] = set()
        for node in ast.walk(tree(path)):
            if isinstance(node, ast.Import):
                roots.update(a.name.split(".")[0] for a in node.names)
            elif (
                isinstance(node, ast.ImportFrom)
                and node.level == 0
                and node.module
            ):
                roots.add(node.module.split(".")[0])
        unexpected = roots - self.ALLOWED - set(sys.stdlib_module_names)
        assert not unexpected, f"{path.name} imports {sorted(unexpected)}"


class TestC6TheGatewayCannotDependOnTheTool:
    def test_the_distribution_is_found_only_under_src(self) -> None:
        data = tomllib.loads((REPO / "pyproject.toml").read_text("utf-8"))
        where = data["tool"]["setuptools"]["packages"]["find"]["where"]
        assert where == ["src"]

    def test_no_package_data_rule_reaches_into_tools(self) -> None:
        data = tomllib.loads((REPO / "pyproject.toml").read_text("utf-8"))
        package_data = (
            data.get("tool", {}).get("setuptools", {}).get("package-data", {})
        )
        for key, patterns in package_data.items():
            for pattern in patterns:
                assert "tools" not in pattern, (key, pattern)

    def test_tools_lives_outside_src(self) -> None:
        assert TOOLS.is_dir()
        assert not str(TOOLS).startswith(str(SRC))

    @pytest.mark.parametrize(
        "path",
        sorted((SRC / "secure_ai_gateway").rglob("*.py")),
        ids=lambda p: p.name,
    )
    def test_nothing_under_src_imports_the_tool(self, path: Path) -> None:
        for node in ast.walk(tree(path)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("tools")
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("tools")

    def test_nothing_under_src_names_the_dashboard(self) -> None:
        for path in (SRC / "secure_ai_gateway").rglob("*.py"):
            source = path.read_text("utf-8")
            assert "dashboard" not in source.lower(), path

    def test_src_is_untouched_by_this_change(self) -> None:
        # The tool is built entirely on pre-existing public extension
        # points. Any edit under src/ would be a change to the gateway
        # that the plan did not authorise.
        import subprocess

        result = subprocess.run(
            ["git", "status", "--porcelain", "--", "src"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == "", result.stdout


@contextmanager
def forbid_writes():
    """Make every file-writing path raise, so a write is a failure
    rather than an observation."""
    real_open = builtins.open
    real_io_open = io.open
    real_os_open = os.open
    attempts: list[str] = []

    def refuse(what: str, target):
        attempts.append(f"{what} {target!r}")
        raise AssertionError(f"dashboard wrote a file: {what} {target!r}")

    def guarded_open(file, mode="r", *args, **kwargs):
        if any(flag in str(mode) for flag in ("w", "a", "x", "+")):
            refuse(f"open(mode={mode!r})", file)
        return real_open(file, mode, *args, **kwargs)

    def guarded_io_open(file, mode="r", *args, **kwargs):
        if any(flag in str(mode) for flag in ("w", "a", "x", "+")):
            refuse(f"io.open(mode={mode!r})", file)
        return real_io_open(file, mode, *args, **kwargs)

    def guarded_os_open(path, flags, *args, **kwargs):
        writing = (
            os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
        )
        if flags & writing:
            refuse(f"os.open(flags={flags})", path)
        return real_os_open(path, flags, *args, **kwargs)

    builtins.open = guarded_open
    io.open = guarded_io_open
    os.open = guarded_os_open
    try:
        yield attempts
    finally:
        builtins.open = real_open
        io.open = real_io_open
        os.open = real_os_open


def snapshot(root: Path) -> set[tuple[str, int, int]]:
    seen: set[tuple[str, int, int]] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix in (".pyc", ".pyo"):
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            seen.add(
                (str(path.relative_to(root)), stat.st_size, stat.st_mtime_ns)
            )
    return seen


@dataclass
class Served:
    server: DashboardHTTPServer
    thread: threading.Thread
    port: int


def serve(recorder) -> Served:
    server = DashboardHTTPServer(
        ("127.0.0.1", 0),
        DashboardRequestHandler,
        recorder=recorder,
        page_template=load_page(),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return Served(server, thread, server.server_address[1])


def fetch(served: Served, token: str, path: str) -> bytes:
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", served.port, timeout=10)
    try:
        conn.request(
            "GET",
            f"/{token}/{path}",
            headers={"Host": f"127.0.0.1:{served.port}"},
        )
        response = conn.getresponse()
        body = response.read()
        assert response.status == 200, response.status
        return body
    finally:
        conn.close()


class TestC4NothingIsWritten:
    def test_a_full_session_writes_nothing(
        self, doc: Path, person_spans, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        with forbid_writes() as attempts:
            harness = Harness(
                spans_by_cell=person_spans,
                instruction_spans=(
                    span(EntityType.PERSON, 0, 3, "王小明"),
                ),
            )
            run = harness.run(doc, instruction="王小明 的毛利率")
            body = run.payload["payload"]["body"]
            assert body  # the run really did produce a request
        assert attempts == []

    def test_serving_requests_writes_nothing(
        self, finished: SessionRun, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        with forbid_writes() as attempts:
            served = serve(finished.harness.recorder)
            try:
                token = served.server.path_token
                page = fetch(served, token, "")
                state = fetch(served, token, "api/state")
                session = fetch(
                    served, token, f"api/session/{finished.payload['request_id']}"
                )
            finally:
                served.server.shutdown()
                served.server.server_close()
                served.thread.join(timeout=10)
        assert page.startswith(b"<!doctype html>")
        assert state and session
        assert attempts == []

    def test_the_repo_tree_is_unchanged_by_a_run(
        self, doc: Path, person_spans
    ) -> None:
        before = snapshot(REPO)
        harness = Harness(spans_by_cell=person_spans)
        harness.run(doc, instruction="請分析")
        harness.recorder.purge_finished_before(10**12)
        after = snapshot(REPO)
        assert before == after, sorted(after ^ before)[:10]

    def test_the_repo_tree_is_unchanged_by_serving(
        self, finished: SessionRun
    ) -> None:
        before = snapshot(REPO)
        served = serve(finished.harness.recorder)
        try:
            fetch(served, served.server.path_token, "api/state")
        finally:
            served.server.shutdown()
            served.server.server_close()
            served.thread.join(timeout=10)
        assert snapshot(REPO) == before

    def test_no_dump_directory_exists(self) -> None:
        assert not (TOOLS / "dashboard" / "_dumps").exists()


class TestGitignoreCoversAccidentalDumps:
    """The recorder never writes, so these are second-line defences for
    a future edit — checked here so the guard cannot be dropped
    silently."""

    @pytest.mark.parametrize(
        "pattern", ["*-dashboard.json", "*.mapping.json"]
    )
    def test_gitignore_refuses_dashboard_dumps(self, pattern: str) -> None:
        text = (REPO / ".gitignore").read_text("utf-8")
        assert pattern in text

    def test_gitignore_does_not_ignore_html_wholesale(self) -> None:
        # A blanket ``*.html`` would silently untrack page.html and
        # docs/gateway_example.html.
        lines = {
            line.strip()
            for line in (REPO / ".gitignore").read_text("utf-8").splitlines()
        }
        assert "*.html" not in lines

    def test_page_html_is_tracked(self) -> None:
        import subprocess

        result = subprocess.run(
            [
                "git",
                "ls-files",
                "--error-unmatch",
                "tools/dashboard/page.html",
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, "page.html is not tracked by git"
