"""The page is a containment boundary, not just a view.

It renders raw PII and the token mapping, so it must not be able to
*reach* anything: no external origin, no HTML sink, no network API
beyond our own two JSON endpoints. Cell values come from an untrusted
document (CLAUDE.md §6.6) and are rendered with ``textContent`` only, so
a document containing markup is displayed as text rather than executed.

Scanned as source text rather than exercised in a browser: there is no
headless browser in this repo, and the claims here are about what the
page *contains*, which is exactly what a source scan can settle.
"""

from __future__ import annotations

import re
from importlib.resources import files

import pytest

from tools.dashboard.server import load_page

PAGE = load_page()

#: Anything that would make the browser open a connection this tool did
#: not intend. ``connect-src 'self'`` blocks these at runtime too — the
#: scan keeps the intent visible in the source, where the CSP cannot.
EXTERNAL = [
    "<script src",
    "<link",
    "<img",
    "<iframe",
    "<embed",
    "<object",
    "@import",
    "@font-face",
    "url(",
    "EventSource",
    "WebSocket",
    "XMLHttpRequest",
    "navigator.sendBeacon",
    "importScripts",
    "http://",
    "https://",
    "//cdn",
    "integrity=",
]

#: HTML sinks. Each would turn a document value into markup — an XSS
#: inside a page that displays raw PII and could read the mapping.
SINKS = [
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "document.writeln",
    "eval(",
    "new Function",
    "setTimeout(\"",
    "setInterval(\"",
    "javascript:",
]


class TestNoExternalReach:
    @pytest.mark.parametrize("needle", EXTERNAL)
    def test_page_contains_no_external_reference(self, needle: str) -> None:
        assert needle not in PAGE, f"page references {needle!r}"

    def test_fonts_are_system_fonts_only(self) -> None:
        families = re.findall(r"font-family:([^;]+);", PAGE)
        assert families
        for family in families:
            assert "http" not in family
            assert ".woff" not in family
            assert ".ttf" not in family

    def test_the_only_fetches_are_our_own_endpoints(self) -> None:
        targets = re.findall(r"fetch\(([^,)]+)", PAGE)
        assert targets, "the page must poll something"
        for target in targets:
            stripped = target.strip().strip('"\'')
            assert stripped.startswith("api/"), stripped

    def test_there_is_no_form_or_credential_field(self) -> None:
        for needle in ("<form", "<input", "password", "localStorage",
                       "sessionStorage", "document.cookie"):
            assert needle not in PAGE, needle


class TestNoHtmlSinks:
    @pytest.mark.parametrize("needle", SINKS)
    def test_page_uses_no_html_sink(self, needle: str) -> None:
        assert needle not in PAGE, f"page uses {needle!r}"

    def test_values_are_written_with_textContent(self) -> None:
        assert "textContent" in PAGE

    def test_elements_are_created_not_parsed(self) -> None:
        assert "document.createElement" in PAGE

    def test_html_helpers_are_documented_as_such(self) -> None:
        # The rule is worth more than the code: a future edit should see
        # why it exists before it reaches for innerHTML.
        assert "textContent ONLY" in PAGE
        assert "untrusted" in PAGE


class TestNonce:
    def test_every_style_and_script_tag_carries_the_nonce(self) -> None:
        tags = re.findall(r"<(?:style|script)\b[^>]*>", PAGE)
        assert len(tags) >= 2
        for tag in tags:
            assert 'nonce="__CSP_NONCE__"' in tag, tag

    def test_no_other_tag_carries_a_nonce(self) -> None:
        assert PAGE.count("__CSP_NONCE__") == len(
            re.findall(r"<(?:style|script)\b[^>]*>", PAGE)
        )

    def test_no_inline_event_handler_attributes(self) -> None:
        # A CSP nonce does not permit inline handlers, and they are the
        # classic way an HTML sink reappears.
        assert not re.search(r"\son[a-z]+\s*=", PAGE)


class TestPageContract:
    def test_page_is_a_complete_document(self) -> None:
        # Without a doctype the browser renders in quirks mode, and the
        # lang attribute is what drives CJK font selection and screen
        # readers on a page that is mostly Chinese.
        assert PAGE.lstrip().startswith("<!doctype html>")
        assert '<html lang="zh-Hant">' in PAGE
        assert "<title>" in PAGE
        assert '<meta charset="utf-8">' in PAGE
        assert PAGE.count("<body>") == 1 and PAGE.count("</body>") == 1
        assert PAGE.rstrip().endswith("</html>")

    def test_debug_banner_is_unmissable(self) -> None:
        assert "DEBUG — 原始值可見" in PAGE

    def test_the_hide_toggle_exists_and_says_it_is_cosmetic(self) -> None:
        assert "隱藏原始值" in PAGE
        assert "顯示原始值" in PAGE  # the toggled-back label

    def test_dark_mode_toggle_exists(self) -> None:
        assert "切換深色" in PAGE
        assert "切換淺色" in PAGE

    def test_polls_once_per_second(self) -> None:
        assert re.search(r"setInterval\(\s*tick\s*,\s*1000\s*\)", PAGE)

    def test_the_page_never_claims_to_be_a_security_control(self) -> None:
        # The blur toggle cannot protect a screen-share, and a reader
        # who believes otherwise is worse off than one who knows.
        assert "不是資安控制項" in PAGE
        assert "視覺模糊" in PAGE
        assert "不構成保護" in PAGE


class TestLoading:
    def test_page_is_loaded_from_the_module_not_from_disk(self) -> None:
        packaged = files("tools.dashboard").joinpath("page.html")
        assert packaged.is_file()
        assert packaged.read_text("utf-8") == PAGE

    def test_loading_does_not_write_anything(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        load_page()
        assert list(tmp_path.iterdir()) == []

    def test_placeholder_is_only_substituted_at_serve_time(self) -> None:
        from tools.dashboard.server import _NONCE_PLACEHOLDER

        assert _NONCE_PLACEHOLDER in PAGE
        assert "nonce-" not in PAGE  # no nonce value is baked in
