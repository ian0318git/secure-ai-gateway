"""Encoding detection: correct detection + fail-closed paths (T-I09)."""

from __future__ import annotations

import os

import pytest

from secure_ai_gateway.encoding import decode_document, detect_encoding
from secure_ai_gateway.errors import EncodingDetectionError

# "陳曉明 財務報告 第二季" — characters present in GBK, Big5, UTF-8
_SAMPLE = "陳曉明 財務報告 第二季"
_GBK_ONLY = "堃"  # 堃 — GBK extension, NOT in GB2312 (superset check)


class TestDetectEncoding:
    def test_utf8(self) -> None:
        assert detect_encoding(_SAMPLE.encode("utf-8")) == "utf_8"

    def test_utf8_with_bom(self) -> None:
        assert detect_encoding(b"\xef\xbb\xbf" + _SAMPLE.encode("utf-8")) == "utf_8"

    def test_gbk(self) -> None:
        assert detect_encoding(_SAMPLE.encode("gbk")) == "gbk"

    def test_gbk_only_extension_char(self) -> None:
        # 堃 is GBK-only; charset-normalizer reports gb2312 and we must
        # decode with the gbk (superset) codec so it round-trips.
        data = _SAMPLE.encode("gbk") + _GBK_ONLY.encode("gbk")
        encoding = detect_encoding(data)
        assert encoding == "gbk"
        assert _GBK_ONLY in decode_document(data, encoding)

    def test_big5(self) -> None:
        assert detect_encoding(_SAMPLE.encode("big5")) == "big5"

    def test_utf16(self) -> None:
        assert detect_encoding(_SAMPLE.encode("utf-16")) == "utf_16"

    def test_ascii_is_utf8(self) -> None:
        assert detect_encoding(b"revenue 8.4M cost 5.7M") == "utf_8"

    def test_empty_input_fails_closed(self) -> None:
        with pytest.raises(EncodingDetectionError):
            detect_encoding(b"")

    def test_random_binary_fails_closed(self) -> None:
        with pytest.raises(EncodingDetectionError):
            detect_encoding(os.urandom(512))

    def test_truncated_utf16_fails_closed(self) -> None:
        data = _SAMPLE.encode("utf-16")[:-1]
        with pytest.raises(EncodingDetectionError):
            detect_encoding(data)


class TestDecodeDocument:
    def test_roundtrip(self) -> None:
        data = _SAMPLE.encode("gbk")
        assert decode_document(data, "gbk") == _SAMPLE

    def test_wrong_encoding_is_strict(self) -> None:
        data = _SAMPLE.encode("big5")
        with pytest.raises(EncodingDetectionError):
            decode_document(data, "utf-8")
