"""Document encoding detection and decoding (SR-025 / T-I09).

Fail-closed design: when charset-normalizer cannot decide with
confidence, raise ``EncodingDetectionError`` instead of guessing.
A wrong guess can decode GBK/Big5 Chinese into mojibake that hides
PII from the detectors (T-I09 — encoding-based detection evasion).

Decoding is strict: if the detected encoding cannot decode the bytes,
the file is rejected. A silent ``errors="replace"`` decode would
insert U+FFFD characters into the detection input and mask content.
"""

from __future__ import annotations

from charset_normalizer import from_bytes

from secure_ai_gateway.errors import EncodingDetectionError

# charset-normalizer reports "gb2312" for most GBK data; gbk is a
# superset of gb2312, so decode with the gbk codec to also cover
# GBK-only characters.
_GBK_ALIASES = {"gb2312", "gbk", "gb18030"}
# charset-normalizer occasionally reports "hz", "iso2022_jp", etc. for
# CJK text; only accept the codecs we can map safely. "ascii" is a
# strict subset of UTF-8, so pure-ASCII files are treated as utf_8.
_ACCEPTED = {"ascii", "utf_8", "utf_16", "utf_16_le", "utf_16_be", "big5"} | _GBK_ALIASES

# Chaos > this means the byte stream looks too unpredictable for the
# claimed encoding (fail closed rather than decode noise).
_MAX_CHAOS = 0.6


# CJK-capable codecs: a CJK guess is only accepted when the bytes
# strictly decode AND the text actually contains CJK characters — a
# GBK/Big5 claim on text with no CJK is a guess, not a detection
# (T-I09: mojibake would hide PII from the detectors).
_CJK_FAMILY = {"big5", "big5hkscs"} | _GBK_ALIASES


def _contains_cjk(text: str) -> bool:
    return any("一" <= ch <= "鿿" for ch in text)


def detect_encoding(data: bytes, *, max_chaos: float = _MAX_CHAOS) -> str:
    """Detect the text encoding of ``data``.

    Returns a Python codec name usable with ``bytes.decode``. Raises
    ``EncodingDetectionError`` when detection is inconclusive.

    Short CJK texts (a small GBK CSV, a config file) produce near-zero
    confidence candidates; scanning the full candidate list — not just
    ``best()`` — with a strict-decode + CJK sanity check lets GBK/Big5
    through when the bytes genuinely decode to Chinese, while refusing
    genuinely ambiguous cases (fail closed).
    """
    if not data:
        raise EncodingDetectionError("empty input: cannot detect encoding")

    candidates = list(from_bytes(data))
    if not candidates:
        raise EncodingDetectionError("no candidate encoding found")

    for match in candidates:
        encoding = match.encoding.lower() if match.encoding else ""
        if encoding not in _ACCEPTED:
            continue
        if match.chaos > max_chaos:
            continue
        if encoding in _CJK_FAMILY:
            codec = "gbk" if encoding in _GBK_ALIASES else "big5"
            try:
                text = data.decode(codec)
            except UnicodeDecodeError:
                continue  # the guess cannot decode: fail closed
            if not _contains_cjk(text):
                continue  # a CJK claim with no CJK content is a guess
        if encoding in _GBK_ALIASES:
            return "gbk"
        if encoding == "ascii":
            return "utf_8"
        return encoding
    raise EncodingDetectionError("no confident encoding candidate")


def decode_document(data: bytes, encoding: str) -> str:
    """Strictly decode ``data`` with ``encoding``.

    Any ``UnicodeDecodeError`` becomes ``EncodingDetectionError`` —
    the detected encoding was wrong, so the document must not proceed.
    """
    try:
        return data.decode(encoding)
    except (UnicodeDecodeError, LookupError) as exc:
        raise EncodingDetectionError(
            f"decode failed with detected encoding {encoding!r}"
        ) from exc
