"""Deterministic prompt-injection detector (docs/DESIGN.md §11).

Static pattern tables, no LLM involved. English patterns use word
boundaries; Chinese patterns are substring matches (no word
boundaries in CJK). Input text must already be NFKC-normalised.

Severity semantics (docs/DECISIONS.md):
- instruction finding (any severity)      -> block the whole request
- document cell finding severity >= 3     -> block the whole request
- document cell finding severity < 3      -> drop the cell + flag

The unit tests require ZERO findings on a clean financial-sentence
control set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from secure_ai_gateway.models import InjectionCategory, InjectionFinding


@dataclass(frozen=True, slots=True)
class _Pattern:
    pattern_id: str
    category: InjectionCategory
    severity: int
    regex: re.Pattern | None
    zh_substrings: tuple[str, ...] = ()


_EN = lambda p: re.compile(p, re.IGNORECASE)  # noqa: E731

_PATTERNS: tuple[_Pattern, ...] = (
    # --- OVERRIDE_DIRECT (severity 3) ---
    _Pattern(
        "od01",
        InjectionCategory.OVERRIDE_DIRECT,
        3,
        _EN(r"\bignore (?:all|the|any|everything)\b.{0,24}"
            r"\b(?:previous|above|prior|earlier) instructions?\b"),
        ("忽略之前的指示", "忽略以上指示", "無視之前指令",
         "忘掉之前的指示", "忽略所有指示", "忽略先前指令"),
    ),
    _Pattern(
        "od02",
        InjectionCategory.OVERRIDE_DIRECT,
        3,
        _EN(r"\bdisregard\b.{0,24}\binstructions?\b"),
        (),
    ),
    # --- OVERRIDE_SYSTEM (severity 3) ---
    _Pattern(
        "os01",
        InjectionCategory.OVERRIDE_SYSTEM,
        3,
        _EN(r"\b(?:you are|you're|act as|pretend(?: to be)?)\b.{0,20}"
            r"\b(?:system|admin|assistant)\b"),
        ("你現在是", "現在你是", "扮演系統", "你是系統",
         "覆寫系統", "覆蓋系統", "取代系統"),
    ),
    _Pattern(
        "os02",
        InjectionCategory.OVERRIDE_SYSTEM,
        3,
        _EN(r"\b(?:override|replace)\b.{0,20}\bsystem prompt\b"),
        (),
    ),
    # --- REVEAL (severity 3) ---
    _Pattern(
        "rv01",
        InjectionCategory.REVEAL,
        3,
        _EN(r"\b(?:output|print|show|reveal|return|display)\b.{0,24}"
            r"\b(?:original|raw|real|actual)\b.{0,24}"
            r"\b(?:name|names|value|values|data|content|mapping)\b"),
        ("輸出原始", "顯示原始", "回覆原始", "原始名稱", "真實名稱",
         "還原原始", "不要用代碼", "直接給原始"),
    ),
    _Pattern(
        "rv02",
        InjectionCategory.REVEAL,
        3,
        _EN(r"\b(?:what|which) (?:is|was|were) the (?:original|real)\b"),
        ("原本叫什麼", "原名是什麼"),
    ),
    # --- DELIMITER (severity 2) ---
    _Pattern(
        "dl01",
        InjectionCategory.DELIMITER,
        2,
        _EN(r"<\|(?:im_start|im_end|system|user|assistant)\|>|"
            r"^\s*(?:system|user|assistant)\s*:\s*|"
            r"###\s*(?:instruction|system)\b"),
        ("系統:", "用戶:", "系統指令:"),
    ),
    # --- TOKEN_PROBE (severity 3) ---
    _Pattern(
        "tp01",
        InjectionCategory.TOKEN_PROBE,
        3,
        _EN(r"\b(?:token|tokens)\b.{0,24}\b(?:mapping|mappings|vault|map)\b|"
            r"\b(?:print|list|show|reveal)\b.{0,16}\b(?:tokens?)\b"),
        ("代碼對應", "對應關係", "列出代碼", "代碼映射", "印出代碼"),
    ),
    _Pattern(
        "tp02",
        InjectionCategory.TOKEN_PROBE,
        3,
        _EN(r"\bde-?tokeni[sz]e\b"),
        ("還原代碼", "解開代碼"),
    ),
    # --- ROLE_HIJACK (severity 3) ---
    _Pattern(
        "rh01",
        InjectionCategory.ROLE_HIJACK,
        3,
        _EN(r"\bi am (?:the|your)?\s*(?:admin|administrator|creator|"
            r"developer|supervisor|boss)\b|\byou must obey me\b"),
        ("我是管理員", "我是系統管理員", "你必須服從", "我是你的開發者",
         "我是你的創建者"),
    ),
    # --- POLICY_MANIP (severity 3) ---
    _Pattern(
        "pm01",
        InjectionCategory.POLICY_MANIP,
        3,
        _EN(r"\b(?:bypass|ignore|disable|remove|skip)\b.{0,20}"
            r"\b(?:policy|security policy|filter|restrictions?|rules?)\b"),
        ("繞過政策", "忽略安全政策", "關閉過濾", "沒有限制",
         "取消限制", "忽略政策", "關閉安全"),
    ),
    _Pattern(
        "pm02",
        InjectionCategory.POLICY_MANIP,
        3,
        _EN(r"\b(?:no|without|unlimited)\b.{0,12}"
            r"\b(?:restrictions?|limits?|boundaries?)\b"),
        (),
    ),
)


def detect(text: str, location: str) -> tuple[InjectionFinding, ...]:
    """Scan ``text`` (NFKC-normalised) for injection patterns.

    ``location`` is "instruction" or a cell_id. One finding per
    pattern, first match only; results sorted by severity desc then
    category then pattern id (deterministic).
    """
    findings: list[InjectionFinding] = []
    for pattern in _PATTERNS:
        if pattern.regex is not None and pattern.regex.search(text):
            findings.append(
                InjectionFinding(
                    category=pattern.category,
                    severity=pattern.severity,
                    location=location,
                    pattern_id=pattern.pattern_id,
                    matched_text=_matched(pattern, text),
                )
            )
            continue
        for substring in pattern.zh_substrings:
            if substring in text:
                findings.append(
                    InjectionFinding(
                        category=pattern.category,
                        severity=pattern.severity,
                        location=location,
                        pattern_id=pattern.pattern_id,
                        matched_text=substring,
                    )
                )
                break
    return tuple(
        sorted(
            findings,
            key=lambda f: (-f.severity, f.category.value, f.pattern_id),
        )
    )


def _matched(pattern: _Pattern, text: str) -> str:
    if pattern.regex is not None:
        match = pattern.regex.search(text)
        if match:
            return match.group(0)[:80]
    for substring in pattern.zh_substrings:
        if substring in text:
            return substring
    return ""
