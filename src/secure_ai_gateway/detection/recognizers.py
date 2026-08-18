"""Deterministic custom recognisers (M1, all zh-oriented).

These replace presidio's default recognisers entirely (docs/DECISIONS.md:
no English-only fallback). Format entities are matched by regex and
validated by ``validate_result`` where possible:

- EMAIL: TLD sanity (2-6 alpha chars)
- CREDIT_CARD: Luhn check
- API_KEY: prefix + Shannon entropy >= 3.5 on >= 20 chars
- JWT: three base64url segments, header decodes
- TW_ID: checksum computed and REPORTED as a flag — invalid checksums
  are still detected (benchmark data is checksum-invalid by
  construction, docs/BENCHMARK.md §2.1)
- PERSON fallback: surname dictionary + 1-2 given chars, with a
  deny-list of common business words that start with a surname
  (e.g. 陳列, 黃金) to control false positives
"""

from __future__ import annotations

import base64
import math
import re
import string

from presidio_analyzer import Pattern, PatternRecognizer

from secure_ai_gateway.models import EntityType

_HEX = set(string.hexdigits)
_B64URL = set(string.ascii_letters + string.digits + "_-")

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# ASCII only; full-width chars are NFKC-normalised by the parser.
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{3,64}@"
    r"[A-Za-z0-9.-]{2,128}\.[A-Za-z]{2,6})(?![A-Za-z0-9])"
)

# TW mobile 09xx-xxxxxx, TW landline 0x-xxxxxxx (+886 variants, CN
# mobile). Landline area codes are 02-08; 0[2-8] excludes "09..." runs
# of 8 digits, which are not a real landline format.
_PHONE_RE = re.compile(
    r"(?<!\d)(?:(?:\+?886[- ]?)?0?9\d{8}|0[2-8][- ]?\d{7,8}"
    r"|1[3-9]\d{9})(?!\d)"
)

_TW_ID_RE = re.compile(r"(?<![A-Za-z0-9])([A-Z][12]\d{8})(?![A-Za-z0-9])")

_CREDIT_CARD_RE = re.compile(
    r"(?<!\d)(?:\d{4}[- ]?){3}\d{1,7}(?!\d)"
)

_API_KEY_RE = re.compile(
    # ASCII word boundaries only: \w in re matches CJK ideographs
    # (re.UNICODE default), which would hide keys embedded in Chinese
    # text — an easy detection-evasion trick (T-I03).
    r"(?i)(?<![A-Za-z0-9_])(?:sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}"
    r"|AIza[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,})(?![A-Za-z0-9_])"
)

_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
    r"[A-Za-z0-9_-]{10,})(?![A-Za-z0-9_-])"
)

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)

_SECRET_KV_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(password|passwd|pwd|secret|api[_-]?key|"
    r"apisecret|access[_-]?key|secret[_-]?key|credential)"
    r"\s*[:=：＝]\s*([A-Za-z0-9_\-./+=]{8,64})(?![A-Za-z0-9_])"
)
_SECRET_ZH_RE = re.compile(
    r"(密碼|金鑰|密鑰)([:：]|是|為)\s*"
    r"([A-Za-z0-9_\-./+=]{8,64})"
)

# Longest prefix first; the (?!OMER)/(?!LOYEE) guards stop the body
# from swallowing the longer-prefix continuation ("CUST"+"OMER" would
# otherwise match inside "CUSTOMER..." with a short span).
_CUSTOMER_ID_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:CUSTOMER|CUST(?!OMER))[-_]?"
    r"[A-Z0-9]{4,16}(?![A-Za-z0-9])"
)
_EMPLOYEE_ID_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:EMPLOYEE|EMP(?!LOYEE))[-_]?"
    r"[A-Z0-9]{4,16}(?![A-Za-z0-9])"
)

# Reserved token format (T-T03 / SR-023): uppercase prefix + 6 hex.
_TOKEN_PATTERN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(CUSTOMER|EMPLOYEE|EMAIL|PHONE|ADDRESS|LOCATION)"
    r"_([0-9a-f]{6})(?![A-Za-z0-9_])"
)

_BANK_ACCOUNT_RE = re.compile(r"(?<!\d)(\d{10,14})(?!\d)")

# Chinese address skeleton (plan: 縣市區…路/街/大道+段/巷/弄/號, score 0.65).
# NFKC-normalised input, so full-width digits/letters are already
# half-width. The skeleton deliberately covers canonical TW addresses
# (city + district + road + section/lane/alley + number); NER LOCATION
# spans overlapping it lose in resolution (ADDRESS > LOCATION family).
_CITY = (
    "台北|新北|桃園|台中|台南|高雄|基隆|新竹|嘉義|宜蘭|花蓮|台東|"
    "苗栗|彰化|南投|雲林|屏東|澎湖|金門|連江"
)
_ADDRESS_RE = re.compile(
    rf"(?:{_CITY})(?:縣|市)"  # county/city: 台中市
    rf"(?:[一-鿿]{{1,4}}(?:區|鄉|鎮|市))?"  # district: 西屯區 (optional)
    rf"[一-鿿]{{1,6}}(?:路|街|大道)"  # road: 台灣大道 / 中山北路
    rf"(?:[一二三四五六七八九十]{{1,2}}段)?"  # section: 三段
    rf"(?:[\d一二三四五六七八九十]{{1,2}}巷)?"  # lane: 12巷
    rf"(?:[\d一二三四五六七八九十]{{1,2}}弄)?"  # alley: 3弄
    rf"(?:[一二三四五六七八九十]+\d*|\d{{1,4}})號"  # number: 789號 / 八號
    rf"(?:之[\d一二三四五六七八九十]{{1,2}})?"  # 之1
    # No trailing CJK guard: Chinese prose glues particles (之/於/的)
    # directly onto nouns — a guard would hide addresses embedded in
    # sentences (measured: 0 FPs on 2500 negative cells without it).
)

_COMPANY_ZH_RE = re.compile(
    r"[一-鿿]{2,8}(公司|集團|科技|實業|企業|控股|股份|"
    r"貿易|建設|工業|銀行|證券|保險|基金|信託|顧問|資訊|電子|能源|"
    r"國際|全球|開發|投資)"
    # No trailing CJK guard (see _ADDRESS_RE): 股份有限公司之… is
    # ordinary prose. The suffix list itself is the precision anchor.
)

# Common Chinese surnames (top ~100 by population).
_SURNAMES = (
    "王李張劉陳楊黃趙吳周徐孫馬朱胡郭何高林羅鄭梁謝宋唐許韓馮鄧曹"
    "彭曾蕭田董潘袁蔣蔡余杜葉程蘇魏呂丁任沈姚盧姜崔鍾譚陸汪范金石"
    "廖賈夏韋付方白鄒孟熊秦邱江尹薛閆段雷侯龍史陶黎賀顧毛郝龔邵萬"
    "錢嚴覃武戴莫孔向湯"
)

# Person-context words: a name directly following one of these is a
# person reference (prefixed fallback mode); the NER PERSON noise
# filter (engine.py) drops spans equal to one of these.
_PERSON_CONTEXT_WORDS = frozenset(
    ["客戶", "供應商", "聯絡人", "付款人", "負責人", "申請人", "簽約人", "承辦人", "經辦人", "業務員", "廠商", "員工", "戶名", "甲方", "乙方", "帳上"]
)

# Names are allowed to be followed by prose particles (之/於/的/是…)
# or punctuation; the deny-list + validate_result catch the
# surname-initial business words (毛利率/高雄港/萬元 …) that also
# end before punctuation. Everything else (為/為數/… mid-word CJK) is
# still a hard boundary.
_PERSON_TRAILING = r"(?=[之於的是，。；、！？：\s]|$)"

# Standalone mode: no CJK/ASCII before the name.
_PERSON_RE = re.compile(
    rf"(?<![一-鿿A-Za-z0-9])([{_SURNAMES}][一-鿿]{{1,2}}){_PERSON_TRAILING}"
)

# Embedded mode: a name directly after a person-context word
# (客戶X於… / 帳上X之…) that the NER misses. The context word anchors
# the match, so no CJK lookbehind is needed.
_PERSON_PREFIX_RE = re.compile(
    rf"(?:{'|'.join(sorted(_PERSON_CONTEXT_WORDS, key=len, reverse=True))})"
    rf"(?:為|是)?([{_SURNAMES}][一-鿿]{{1,2}}){_PERSON_TRAILING}"
)

# English full names (the zh NER misses "Alice Miller 的Email…").
# First word not a month, second word not a business term:
# validated in validate_result.
_PERSON_EN_RE = re.compile(
    r"(?<![A-Za-z])([A-Z][a-z]{1,12} [A-Z][a-z]{1,12})"
    r"(?=[的，。；、！？：\s]|$)"
)

_PERSON_EN_DENY_FIRST = frozenset(
    ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December", "Q1", "Q2", "Q3", "Q4"]
)
_PERSON_EN_DENY_SECOND = frozenset(
    ["Sales", "Revenue", "Margin", "Growth", "Report", "Office", "Region", "Market", "Team", "Year", "Quarter", "Rate", "Index", "Ratio", "Plan", "Budget", "Division", "Section", "Department", "Summary", "Update", "Strategy"]
)

# Common words that start with a surname but are NOT names (FP control).
# Extensions below are benchmark-measured (docs/DECISIONS.md):
# surname-initial financial terms (毛利率 萬元 現金流量 …), city
# names (高雄港 台北 …), and person-context role words (客戶 付款人 …)
# that the zh NER mislabels as PERSON.
#
# Exact-match deny words: business words that can also be a real
# name's prefix (王國X, 黃金X, 白雲X …), so they are checked as whole
# strings only — a 王國明 must not be denied because 王國 (kingdom)
# is a word.
_PERSON_DENY_WORDS = frozenset(
    ["陳列", "陳述", "陳情", "陳年", "陳舊", "林業", "林場", "林木", "黃昏", "黃金", "黃色", "黃牛", "王國", "王子", "王朝", "王位", "王后", "李樹", "周邊", "周圍", "周全", "周年", "週期", "週末", "週年", "錢財", "孫子", "孫女", "孫中山", "趙雲", "中國", "中華", "中間", "中旬", "中和", "中繼", "高級", "高層", "高峰", "高點", "高價", "高風險", "高科技", "高等", "高空", "高山", "高原", "高速", "高度", "高端", "高收益", "高成長", "高回報", "和諧", "和平", "和氣", "何在", "何時", "何處", "何如", "何謂", "謝禮", "韓愈", "蘇州", "蘇打", "馬匹", "馬車", "馬達", "馬力", "馬上", "馬年", "猴子", "熊市", "熊掌", "龍頭", "龍舟", "龍年", "馮唐", "董卓", "董座", "董事", "彭祖", "蔡司", "余額", "余下", "傅雷", "秦朝", "唐朝", "唐宋", "宋詞", "明清", "清朝", "民國", "漢朝", "漢語", "漢字", "魏晉", "陸軍", "陸地", "大陸", "范圍", "範疇", "石頭", "石料", "金錢", "金庫", "金額", "金屬", "金管會", "銀兩", "銀行", "白銀", "白紙", "白條", "白天", "白云", "方針", "方向", "方便", "方法", "方式", "方位", "東風", "東方", "東岸", "南方", "南北", "南區", "孟姜女", "孔廟", "孔子", "湯圓", "湯頭", "康復", "康德", "安和", "安全", "安定", "常識", "平常", "經常", "簡報", "簡易", "簡稱", "詹天佑", "施政", "施展", "洪流", "洪水", "洪水猛獸", "溫泉", "溫度", "溫暖", "歐陽", "文書", "文章", "文化", "文書處理", "章節", "章魚", "華盛頓", "華人", "華爾街", "華航", "費率", "費用", "費心", "池水", "池塘", "湯水", "嚴肅", "嚴格", "嚴重", "嚴謹", "柳樹", "柳葉", "花園", "花卉", "范仲淹", "葉子", "葉片", "草率", "黃昏後"]
)

# Prefix-match deny words (benchmark-measured, docs/DECISIONS.md):
# surname-initial financial terms (金額/毛利/萬元 …), city names and
# role words — none of these can begin a real name (金額X/高雄X/萬元X
# are not people), so the first 2/3 chars of any fallback match are
# checked against them. Catches the greedy extension 金額已 while an
# exact-match list would miss it. (王國/黃金/白雲 stay exact-match:
# 王國X IS a real name shape.)
_PERSON_DENY_PREFIX_WORDS = frozenset(
    ["金額", "金庫", "金錢", "金管會", "銀行", "白銀", "白紙", "白條", "白天", "白云", "毛利率", "淨利率", "收益率", "匯率", "利率", "單價", "毛利", "萬元", "金流量", "現金流量", "高雄港", "高雄", "台北", "台中", "台南", "新北", "桃園", "基隆", "花蓮", "台東", "苗栗", "彰化", "南投", "雲林", "屏東", "澎湖", "金門", "連江", "客戶", "付款人", "供應商", "聯絡人", "負責人", "申請人", "簽約人", "承辦人", "經辦人", "業務員", "戶名", "廠商", "員工"]
)

# NER PERSON spans that are exactly a deny-listed or context word are
# mislabels (業務員/客戶/付款人 …) and are dropped in engine.py.
_PERSON_NOISE_WORDS = (
    _PERSON_DENY_WORDS | _PERSON_DENY_PREFIX_WORDS | _PERSON_CONTEXT_WORDS
)

_TITLES = (
    "先生小姐女士太太總經理副總經理董事長執行長財務長技術長營運長"
    "經理副理課長組長處長部長主任專員顧問會計出納業務採購工程師"
    "主管員工同仁"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pattern(name: str, regex: re.Pattern[str], score: float) -> Pattern:
    """presidio's Pattern requires the regex as a STRING (it re-compiles
    with its own flags via the ``regex`` module); unwrap compiled ones."""
    return Pattern(name, regex.pattern, score)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _luhn_ok(digits: str) -> bool:
    if len(digits) < 13:
        return False
    total = 0
    double = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


def _tw_id_checksum(letter: str, digits: str) -> bool:
    """Validate the TW ID check digit.

    Standard ROC ID format: one letter + 9 digits, the 9th digit being
    the check digit (weight 1). Malformed input is rejected (False),
    never an IndexError — fail closed.
    """
    values = {c: i + 10 for i, c in enumerate("ABCDEFGHJKLMNPQRSTUVXYWZIO")}
    if letter not in values or len(digits) != 9:
        return False
    number = values[letter]
    total = (number // 10) + (number % 10) * 9
    weights = (8, 7, 6, 5, 4, 3, 2, 1, 1)
    for i, ch in enumerate(digits):
        total += int(ch) * weights[i]
    return total % 10 == 0


def _is_b64url(value: str) -> bool:
    return all(ch in _B64URL for ch in value)


def _jwt_header_ok(header: str) -> bool:
    if not _is_b64url(header):
        return False
    pad = "=" * (-len(header) % 4)
    try:
        raw = base64.urlsafe_b64decode(header + pad)
    except (ValueError, TypeError):
        return False
    text = raw.decode("utf-8", "replace")
    return '"alg"' in text and '"typ"' in text


# ---------------------------------------------------------------------------
# Recogniser builders
# ---------------------------------------------------------------------------


class EmailRecognizerZh(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.EMAIL.value,
            name="email_zh",
            supported_language="zh",
            patterns=[_pattern("EMAIL_ZH", _EMAIL_RE, 0.7)],
        )


class PhoneRecognizerZh(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.PHONE.value,
            name="phone_zh",
            supported_language="zh",
            patterns=[_pattern("PHONE_ZH", _PHONE_RE, 0.7)],
        )


class CreditCardRecognizerZh(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.CREDIT_CARD.value,
            name="credit_card_zh",
            supported_language="zh",
            patterns=[_pattern("CC_ZH", _CREDIT_CARD_RE, 0.6)],
        )

    def validate_result(self, pattern_text: str) -> bool:
        digits = re.sub(r"[-\s]", "", pattern_text)
        return _luhn_ok(digits)


class TwIdRecognizerZh(PatternRecognizer):
    """TW ID: always flagged; checksum validity reported as a flag.

    No ``validate_result``: the regex already guarantees the format,
    and presidio would set MAX_SCORE (1.0) on any validated match,
    overriding the designed 0.8. The engine computes the checksum
    flag (checksum-invalid IDs are still detected, BENCHMARK.md §2.1).
    """

    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.TW_ID.value,
            name="tw_id_zh",
            supported_language="zh",
            patterns=[_pattern("TWID_ZH", _TW_ID_RE, 0.8)],
        )


class ApiKeyRecognizerZh(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.API_KEY.value,
            name="api_key_zh",
            supported_language="zh",
            patterns=[_pattern("APIKEY_ZH", _API_KEY_RE, 0.5)],
        )

    def validate_result(self, pattern_text: str) -> bool:
        return len(pattern_text) >= 20 and _shannon_entropy(pattern_text) >= 3.5


class JwtRecognizerZh(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.JWT.value,
            name="jwt_zh",
            supported_language="zh",
            patterns=[_pattern("JWT_ZH", _JWT_RE, 0.5)],
        )

    def validate_result(self, pattern_text: str) -> bool:
        header, _, _ = pattern_text.partition(".")
        return _jwt_header_ok(header)


class PrivateKeyRecognizerZh(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.PRIVATE_KEY.value,
            name="private_key_zh",
            supported_language="zh",
            patterns=[_pattern("PKEY_ZH", _PRIVATE_KEY_RE, 0.95)],
        )


class SecretRecognizerZh(PatternRecognizer):
    """key=value style secrets (deny-list keys, no bare "token")."""

    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.SECRET.value,
            name="secret_zh",
            supported_language="zh",
            patterns=[
                _pattern("SECRET_KV_ZH", _SECRET_KV_RE, 0.8),
                _pattern("SECRET_ZH_ZH", _SECRET_ZH_RE, 0.8),
            ],
        )


class BankAccountRecognizerZh(PatternRecognizer):
    """Bare 10-14 digit runs are ambiguous: low score 0.55, the
    column-header context boost decides (context.py). No validation:
    the regex already guarantees the format, and presidio would set
    MAX_SCORE (1.0) on any validated match, defeating the design."""

    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.BANK_ACCOUNT.value,
            name="bank_account_zh",
            supported_language="zh",
            patterns=[_pattern("BANK_ZH", _BANK_ACCOUNT_RE, 0.55)],
        )


class CustomerIdRecognizerZh(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.CUSTOMER_ID.value,
            name="customer_id_zh",
            supported_language="zh",
            patterns=[_pattern("CUSTID_ZH", _CUSTOMER_ID_RE, 0.85)],
        )


class EmployeeIdRecognizerZh(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.EMPLOYEE_ID.value,
            name="employee_id_zh",
            supported_language="zh",
            patterns=[_pattern("EMPID_ZH", _EMPLOYEE_ID_RE, 0.85)],
        )


class TokenPatternRecognizerZh(PatternRecognizer):
    """Reserved-token-format values (T-T03): flagged for M2 escaping."""

    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.TOKEN_PATTERN.value,
            name="token_pattern_zh",
            supported_language="zh",
            patterns=[_pattern("TOKENPAT_ZH", _TOKEN_PATTERN_RE, 0.95)],
        )


class CompanyNameRecognizerZh(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.COMPANY_NAME.value,
            name="company_name_zh",
            supported_language="zh",
            patterns=[_pattern("COMPANY_ZH", _COMPANY_ZH_RE, 0.6)],
        )


class AddressRecognizerZh(PatternRecognizer):
    """Deterministic Chinese address skeleton (plan: score 0.65).

    NER LOCATION spans overlapping an ADDRESS span lose in resolution
    (ADDRESS > LOCATION family) — the skeleton is the more specific
    signal for a full mailing address.
    """

    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.ADDRESS.value,
            name="address_zh",
            supported_language="zh",
            patterns=[_pattern("ADDR_ZH", _ADDRESS_RE, 0.65)],
        )


class PersonFallbackRecognizerZh(PatternRecognizer):
    """Surname-dictionary fallback for names the NER misses.

    Three modes (benchmark-calibrated, docs/DECISIONS.md):
    - standalone (0.55): a name at a non-CJK boundary, optionally
      followed by a prose particle (之/於/的/是/，/。);
    - embedded (0.6): a name right after a person-context word
      (客戶/供應商/帳上/負責人 …) — the NER misses most of these;
    - english (0.6): "Alice Miller"-shaped full names.

    ``validate_result`` denies business words (陳列, 毛利率, …) and
    en-mode business terms (April Sales, Q3 Report …). Note presidio
    sets MAX_SCORE (1.0) when validation passes, so a validated
    fallback name scores 1.0 — when NER also fires on the same
    standalone span the content is identical, so the winner is
    irrelevant.
    """

    def __init__(self) -> None:
        super().__init__(
            supported_entity=EntityType.PERSON.value,
            name="person_fallback_zh",
            supported_language="zh",
            patterns=[
                _pattern("PERSON_FB_ZH", _PERSON_RE, 0.55),
                _pattern("PERSON_FB_PREFIX_ZH", _PERSON_PREFIX_RE, 0.6),
                _pattern("PERSON_FB_EN", _PERSON_EN_RE, 0.6),
            ],
        )

    def validate_result(self, pattern_text: str) -> bool:
        # The embedded-mode full match includes the anchoring context
        # word (客戶梁涵), so strip it before the length checks. Safe:
        # every context word starts with a non-surname char.
        name = pattern_text
        for word in sorted(_PERSON_CONTEXT_WORDS, key=len, reverse=True):
            if name.startswith(word):
                name = name[len(word):]
                break
        if name.startswith(("為", "是")):
            name = name[1:]
        if " " in name:  # en mode: "Alice Miller"
            first, second = name.split(" ", 1)
            if len(first) < 2 or len(second) < 2:
                return False
            if first in _PERSON_EN_DENY_FIRST:
                return False
            return second not in _PERSON_EN_DENY_SECOND
        if len(name) < 2 or len(name) > 3:
            return False
        if name in _PERSON_DENY_WORDS:
            return False
        # Deny-prefix check: 金額已 is a greedy 3-char extension of the
        # financial word 金額; reject any name whose 2- or 3-char prefix
        # is in the measured business/geo word set (金額X/高雄X/萬元X are
        # never real names — unlike 王國X, which stays exact-match only).
        if (
            name[:2] in _PERSON_DENY_PREFIX_WORDS
            or name[:3] in _PERSON_DENY_PREFIX_WORDS
        ):
            return False
        if len(set(name)) == 1:  # "王王王" is not a name
            return False
        return not (len(name) == 2 and name in _TITLES)


def build_pattern_recognizers() -> list[PatternRecognizer]:
    """All custom recognisers; used as ad_hoc_recognizers."""
    return [
        EmailRecognizerZh(),
        PhoneRecognizerZh(),
        CreditCardRecognizerZh(),
        TwIdRecognizerZh(),
        ApiKeyRecognizerZh(),
        JwtRecognizerZh(),
        PrivateKeyRecognizerZh(),
        SecretRecognizerZh(),
        BankAccountRecognizerZh(),
        CustomerIdRecognizerZh(),
        EmployeeIdRecognizerZh(),
        TokenPatternRecognizerZh(),
        CompanyNameRecognizerZh(),
        AddressRecognizerZh(),
        PersonFallbackRecognizerZh(),
    ]
