"""Custom recogniser unit tests (plan matrix: 5+ pos / 5+ neg each).

Each recogniser is exercised through presidio's real
``PatternRecognizer.analyze`` — regex + ``validate_result`` semantics
included — without the zh NLP model.
"""

from __future__ import annotations

import pytest

from secure_ai_gateway.detection.recognizers import (
    AddressRecognizerZh,
    ApiKeyRecognizerZh,
    BankAccountRecognizerZh,
    CompanyNameRecognizerZh,
    CreditCardRecognizerZh,
    CustomerIdRecognizerZh,
    EmailRecognizerZh,
    EmployeeIdRecognizerZh,
    JwtRecognizerZh,
    PersonFallbackRecognizerZh,
    PhoneRecognizerZh,
    PrivateKeyRecognizerZh,
    SecretRecognizerZh,
    TokenPatternRecognizerZh,
    TwIdRecognizerZh,
    _tw_id_checksum,
    build_pattern_recognizers,
)
from secure_ai_gateway.models import EntityType


def _spans(recognizer, text: str) -> list[tuple[str, int, int]]:
    results = recognizer.analyze(text, "zh")
    return [(r.entity_type, r.start, r.end) for r in results]


# ---------------------------------------------------------------------------
# Format recognisers
# ---------------------------------------------------------------------------


class TestEmailRecognizerZh:
    POS = (
        "請聯絡 john.doe@example.com 確認",
        "聯絡人：mkt_team@corp.tw",
        "xy12@ab.co",
        "a.b+c-d@sub.domain.org",
        "bob@example.com.tw",
    )
    NEG = (
        "foo@bar",           # no TLD dot
        "a@b.co",            # local part < 3 chars
        "foo@bar.c",         # TLD < 2 chars
        "foo@bar.com123",    # digit after TLD blocks the boundary
        "請電洽分機1234",     # no address at all
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(EmailRecognizerZh(), text)
        assert any(t == EntityType.EMAIL.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(EmailRecognizerZh(), text) == [], text


class TestPhoneRecognizerZh:
    POS = (
        "手機 0912345678",
        "+886912345678",
        "公司電話 02-23456789",
        "傳真 0223456789",
        "中國手機 13912345678",
    )
    NEG = (
        "091234567",          # too short
        "091234567890",       # too long
        "12345",
        "phone: abc",
        "號碼 0912-345-678",  # dash format not in contract
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(PhoneRecognizerZh(), text)
        assert any(t == EntityType.PHONE.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(PhoneRecognizerZh(), text) == [], text


class TestTwIdRecognizerZh:
    POS = (
        "身份證 A123456789",
        "證號 B200000001",
        "身分證 C123456789",
        "id: D100000001",
        "ID E200000000",
    )
    # NOTE: lowercase "a123456789" is NOT here — presidio compiles
    # patterns with global IGNORECASE, so it matches (over-detection
    # direction; recorded in docs/DECISIONS.md).
    NEG = (
        "A12345678",        # 8 digits
        "A1234567890",      # 10 digits
        "1234567890",       # no letter
        "A012345678",       # gender digit must be 1/2
        "X12345678",        # too short
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(TwIdRecognizerZh(), text)
        assert any(t == EntityType.TW_ID.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(TwIdRecognizerZh(), text) == [], text

    def test_checksum_helpers(self) -> None:
        assert _tw_id_checksum("A", "123456789") is True   # computed valid
        assert _tw_id_checksum("A", "123456780") is False
        assert _tw_id_checksum("A", "12345678") is False   # malformed
        assert _tw_id_checksum("!", "123456789") is False  # bad letter


class TestCreditCardRecognizerZh:
    POS = (
        "卡號 4111111111111111",        # classic Luhn-valid Visa
        "378282246310005",              # Luhn-valid Amex (15)
        "4111 1111 1111 1111",          # spaced variant
        "5555555555554444",             # Luhn-valid MasterCard
        "帳上 4111111111111111 之金額",  # embedded in prose
    )
    NEG = (
        "4111111111111112",   # same prefix, invalid check digit
        "1234 5678 9012 3456",
        "4111111111111",      # too short
        "4111111111111111111",
        "12345",
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(CreditCardRecognizerZh(), text)
        assert any(t == EntityType.CREDIT_CARD.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(CreditCardRecognizerZh(), text) == [], text


class TestApiKeyRecognizerZh:
    POS = (
        "sk-aB3dEfGhIjKlMnOpQrStUvWxYz0123456789abcdef",
        # Synthetic placeholder. Shaped like a Google key so the AIza
        # branch of _API_KEY_RE is exercised, but self-evidently not a
        # real credential. Never paste a real key into a fixture.
        "供應商 AIzaSyEXAMPLEKEYabcdefghijklmnopqrst 之金鑰",
        "ghp_M9O1kSGgc7oJ68nQuPFL3r94JIy9h6rbK",
        "AKIAIOSFODNN7EXAMPLE",
        "xoxb-123456789012-abcdefghijkl",
    )
    NEG = (
        "sk-" + "a" * 40,            # entropy 0 fails validate_result
        "AKIA1234",                  # too short
        "AIza" + "a" * 25,           # low entropy
        "sk-abc",                    # too short
        "ghp_shorttoken",
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(ApiKeyRecognizerZh(), text)
        assert any(t == EntityType.API_KEY.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(ApiKeyRecognizerZh(), text) == [], text


class TestJwtRecognizerZh:
    HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"  # {"alg":"HS256","typ":"JWT"}
    PAYLOAD = "eyJzdWIiOiJiZW5jaCIsImlhdCI6MTc1NTAwMDAwMH0"
    POS = (
        f"{HEADER}.{PAYLOAD}.{'x' * 43}",
        f"token 為 {HEADER}.{PAYLOAD}.{'y' * 43}",
    )
    NEG = (
        "aaa.bbb.ccc",          # header does not decode to a JWT header
        f"{HEADER}.{PAYLOAD}",  # two segments only
        f"{HEADER}.{PAYLOAD}.zz!zzzzzzzzzz",  # segment < 10 chars before !
        "not.a.jwt",
        "....",
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(JwtRecognizerZh(), text)
        assert any(t == EntityType.JWT.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(JwtRecognizerZh(), text) == [], text


class TestPrivateKeyRecognizerZh:
    _KEY = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n"
        "-----END PRIVATE KEY-----"
    )
    POS = (
        _KEY,
        "伺服器上的金鑰：\n" + _KEY + "\n請勿外流",
        "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
    )
    NEG = (
        "-----BEGIN PRIVATE KEY-----\nAAAA",   # no END marker
        "BEGIN PRIVATE KEY-----END PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
        "private key here",
        "PEM: MIIEvQIBADANBgkqhkiG9w0BAQE",
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(PrivateKeyRecognizerZh(), text)
        assert any(t == EntityType.PRIVATE_KEY.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(PrivateKeyRecognizerZh(), text) == [], text


class TestSecretRecognizerZh:
    POS = (
        "password=Abcdef12345",
        "api_key : sk-abcdefgh12345678",
        "密碼：Abcdef12345",
        "金鑰是 qwertyuiop12345678",
        "SECRET=Abcdef12345",
    )
    NEG = (
        "token=abc123",        # 'token' not a deny-listed key
        "password=",           # empty value
        "password=abc",        # value < 8 chars
        "密碼：abc",           # zh form, value too short
        "the password is long",  # no key=value structure
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(SecretRecognizerZh(), text)
        assert any(t == EntityType.SECRET.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(SecretRecognizerZh(), text) == [], text


class TestBankAccountRecognizerZh:
    POS = (
        "帳號 123456789012",      # 12 digits
        "0123456789",            # 10 digits
        "帳戶：98765432101234",   # 14 digits
        "轉帳至 112233445566 帳號",
        "戶號 556677889900",
    )
    NEG = (
        "123456789",                    # 9 digits
        "123456789012345",              # 15 digits
        "帳號 12345678901234567890",    # 20 digits: 14-run breaks boundary
        "ID:123456789012345678901234",  # 24 digits
        "1234",
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(BankAccountRecognizerZh(), text)
        assert any(t == EntityType.BANK_ACCOUNT.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(BankAccountRecognizerZh(), text) == [], text


class TestCustomerIdRecognizerZh:
    POS = (
        "CUST-1234",
        "CUSTOMER_987654321",
        "客戶編號 CUST12345678",
        "cUsToMeR-AbCdEf",
        "CUSTOMER_1234567890123456",
    )
    # NOTE: "CUST1234extra" is NOT here — global IGNORECASE makes it a
    # valid body (over-detection direction; DECISIONS.md).
    NEG = (
        "CUST_123",                      # body < 4 chars
        "CUSTOMER_12345678901234567",    # body > 16 chars
        "CUST_12-34",                    # '-' inside the body
        "CUST-12-34",                    # '-' inside the body
        "CUST_AB",                       # body < 4 chars
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(CustomerIdRecognizerZh(), text)
        assert any(t == EntityType.CUSTOMER_ID.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(CustomerIdRecognizerZh(), text) == [], text


class TestEmployeeIdRecognizerZh:
    POS = (
        "EMP-0001234",
        "EMPLOYEE_00000001",
        "員工編號 EMP0005678",
        "EMP99999999",
        "EMPLOYEE_ABCD1234",
    )
    # NOTE: "EMP123extra" is NOT here — global IGNORECASE makes it a
    # valid body (over-detection direction; DECISIONS.md).
    NEG = (
        "EMP_123",
        "EMP-12",
        "EMPLOYEE_12345678901234567",  # body > 16 chars
        "EMP-12-34",                   # '-' inside the body
        "EMPLOYEE_AB",                 # body < 4 chars
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(EmployeeIdRecognizerZh(), text)
        assert any(t == EntityType.EMPLOYEE_ID.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(EmployeeIdRecognizerZh(), text) == [], text


class TestTokenPatternRecognizerZh:
    """Reserved-token format (T-T03): must never escape detection."""

    POS = (
        "CUSTOMER_a1b2c3",
        "EMPLOYEE_ffffff",
        "EMAIL_0f0f0f",
        "PHONE_123abc",
        "ADDRESS_deadbe",
    )
    # NOTE: "customer_a1b2c3" is NOT here — global IGNORECASE makes it
    # match (over-detection direction; DECISIONS.md).
    NEG = (
        "CUSTOMER_zzzzzz",     # not hex
        "EMAIL_a1b2c",         # 5 hex chars
        "CUSTOMER_12345",      # 5 hex chars
        "CUSTOMER_1234567",    # 7 hex chars
        "CUSTOMER_a1b2c3x",    # no trailing boundary
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(TokenPatternRecognizerZh(), text)
        assert any(t == EntityType.TOKEN_PATTERN.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(TokenPatternRecognizerZh(), text) == [], text


# ---------------------------------------------------------------------------
# NER-family recognisers (deterministic helpers)
# ---------------------------------------------------------------------------


class TestAddressRecognizerZh:
    POS = (
        "台北市中正區中山北路一段123號",
        "台中市西屯區台灣大道三段789號",
        "高雄市前鎮區中山二路266號之1",
        "花蓮縣板橋區成功路75巷11弄866號",
        "供應商彰化縣安平區文化路一段74弄898號之4之採購金額",
    )
    NEG = (
        "台北市",                 # no road / number
        "中山北路一段123號",      # no city
        "台北市中正區",           # no road / number
        "台北市中山區中山北路",   # no number
        "新北市中和區景平路",     # road without number
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(AddressRecognizerZh(), text)
        assert any(t == EntityType.ADDRESS.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(AddressRecognizerZh(), text) == [], text


class TestCompanyNameRecognizerZh:
    POS = (
        "台塑集團",
        "中鋼企業股份有限公司",
        "聯發科技",
        "華碩資訊股份有限公司之應收帳款",
        "客戶宏碁企業股份有限公司於2026/08/15下單",
    )
    NEG = (
        "台塑",               # no suffix
        "供應商",             # no suffix
        "財務報表",           # 報表 not a suffix
        "經濟發展",           # 發展 not a suffix
        "中山區公所",         # 公所 not a suffix
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(CompanyNameRecognizerZh(), text)
        assert any(t == EntityType.COMPANY_NAME.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(CompanyNameRecognizerZh(), text) == [], text


class TestPersonFallbackRecognizerZh:
    POS = (
        "王小明",                    # standalone
        "陳大文",
        "林俊傑",
        "張三",
        "李四 與 王五",
        "湯家於今年第一季出貨",        # standalone + particle 於
        "戴芷淑之毛利率為32%。",       # standalone + particle 之
        "梁涵的Email是bob@x.com。",    # standalone + particle 的
        "王小明是業務員。",            # standalone + particle 是
        "客戶梁涵，身分證字號H130400517。",  # embedded after 客戶
        "供應商曹芷芷之採購金額達NT$120000。",  # embedded after 供應商
        "帳上鄭涵之逾期天數超過60天，須催收。",  # embedded after 帳上
        "Alice Miller",              # english full name
        "Steven Hall 的聯絡方式",     # english + particle
        "Paul White的Email是p@x.com。",  # english + 的
    )
    NEG = (
        "陳列",         # business word (deny-list)
        "黃金",         # business word
        "毛利率為32%。",  # 毛利率 deny-listed despite trailing 為
        "金額已於月結時核對完成。",  # 金額已 = greedy extension of deny 金額
        "客戶金額已於月結時核對完成。",  # deny-prefix applies after the prefix
        "高雄港貨運量",  # 高+雄港 mid-word CJK: hard boundary
        "金額",         # deny-listed
        "萬元",         # deny-listed
        "現金流量",     # deny-listed
        "王王王",       # all-identical chars
        "王",           # single char
        "王小明華",     # 4 chars: not the 1-2 given-char shape
        "April Sales",  # en mode: month + business term
        "Taipei Office",  # en mode: business term second word
    )

    @pytest.mark.parametrize("text", POS)
    def test_positive(self, text: str) -> None:
        spans = _spans(PersonFallbackRecognizerZh(), text)
        assert any(t == EntityType.PERSON.value for t, _, _ in spans), text

    @pytest.mark.parametrize("text", NEG)
    def test_negative(self, text: str) -> None:
        assert _spans(PersonFallbackRecognizerZh(), text) == [], text


class TestBuildPatternRecognizers:
    def test_all_zh_and_distinct_names(self) -> None:
        recognizers = build_pattern_recognizers()
        names = [r.name for r in recognizers]
        assert len(names) == len(set(names))
        for r in recognizers:
            assert r.supported_language == "zh"

    def test_supported_entities_cover_all_format_types(self) -> None:
        recognizers = build_pattern_recognizers()
        entities = {
            e for r in recognizers for e in r.get_supported_entities()
        }
        assert EntityType.EMAIL.value in entities
        assert EntityType.TW_ID.value in entities
        assert EntityType.CREDIT_CARD.value in entities
