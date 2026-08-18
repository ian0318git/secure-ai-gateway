"""M6 CLI tests: --vault-store opt-in persistent vault (SR-026).

The real DetectionEngine is never loaded (cli.DetectionEngine is
monkeypatched, same pattern as test_cli.py). The store file itself is
the observable: the CLI output shows only restored text, so token
reuse across runs is verified by decrypting the store.
"""

from __future__ import annotations

import json

import pytest
from cryptography.fernet import Fernet

from secure_ai_gateway import cli
from secure_ai_gateway.models import (
    CellDetection,
    DetectionSpan,
    EntityType,
    SpanSource,
)

_KEY = Fernet.generate_key()


class StubEngine:
    """Duck-typed DetectionEngine; no NLP model loaded."""

    def __init__(self, spans_by_cell: dict[str, tuple[DetectionSpan, ...]]):
        self._spans = spans_by_cell

    def analyze_cell(self, cell):
        return CellDetection(
            cell_id=cell.cell_id,
            spans=self._spans.get(cell.cell_id, ()),
        )

    def analyze_text(self, text: str) -> tuple[DetectionSpan, ...]:
        return ()


def _span(entity: EntityType, start: int, end: int, raw: str) -> DetectionSpan:
    return DetectionSpan(entity, start, end, 0.9, SpanSource.PATTERN, raw)


def _stub_detection(monkeypatch, spans_by_cell) -> None:
    engine = StubEngine(spans_by_cell)
    monkeypatch.setattr(cli, "DetectionEngine", lambda: engine)


def _decrypt(path, key: bytes) -> dict:
    """Read and decrypt a store file for observation."""
    return json.loads(Fernet(key).decrypt(path.read_bytes()))


@pytest.fixture
def pii_csv(tmp_path):
    f = tmp_path / "pii.csv"
    f.write_bytes("客戶,營業收入\n王小明,8.4M\n".encode())
    return f


class TestParser:
    def test_default_vault_store_none(self) -> None:
        args = cli.build_parser().parse_args(["--file", "x.csv"])
        assert args.vault_store is None

    def test_vault_store_flag_accepted(self) -> None:
        args = cli.build_parser().parse_args(
            ["--file", "x.csv", "--vault-store", "tmp/demo.vault"]
        )
        assert args.vault_store == "tmp/demo.vault"


class TestMain:
    def test_vault_store_reuses_tokens_across_runs(
        self, monkeypatch, pii_csv, tmp_path, capsys
    ) -> None:
        _stub_detection(
            monkeypatch, {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        store_path = tmp_path / "demo.vault"
        args = [
            "--file",
            str(pii_csv),
            "--instruction",
            "請分析",
            "--provider",
            "fake",
            "--vault-store",
            str(store_path),
        ]
        monkeypatch.setenv("VAULT_MASTER_KEY", _KEY.decode())
        assert cli.main(args) == 0
        assert "DELIVERED" in capsys.readouterr().out
        t1 = _decrypt(store_path, _KEY)["mappings"]["PERSON"]["王小明"]
        assert cli.main(args) == 0
        assert "DELIVERED" in capsys.readouterr().out
        t2 = _decrypt(store_path, _KEY)["mappings"]["PERSON"]["王小明"]
        assert t1 == t2  # identity reused across runs

    def test_vault_store_missing_key_exits_2(
        self, monkeypatch, pii_csv, tmp_path, capsys
    ) -> None:
        _stub_detection(
            monkeypatch, {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        code = cli.main(
            [
                "--file",
                str(pii_csv),
                "--provider",
                "fake",
                "--vault-store",
                str(tmp_path / "s.vault"),
            ]
        )
        err = capsys.readouterr().err
        assert code == 2
        assert "VAULT_MASTER_KEY" in err

    def test_vault_store_invalid_key_exits_2(
        self, monkeypatch, pii_csv, tmp_path, capsys
    ) -> None:
        _stub_detection(
            monkeypatch, {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        monkeypatch.setenv("VAULT_MASTER_KEY", "not a key!!")
        code = cli.main(
            [
                "--file",
                str(pii_csv),
                "--provider",
                "fake",
                "--vault-store",
                str(tmp_path / "s.vault"),
            ]
        )
        assert code == 2
        assert "VAULT_MASTER_KEY" in capsys.readouterr().err

    def test_vault_store_tampered_fails_closed(
        self, monkeypatch, pii_csv, tmp_path, capsys
    ) -> None:
        _stub_detection(
            monkeypatch, {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        store_path = tmp_path / "s.vault"
        store_path.write_bytes(b"gAAAA" + b"x" * 100)
        monkeypatch.setenv("VAULT_MASTER_KEY", _KEY.decode())
        code = cli.main(
            [
                "--file",
                str(pii_csv),
                "--provider",
                "fake",
                "--vault-store",
                str(store_path),
            ]
        )
        assert code == 2  # fail closed at startup, no session ran
        assert "DELIVERED" not in capsys.readouterr().out

    def test_vault_store_blocked_session_leaves_store_unchanged(
        self, monkeypatch, pii_csv, tmp_path, capsys
    ) -> None:
        store_path = tmp_path / "s.vault"
        monkeypatch.setenv("VAULT_MASTER_KEY", _KEY.decode())
        _stub_detection(
            monkeypatch, {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        assert (
            cli.main(
                [
                    "--file",
                    str(pii_csv),
                    "--instruction",
                    "請分析",
                    "--provider",
                    "fake",
                    "--vault-store",
                    str(store_path),
                ]
            )
            == 0
        )
        before = store_path.read_bytes()

        # Now a BLOCK path: secret in the document -> no commits.
        secret_csv = pii_csv.with_name("secret.csv")
        secret_csv.write_bytes("客戶,收入\nsk-live-abc,8.4M\n".encode())
        _stub_detection(
            monkeypatch,
            {"r1_c0": (_span(EntityType.API_KEY, 0, 11, "sk-live-abc"),)},
        )
        code = cli.main(
            [
                "--file",
                str(secret_csv),
                "--provider",
                "fake",
                "--vault-store",
                str(store_path),
            ]
        )
        assert code == 1
        assert "secret:API_KEY" in capsys.readouterr().out
        assert store_path.read_bytes() == before  # store untouched

    def test_vault_store_open_log_has_no_content(
        self, monkeypatch, pii_csv, tmp_path, caplog
    ) -> None:
        _stub_detection(
            monkeypatch, {"r1_c0": (_span(EntityType.PERSON, 0, 3, "王小明"),)}
        )
        monkeypatch.setenv("VAULT_MASTER_KEY", _KEY.decode())
        store_path = tmp_path / "s.vault"
        with caplog.at_level("INFO"):
            assert (
                cli.main(
                    [
                        "--file",
                        str(pii_csv),
                        "--provider",
                        "fake",
                        "--vault-store",
                        str(store_path),
                    ]
                )
                == 0
            )
        joined = caplog.text
        assert "vault_store_open" in joined
        assert "entries=0" in joined
        assert "王小明" not in joined
        assert "mappings" not in joined  # forbidden log key never used
