"""Resource limits and token estimation."""

from __future__ import annotations

from secure_ai_gateway.limits import ResourceLimits, estimate_tokens


class TestResourceLimits:
    def test_defaults_are_strict(self) -> None:
        limits = ResourceLimits()
        assert limits.max_file_bytes == 10 * 1024 * 1024
        assert limits.max_rows == 100_000
        assert limits.max_cells == 1_000_000
        assert limits.max_cell_chars == 10_000
        assert limits.max_decompressed_bytes == 200 * 1024 * 1024


class TestEstimateTokens:
    def test_empty(self) -> None:
        assert estimate_tokens(0) == 1

    def test_single_char(self) -> None:
        assert estimate_tokens(1) == 1

    def test_cjk_ratio(self) -> None:
        assert estimate_tokens(4) == 2  # 4 chars / 2

    def test_odd_length_rounds_up(self) -> None:
        assert estimate_tokens(5) == 3
