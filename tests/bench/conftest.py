"""Mark all benchmark tests as slow (BENCHMARK.md §7 + plan).

These tests import the recogniser module (and thus presidio) but do
NOT load the NLP model. They are still gated so CI smoke runs
(``pytest -m "not benchmark"``) stay fast; the full validation runs
``pytest -m benchmark tests/benchmark/``.
"""

import pytest

pytestmark = pytest.mark.benchmark
