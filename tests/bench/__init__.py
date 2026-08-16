"""Benchmark unit tests (no NLP model, fast).

These assert the BENCHMARK.md §7 determinism requirements, the corpus
composition, and the generator<->recogniser alignment contract (a
generated value must always be detectable by its recogniser — this is
what makes the benchmark measure the DETECTOR rather than generator
drift).
"""
