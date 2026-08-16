"""Synthetic detection benchmark (docs/BENCHMARK.md, normative).

Package layout:
- generate.py: corpus generation (seed 42, checksum-invalid TW IDs)
- split.py:     stratified 80/20 via sha256(record_id)
- scoring.py:   greedy one-to-one span matching, micro aggregate
- report.py:    benchmark report JSON + markdown (docs/BENCHMARK.md §8)
- run.py:       end-to-end run: generate -> calibrate -> evaluate
"""
