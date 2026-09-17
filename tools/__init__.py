"""Developer tools — NOT part of the packaged gateway.

``[tool.setuptools.packages.find] where = ["src"]`` (pyproject.toml)
keeps this tree out of the installed distribution, so the PoC's
published security claims stay literally true of
``secure_ai_gateway``. The dependency direction is one-way: tools may
import the gateway as a library; nothing under ``src/`` may import
``tools`` (pinned by tests/tools/test_scope.py).

See docs/DECISIONS.md (2026-09-18) for the approval record covering
the local debug dashboard.
"""
