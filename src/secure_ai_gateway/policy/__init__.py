"""Policy engine package (static, default-deny)."""

from secure_ai_gateway.policy.engine import evaluate
from secure_ai_gateway.policy.templates import TASK_TEMPLATES, resolve_template

__all__ = ["evaluate", "resolve_template", "TASK_TEMPLATES"]
