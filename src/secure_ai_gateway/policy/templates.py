"""Task templates: static column allowlists per task (DESIGN §12).

A template is the ONLY way columns may pass through the pipeline.
Columns not matching any allowed keyword are dropped. Matching is
case-insensitive substring matching on the NFKC-normalised column
label — deliberately simple and deterministic for the PoC.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TaskTemplate:
    name: str
    description: str
    allowed_columns: tuple[str, ...]


TASK_TEMPLATES: dict[str, TaskTemplate] = {
    "gross_margin": TaskTemplate(
        name="gross_margin",
        description=(
            "Gross-margin analysis on financial reports: customer name "
            "plus revenue / cost / margin columns only."
        ),
        allowed_columns=(
            "客戶",
            "客戶名稱",
            "營業收入",
            "收入",
            "成本",
            "毛利",
            "毛利率",
            "營業額",
            "revenue",
            "cost",
            "margin",
            "sales",
            "金額",
            "月份",
            "年度",
            "季",
        ),
    ),
}


def resolve_template(name: str | None) -> TaskTemplate | None:
    """Resolve a template name; None/unknown -> None (-> policy BLOCK)."""
    if name is None:
        return None
    return TASK_TEMPLATES.get(name)
