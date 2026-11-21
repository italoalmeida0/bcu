"""
Header Stats Banner Widget displaying system summary and live selection counters.
Designed to remain crisp and unclipped at all terminal sizes (80x24 and above).
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Label, Static
from bcu.utils.formatting import format_size


class StatCard(Static):
    """A compact 2-line metric card without vertical border clipping."""

    def __init__(self, title: str, value: str, icon: str = "", card_id: str = "", classes: str = ""):
        super().__init__(id=card_id, classes=classes)
        self.title_text = title
        self.value_text = value
        self.icon = icon

    def compose(self) -> ComposeResult:
        label_prefix = f"{self.icon} " if self.icon else ""
        yield Label(f"{label_prefix}{self.title_text}", classes="stat-title")
        yield Label(self.value_text, classes="stat-value", id=f"{self.id}-val" if self.id else None)

    def update_value(self, new_val: str) -> None:
        try:
            val_lbl = self.query_one(f"#{self.id}-val", Label)
            val_lbl.update(new_val)
        except Exception:
            pass


class HeaderStatsBanner(Static):
    """Top-level stats bar showing metrics and live selection counts."""

    def compose(self) -> ComposeResult:
        with Horizontal(classes="stats-container"):
            yield StatCard("APPS", "0", icon="▪", card_id="stat-total", classes="stat-card card-blue")
            yield StatCard("QUIET", "0%", icon="⚡", card_id="stat-quiet", classes="stat-card card-green")
            yield StatCard("SIZE", "0 B", icon="◆", card_id="stat-size", classes="stat-card card-purple")
            yield StatCard("SELECTED", "0 apps", icon="✓", card_id="stat-selected", classes="stat-card card-amber")

    def update_stats(
        self,
        total: int,
        quiet_count: int,
        total_size_bytes: int,
        selected_count: int,
        visible_count: int | None = None,
    ) -> None:
        quiet_pct = f"{(quiet_count / total * 100):.0f}%" if total > 0 else "0%"
        size_str = format_size(total_size_bytes)
        total_str = f"{visible_count}/{total}" if (visible_count is not None and visible_count != total) else str(total)

        self.query_one("#stat-total", StatCard).update_value(total_str)
        self.query_one("#stat-quiet", StatCard).update_value(f"{quiet_count} ({quiet_pct})")
        self.query_one("#stat-size", StatCard).update_value(size_str)
        self.query_one("#stat-selected", StatCard).update_value(f"{selected_count} app{'s' if selected_count != 1 else ''}")
