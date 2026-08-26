"""
Header Stats Banner Widget displaying system summary and live selection counters.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Label, Static
from bcu.utils.formatting import format_size


class StatCard(Static):
    """A card showing an individual metric."""

    def __init__(self, title: str, value: str, icon: str = "", card_id: str = ""):
        super().__init__(id=card_id)
        self.title_text = title
        self.value_text = value
        self.icon = icon

    def compose(self) -> ComposeResult:
        yield Label(f"{self.icon} {self.title_text}", classes="stat-title")
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
            yield StatCard("TOTAL APPS", "0", icon="📦", card_id="stat-total")
            yield StatCard("QUIET SUPPORT", "0%", icon="⚡", card_id="stat-quiet")
            yield StatCard("TOTAL SIZE", "0 B", icon="💾", card_id="stat-size")
            yield StatCard("SELECTED", "0 apps", icon="✓", card_id="stat-selected")

    def update_stats(self, total: int, quiet_count: int, total_size_bytes: int, selected_count: int) -> None:
        quiet_pct = f"{(quiet_count / total * 100):.0f}%" if total > 0 else "0%"
        size_str = format_size(total_size_bytes)

        self.query_one("#stat-total", StatCard).update_value(str(total))
        self.query_one("#stat-quiet", StatCard).update_value(f"{quiet_count} ({quiet_pct})")
        self.query_one("#stat-size", StatCard).update_value(size_str)
        self.query_one("#stat-selected", StatCard).update_value(f"{selected_count} selected")
