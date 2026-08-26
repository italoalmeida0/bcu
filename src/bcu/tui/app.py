"""
Main Textual Application for Bulk Crap Uninstaller (BCU).
Big-Tech tier TUI with live search, multi-selection, inspector drawer, and modal execution.
"""

from __future__ import annotations

import sys
from typing import Dict, List, Optional, Set
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
)

from bcu import __version__
from bcu.models import ApplicationEntry, FilterCriteria, UninstallerType
from bcu.scanners.manager import ScannerManager
from bcu.tui.screens.ai_diag_modal import AiDiagModal
from bcu.tui.screens.junk_modal import JunkModal
from bcu.tui.screens.uninstall_modal import UninstallModal
from bcu.tui.widgets.header_stats import HeaderStatsBanner
from bcu.tui.widgets.inspector import InspectorSidebar
from bcu.utils.formatting import format_size


CSS = """
Screen {
    background: #0d1117;
    color: #e6edf3;
}

Header {
    background: #161b22;
    color: #58a6ff;
    text-style: bold;
    height: 1;
}

Footer {
    background: #161b22;
    color: #8b949e;
}

/* Stats Banner */
.stats-container {
    height: 4;
    background: #161b22;
    border-bottom: solid #30363d;
    padding: 0 1;
}

StatCard {
    width: 1fr;
    height: 100%;
    background: #21262d;
    border: round #30363d;
    padding: 0 1;
    margin: 0 1;
    align: center middle;
}

.stat-title {
    color: #8b949e;
    text-style: bold;
    text-align: center;

}

.stat-value {
    color: #58a6ff;
    text-style: bold;
    text-align: center;
}

/* Search & Action Bar */
.search-action-bar {
    height: 3;
    padding: 0 1;
    margin: 1 0;
}

#search-input {
    width: 3fr;
    background: #21262d;
    border: tall #30363d;
    color: #ffffff;
}

#search-input:focus {
    border: tall #58a6ff;
}

#filter-type {
    width: 1fr;
    margin-left: 1;
    background: #21262d;
}

.btn-action {
    margin-left: 1;
    min-width: 12;
    height: 3;
}

/* Main Split View */
.main-split {
    height: 1fr;
    padding: 0 1;
}

#app-table {
    width: 3fr;
    height: 100%;
    background: #161b22;
    border: round #30363d;
}

#app-table:focus {
    border: round #58a6ff;
}

/* Inspector Sidebar */
.inspector-sidebar {
    width: 1fr;
    height: 100%;
    background: #161b22;
    border: round #30363d;
    margin-left: 1;
    padding: 1;
}

.inspector-scroll {
    height: 100%;
}

.inspector-title {
    color: #bc8cff;
    text-style: bold;
    border-bottom: solid #30363d;
    padding-bottom: 1;
    margin-bottom: 1;
    text-align: center;
}

.insp-header-name {
    color: #ffffff;
    text-style: bold;

}

.insp-meta {
    color: #8b949e;
    margin-bottom: 1;
}

.insp-section {
    margin-top: 1;
    background: #21262d;
    border: round #30363d;
    padding: 1;
}

.insp-section-title {
    color: #58a6ff;
    text-style: bold;
    margin-bottom: 1;
}

.insp-field {
    color: #e6edf3;
    margin-bottom: 0;
}

.insp-code-block {
    color: #7ee787;
    background: #0d1117;
    padding: 1;
    border: solid #30363d;

}

/* Modals */
.modal-container {
    width: 80%;
    max-width: 100;
    height: 85%;
    background: #161b22;
    border: thick #58a6ff;
    padding: 1 2;
    align: center middle;
}

.modal-title {
    color: #58a6ff;
    text-style: bold;
    text-align: center;

    margin-bottom: 0;
}

.modal-subtitle {
    color: #8b949e;
    text-align: center;
    margin-bottom: 1;
}

.modal-app-list {
    height: 6;
    background: #0d1117;
    border: round #30363d;
    padding: 1;
    margin-bottom: 1;
}

.modal-options-grid {
    grid-size: 2;
    grid-gutter: 1;
    height: 6;
    margin-bottom: 1;
}

.modal-options-row {
    height: 3;
    margin-bottom: 1;
}

.modal-table {
    height: 10;
    background: #0d1117;
    border: round #30363d;
    margin-bottom: 1;
}

.modal-progress {
    margin: 1 0;
}

.modal-log {
    height: 8;
    background: #0d1117;
    border: round #30363d;
    margin-bottom: 1;
}

.modal-buttons {
    height: 3;
    align: center middle;
}

.diag-scroll {
    height: 18;
    background: #0d1117;
    border: round #30363d;
    padding: 1;
    margin-bottom: 1;
}
"""


class BcuApp(App):
    """Modern Big-Tech style Textual TUI Application for Bulk Crap Uninstaller."""

    CSS = CSS
    TITLE = "Bulk Crap Uninstaller (BCU) - TUI Terminal Edition"
    SUB_TITLE = f"v{__version__} | Autonomous AI & Clean Slate Engine"

    BINDINGS = [
        Binding("u", "uninstall_selected", "Uninstall Selected", priority=True),
        Binding("j", "scan_junk", "Clean Slate Remnants", priority=True),
        Binding("space", "toggle_selection", "Select/Deselect", priority=True),
        Binding("a", "toggle_select_all", "Select All", priority=True),
        Binding("d", "open_ai_diag", "AI Diagnostics", priority=True),
        Binding("r", "refresh_apps", "Refresh", priority=True),
        Binding("q", "quit", "Quit", priority=True),
    ]

    def __init__(self):
        super().__init__()
        self.all_apps: List[ApplicationEntry] = []
        self.filtered_apps: List[ApplicationEntry] = []
        self.selected_ids: Set[str] = set()
        self.row_to_app: Dict[str, ApplicationEntry] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield HeaderStatsBanner(id="stats-banner")

        with Horizontal(classes="search-action-bar"):
            yield Input(placeholder="🔍 Search installed apps (name, publisher, id)...", id="search-input")
            yield Select(
                [
                    ("All Types", "ALL"),
                    ("MSI Installers", "Msiexec"),
                    ("Inno Setup", "InnoSetup"),
                    ("NSIS", "Nsis"),
                    ("Store Apps (AppX)", "StoreApp"),
                    ("Steam Games", "Steam"),
                    ("Chocolatey / Scoop", "PackageMgr"),
                ],
                value="ALL",
                id="filter-type",
                allow_blank=False,
            )
            yield Button("UNINSTALL", variant="error", id="btn-uninstall-action", classes="btn-action")
            yield Button("CLEAN JUNK", variant="warning", id="btn-junk-action", classes="btn-action")
            yield Button("AI DIAG", variant="primary", id="btn-ai-action", classes="btn-action")

        with Horizontal(classes="main-split"):
            yield DataTable(id="app-table")
            yield InspectorSidebar()

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#app-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("✓", "Display Name", "Version", "Publisher", "Size", "Type", "Quiet")
        self.load_applications_async()

    @work(thread=True)
    def load_applications_async(self) -> None:
        """Discovers applications across all system sources asynchronously."""
        mgr = ScannerManager()
        apps = mgr.scan_all()
        self.all_apps = apps

        def update_ui():
            self.apply_filters_and_render()

        self.call_from_thread(update_ui)

    def apply_filters_and_render(self) -> None:
        """Filters applications based on search text and type dropdown, then repopulates the DataTable."""
        search_query = self.query_one("#search-input", Input).value.strip()
        type_filter = self.query_one("#filter-type", Select).value

        criteria = FilterCriteria(query=search_query if search_query else None)
        if type_filter == "PackageMgr":
            apps_to_filter = [a for a in self.all_apps if a.uninstaller_type in (UninstallerType.CHOCOLATEY, UninstallerType.SCOOP, UninstallerType.WINGET)]
        elif type_filter != "ALL":
            criteria.uninstaller_type = UninstallerType(type_filter)
            apps_to_filter = self.all_apps
        else:
            apps_to_filter = self.all_apps

        self.filtered_apps = ScannerManager.filter_entries(apps_to_filter, criteria)

        table = self.query_one("#app-table", DataTable)
        table.clear()
        self.row_to_app.clear()

        for app in self.filtered_apps:
            is_sel = app.id in self.selected_ids
            check_mark = "[bold green]✓[/bold green]" if is_sel else "[dim]□[/dim]"
            quiet_mark = "[green]✓[/green]" if app.quiet_uninstall_possible else "[dim]✗[/dim]"

            name_disp = app.display_name_trimmed
            if len(name_disp) > 35:
                name_disp = name_disp[:32] + "..."

            row_key = table.add_row(
                check_mark,
                name_disp,
                app.display_version or "-",
                app.publisher_trimmed or "-",
                format_size(app.estimated_size_bytes),
                app.uninstaller_type.value,
                quiet_mark,
                key=app.id,
            )
            self.row_to_app[str(row_key)] = app

        # Update stats
        total = len(self.all_apps)
        quiet_count = sum(1 for a in self.all_apps if a.quiet_uninstall_possible)
        total_size = sum(a.estimated_size_bytes or 0 for a in self.all_apps)
        selected_count = len(self.selected_ids)

        self.query_one("#stats-banner", HeaderStatsBanner).update_stats(
            total=total,
            quiet_count=quiet_count,
            total_size_bytes=total_size,
            selected_count=selected_count,
        )

        # Update inspector with first item if available
        if self.filtered_apps:
            self.query_one(InspectorSidebar).inspect_app(self.filtered_apps[0])

    @on(Input.Changed, "#search-input")
    def on_search_changed(self) -> None:
        self.apply_filters_and_render()

    @on(Select.Changed, "#filter-type")
    def on_filter_changed(self) -> None:
        self.apply_filters_and_render()

    @on(DataTable.RowHighlighted, "#app-table")
    def on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key and str(event.row_key.value) in self.row_to_app:
            app = self.row_to_app[str(event.row_key.value)]
            self.query_one(InspectorSidebar).inspect_app(app)

    @on(DataTable.RowSelected, "#app-table")
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_toggle_selection()

    def action_toggle_selection(self) -> None:
        """Toggles selection checkbox on the highlighted row."""
        table = self.query_one("#app-table", DataTable)
        if table.cursor_row is None or table.cursor_row < 0 or table.cursor_row >= len(self.filtered_apps):
            return

        app = self.filtered_apps[table.cursor_row]
        if app.id in self.selected_ids:
            self.selected_ids.remove(app.id)
        else:
            self.selected_ids.add(app.id)

        # Update row cell
        is_sel = app.id in self.selected_ids
        check_mark = "[bold green]✓[/bold green]" if is_sel else "[dim]□[/dim]"
        table.update_cell_at((table.cursor_row, 0), check_mark)

        # Update stats
        total = len(self.all_apps)
        quiet_count = sum(1 for a in self.all_apps if a.quiet_uninstall_possible)
        total_size = sum(a.estimated_size_bytes or 0 for a in self.all_apps)
        self.query_one("#stats-banner", HeaderStatsBanner).update_stats(
            total=total,
            quiet_count=quiet_count,
            total_size_bytes=total_size,
            selected_count=len(self.selected_ids),
        )

    def action_toggle_select_all(self) -> None:
        """Selects or deselects all currently visible applications."""
        if len(self.selected_ids) >= len(self.filtered_apps):
            self.selected_ids.clear()
        else:
            self.selected_ids = {a.id for a in self.filtered_apps}
        self.apply_filters_and_render()

    def action_uninstall_selected(self) -> None:
        """Opens the uninstallation confirmation modal for selected apps."""
        targets = [a for a in self.all_apps if a.id in self.selected_ids]
        if not targets:
            # If no selection, select currently focused app
            table = self.query_one("#app-table", DataTable)
            if table.cursor_row is not None and table.cursor_row >= 0 and table.cursor_row < len(self.filtered_apps):
                targets = [self.filtered_apps[table.cursor_row]]

        if not targets:
            return

        def handle_uninstall_result(completed: bool):
            if completed:
                self.selected_ids.clear()
                self.load_applications_async()

        self.push_screen(UninstallModal(target_apps=targets), handle_uninstall_result)

    def action_scan_junk(self) -> None:
        """Opens the clean-slate remnant manager modal."""
        targets = [a for a in self.all_apps if a.id in self.selected_ids]
        if not targets:
            table = self.query_one("#app-table", DataTable)
            if table.cursor_row is not None and table.cursor_row >= 0 and table.cursor_row < len(self.filtered_apps):
                targets = [self.filtered_apps[table.cursor_row]]

        if not targets:
            targets = self.all_apps[:10]  # sample if none selected

        self.push_screen(JunkModal(target_apps=targets, all_apps=self.all_apps))

    def action_open_ai_diag(self) -> None:
        """Opens the AI Diagnostic Suite modal."""
        self.push_screen(AiDiagModal(apps=self.all_apps))

    def action_refresh_apps(self) -> None:
        """Refreshes discovery across all system sources."""
        self.load_applications_async()

    @on(Button.Pressed, "#btn-uninstall-action")
    def on_uninstall_button(self) -> None:
        self.action_uninstall_selected()

    @on(Button.Pressed, "#btn-junk-action")
    def on_junk_button(self) -> None:
        self.action_scan_junk()

    @on(Button.Pressed, "#btn-ai-action")
    def on_ai_button(self) -> None:
        self.action_open_ai_diag()


def main():
    """Starts the Textual TUI Application."""
    app = BcuApp()
    app.run()


if __name__ == "__main__":
    main()
