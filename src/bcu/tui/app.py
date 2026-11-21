"""
Main Textual Application for Bulk Crap Uninstaller (BCU).
Responsive TUI designed to work cleanly across all terminal dimensions (80x24 to ultrawide)
without overlapping, clipped controls, or off-screen modal buttons.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set
from rich.markup import escape as escape_markup
from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Select,
    Static,
)

from bcu import __version__
from bcu.models import ApplicationEntry, FilterCriteria, UninstallerType
from bcu.scanners.manager import ScannerManager
from bcu.tui.screens.audit_modal import AuditModal
from bcu.tui.screens.junk_modal import JunkModal
from bcu.tui.screens.uninstall_modal import UninstallModal
from bcu.tui.widgets.header_stats import HeaderStatsBanner
from bcu.tui.widgets.inspector import InspectorSidebar
from bcu.utils.formatting import format_size
from bcu.utils.platform import is_admin


CSS = """
Screen {
    background: #0d1117;
    color: #e6edf3;
    layout: vertical;
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

/* Header Stats Banner: guaranteed 3-row footprint with zero vertical border clipping */
HeaderStatsBanner {
    height: 3;
    width: 100%;
    background: #161b22;
    border-bottom: solid #30363d;
}

.stats-container {
    height: 2;
    width: 100%;
    padding: 0 1;
}

.stat-card {
    width: 1fr;
    height: 2;
    background: #1c2128;
    padding: 0 1;
    margin-right: 1;
    content-align: left middle;
}

.stat-card:last-of-type {
    margin-right: 0;
}

.card-blue   { border-left: thick #58a6ff; }
.card-green  { border-left: thick #3fb950; }
.card-purple { border-left: thick #bc8cff; }
.card-amber  { border-left: thick #d29922; }

.stat-title {
    color: #8b949e;
    text-style: bold;
    width: 100%;
    height: 1;
}

.stat-value {
    color: #e6edf3;
    text-style: bold;
    width: 100%;
    height: 1;
}

/* Search & Type Filter Bar (Row 1) */
.search-action-bar {
    height: 3;
    width: 100%;
    padding: 0 1;
    margin-top: 0;
    margin-bottom: 0;
}

#search-input {
    width: 1fr;
    min-width: 18;
    height: 3;
    background: #21262d;
    border: tall #30363d;
    color: #ffffff;
}

#search-input:focus {
    border: tall #58a6ff;
}

#filter-type {
    width: 24;
    min-width: 18;
    height: 3;
    margin-left: 1;
    background: #21262d;
}

/* Compact 1-Row Action Pill Bar (Row 2) - fits cleanly even at 80 cols */
.action-pill-bar {
    height: 1;
    width: 100%;
    padding: 0 1;
    margin-bottom: 0;
    background: #0d1117;
}

.btn-pill {
    height: 1;
    min-width: 8;
    border: none;
    padding: 0 1;
    margin-right: 1;
    text-style: bold;
}

#status-bar {
    height: 1;
    width: 100%;
    padding: 0 1;
    color: #58a6ff;
    background: #161b22;
}

.hidden {
    display: none;
}

/* Main Split View */
.main-split {
    height: 1fr;
    width: 100%;
    padding: 0 1;
}

#app-table {
    width: 1fr;
    height: 100%;
    background: #161b22;
    border: round #30363d;
}

#app-table:focus {
    border: round #58a6ff;
}

/* Inspector Sidebar: fixed sensible width, auto-hidden below 100 cols (toggleable with 'i') */
.inspector-sidebar {
    width: 38;
    min-width: 30;
    max-width: 48;
    height: 100%;
    background: #161b22;
    border: round #30363d;
    margin-left: 1;
    padding: 0 1;
}

.inspector-scroll {
    height: 100%;
    width: 100%;
}

.inspector-title {
    color: #bc8cff;
    text-style: bold;
    border-bottom: solid #30363d;
    padding: 0 0 0 0;
    margin-bottom: 1;
    width: 100%;
    text-align: center;
}

.insp-header-name {
    color: #ffffff;
    text-style: bold;
    width: 100%;
    height: auto;
}

.insp-meta {
    color: #8b949e;
    margin-bottom: 1;
    width: 100%;
    height: auto;
}

.insp-section {
    height: auto;
    width: 100%;
    margin-bottom: 1;
    background: #21262d;
    border: round #30363d;
    padding: 0 1;
}

.insp-section-title {
    color: #58a6ff;
    text-style: bold;
    width: 100%;
    height: 1;
}

.insp-field {
    color: #e6edf3;
    width: 100%;
    height: auto;
}

.insp-code-block {
    color: #7ee787;
    background: #0d1117;
    padding: 0 1;
    margin-top: 0;
    margin-bottom: 1;
    border: solid #30363d;
    width: 100%;
    height: auto;
}

/* Modals: properly centered on ModalScreen with flexible bodies and guaranteed visible footer buttons */
UninstallModal, JunkModal, AuditModal {
    align: center middle;
    background: rgba(0, 0, 0, 0.72);
}

.modal-container {
    width: 92%;
    max-width: 108;
    height: 92%;
    max-height: 94%;
    background: #161b22;
    border: thick #58a6ff;
    padding: 0 2;
    layout: vertical;
}

.modal-title {
    color: #58a6ff;
    text-style: bold;
    text-align: center;
    width: 100%;
    height: 1;
}

.modal-subtitle {
    color: #8b949e;
    text-align: center;
    width: 100%;
    height: 1;
    margin-bottom: 0;
}

.modal-body {
    height: 1fr;
    width: 100%;
    layout: vertical;
    overflow-y: auto;
}

.modal-app-list {
    height: auto;
    max-height: 4;
    min-height: 2;
    width: 100%;
    background: #0d1117;
    border: round #30363d;
    padding: 0 1;
    margin-bottom: 0;
}

.modal-options-grid {
    grid-size: 2;
    grid-gutter: 0 1;
    height: auto;
    width: 100%;
    margin: 0;
}

.modal-options-row {
    height: auto;
    width: 100%;
    margin: 0;
}

.compact-cb {
    height: 1;
    border: none;
    padding: 0 1 0 0;
    background: transparent;
}

.modal-table {
    height: 1fr;
    min-height: 4;
    width: 100%;
    background: #0d1117;
    border: round #30363d;
    margin-bottom: 0;
}

.modal-progress {
    height: 1;
    width: 100%;
    margin: 0;
}

.modal-log {
    height: 1fr;
    min-height: 4;
    width: 100%;
    background: #0d1117;
    border: round #30363d;
}

.modal-log-sm {
    height: 4;
    min-height: 3;
    max-height: 6;
    width: 100%;
    background: #0d1117;
    border: round #30363d;
}

.junk-search-bar {
    height: 3;
    width: 100%;
    margin-bottom: 0;
}

#junk-removed-input {
    width: 1fr;
    min-width: 16;
    height: 3;
    background: #21262d;
    border: tall #30363d;
    color: #ffffff;
}

#junk-removed-input:focus {
    border: tall #58a6ff;
}

.junk-bar-btn {
    height: 3;
    min-width: 12;
    margin-left: 1;
}

.modal-buttons {
    height: 3;
    width: 100%;
    padding-top: 0;
    margin-top: 0;
    align: center middle;
}

.modal-btn {
    margin: 0 1;
    height: 3;
}

.audit-summary {
    height: auto;
    width: 100%;
    margin-bottom: 1;
}
"""


class BcuApp(App):
    """Responsive Textual TUI Application for Bulk Crap Uninstaller."""

    CSS = CSS
    TITLE = "Bulk Crap Uninstaller (BCU)"
    SUB_TITLE = f"v{__version__} | {'ADMIN' if is_admin() else 'USER'} Mode"

    # Non-priority bindings prevent hijacking modal Checkboxes or text Inputs
    BINDINGS = [
        Binding("space", "toggle_selection", "Select"),
        Binding("a", "toggle_select_all", "All"),
        Binding("u", "uninstall_selected", "Uninstall"),
        Binding("j", "scan_junk", "Orphan Junk"),
        Binding("v", "open_audit", "CVE Audit"),
        Binding("i", "toggle_inspector", "Inspector"),
        Binding("s", "toggle_system_apps", "System"),
        Binding("slash", "focus_search", "Search"),
        Binding("r", "refresh_apps", "Refresh"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self):
        super().__init__()
        self.all_apps: List[ApplicationEntry] = []
        self.filtered_apps: List[ApplicationEntry] = []
        self.selected_ids: Set[str] = set()
        self.row_to_app: Dict[str, ApplicationEntry] = {}
        self.show_system_apps: bool = False
        self._user_toggled_inspector: Optional[bool] = None
        self._is_loading: bool = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield HeaderStatsBanner(id="stats-banner")

        with Horizontal(classes="search-action-bar"):
            yield Input(placeholder="Search apps (name, publisher, id)... [/]", id="search-input")
            yield Select(
                [
                    ("All Types", "ALL"),
                    ("MSI Installers", "Msiexec"),
                    ("Inno Setup", "InnoSetup"),
                    ("NSIS", "Nsis"),
                    ("Store Apps", "StoreApp"),
                    ("Winget", "Winget"),
                    ("Scoop / Choco", "PackageMgr"),
                    ("Steam Games", "Steam"),
                    ("Win Features", "WindowsFeature"),
                    ("Win Updates", "WindowsUpdate"),
                    ("Custom", "Custom"),
                ],
                value="ALL",
                id="filter-type",
                allow_blank=False,
            )

        with Horizontal(classes="action-pill-bar"):
            yield Button("U Uninstall", variant="error", id="btn-uninstall-action", classes="btn-pill")
            yield Button("J Orphans", variant="warning", id="btn-junk-action", classes="btn-pill")
            yield Button("V Audit", variant="success", id="btn-audit-action", classes="btn-pill")
            yield Button("S Sys:OFF", variant="default", id="btn-sys-toggle", classes="btn-pill")
            yield Button("I Panel", variant="default", id="btn-inspector-toggle", classes="btn-pill")
            yield Button("R Refresh", variant="primary", id="btn-refresh-action", classes="btn-pill")

        yield Static("", id="status-bar", classes="hidden")

        with Horizontal(classes="main-split"):
            yield DataTable(id="app-table")
            yield InspectorSidebar(id="inspector-sidebar")

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#app-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("✓", "Display Name", "Version", "Publisher", "Size", "Type", "Q")
        self._sync_responsive_layout()
        self.load_applications_async()

    def on_resize(self, event: events.Resize) -> None:
        self._sync_responsive_layout()
        if self.all_apps:
            self._render_table_rows()

    def _sync_responsive_layout(self) -> None:
        """Adapts inspector visibility and filter width to current terminal size."""
        width = self.size.width
        try:
            inspector = self.query_one("#inspector-sidebar", InspectorSidebar)
            if self._user_toggled_inspector is not None:
                show_insp = self._user_toggled_inspector
            else:
                show_insp = width >= 112
            inspector.set_class(not show_insp, "hidden")

            filter_sel = self.query_one("#filter-type", Select)
            filter_sel.styles.width = 18 if width < 90 else 24
        except Exception:
            pass

    def _set_status(self, message: str) -> None:
        try:
            bar = self.query_one("#status-bar", Static)
            if message:
                bar.update(message)
                bar.remove_class("hidden")
            else:
                bar.update("")
                bar.add_class("hidden")
        except Exception:
            pass

    @work(thread=True, exclusive=True)
    def load_applications_async(self, force_refresh: bool = False) -> None:
        """Discovers applications across all system sources asynchronously."""
        self._is_loading = True
        self.call_from_thread(self._set_status, "⟳ Scanning installed applications across Windows sources...")

        def on_scan_progress(msg: str) -> None:
            self.call_from_thread(self._set_status, f"⟳ {escape_markup(msg)}")

        try:
            mgr = ScannerManager()
            apps = mgr.scan_all(progress_callback=on_scan_progress, force_refresh=force_refresh)
            self.all_apps = apps
        except Exception as exc:
            self.call_from_thread(self._set_status, f"[red]Scan error: {escape_markup(str(exc))}[/red]")
            self._is_loading = False
            return

        def update_ui():
            self._is_loading = False
            self._set_status("")
            self.apply_filters_and_render()

        self.call_from_thread(update_ui)

    def _get_column_limits(self) -> tuple[int, int, int]:
        """Returns dynamic (name_max, ver_max, pub_max) limits so all columns stay visible without scrolling."""
        try:
            inspector = self.query_one("#inspector-sidebar", InspectorSidebar)
            insp_w = 40 if not inspector.has_class("hidden") else 0
        except Exception:
            insp_w = 0
        avail = max(50, self.size.width - insp_w - 4)
        if avail >= 105:
            return (36, 15, 22)
        if avail >= 82:
            return (28, 12, 16)
        return (20, 10, 12)

    @staticmethod
    def _clip(text: str, max_len: int) -> str:
        if len(text) <= max_len:
            return text
        return text[: max(1, max_len - 1)] + "…"

    def _update_stats_banner(self) -> None:
        total = len(self.all_apps)
        quiet_count = sum(1 for a in self.all_apps if a.quiet_uninstall_possible)
        total_size = sum(a.estimated_size_bytes or 0 for a in self.all_apps)
        self.query_one("#stats-banner", HeaderStatsBanner).update_stats(
            total=total,
            quiet_count=quiet_count,
            total_size_bytes=total_size,
            selected_count=len(self.selected_ids),
            visible_count=len(self.filtered_apps),
        )

    def _render_table_rows(self) -> None:
        table = self.query_one("#app-table", DataTable)
        prev_cursor = table.cursor_row
        table.clear()
        self.row_to_app.clear()

        name_max, ver_max, pub_max = self._get_column_limits()

        for idx, app in enumerate(self.filtered_apps):
            is_sel = app.id in self.selected_ids
            check_mark = "[bold green]✓[/bold green]" if is_sel else "[dim]□[/dim]"
            quiet_mark = "[green]✓[/green]" if app.quiet_uninstall_possible else "[dim]✗[/dim]"

            name_disp = escape_markup(self._clip(app.display_name_trimmed, name_max))
            ver_disp = escape_markup(self._clip(app.display_version or "-", ver_max))
            pub_disp = escape_markup(self._clip(app.publisher_trimmed or "-", pub_max))
            size_disp = format_size(app.estimated_size_bytes)
            type_disp = app.uninstaller_type.value[:11]

            row_id = app.id if app.id not in self.row_to_app else f"{app.id}#{idx}"
            table.add_row(
                check_mark,
                name_disp,
                ver_disp,
                pub_disp,
                size_disp,
                type_disp,
                quiet_mark,
                key=row_id,
            )
            self.row_to_app[row_id] = app

        if self.filtered_apps:
            target_row = min(max(0, prev_cursor or 0), len(self.filtered_apps) - 1)
            table.move_cursor(row=target_row)
            self.query_one(InspectorSidebar).inspect_app(self.filtered_apps[target_row])
        else:
            self.query_one(InspectorSidebar).inspect_app(None)

    def apply_filters_and_render(self) -> None:
        """Filters applications based on search text, type dropdown, and system toggle, then repopulates DataTable."""
        search_query = self.query_one("#search-input", Input).value.strip()
        type_filter = self.query_one("#filter-type", Select).value

        # Auto-include system apps if user explicitly picks WindowsFeature / WindowsUpdate filter
        include_sys = self.show_system_apps or type_filter in ("WindowsFeature", "WindowsUpdate")
        criteria = FilterCriteria(
            query=search_query if search_query else None,
            include_system=include_sys,
            include_protected=include_sys,
        )
        if type_filter == "PackageMgr":
            apps_to_filter = [
                a
                for a in self.all_apps
                if a.uninstaller_type in (UninstallerType.CHOCOLATEY, UninstallerType.SCOOP, UninstallerType.WINGET)
            ]
        elif type_filter != "ALL":
            try:
                criteria.uninstaller_type = UninstallerType(str(type_filter))
            except ValueError:
                pass
            apps_to_filter = self.all_apps
        else:
            apps_to_filter = self.all_apps

        self.filtered_apps = ScannerManager.filter_entries(apps_to_filter, criteria)
        self._render_table_rows()
        self._update_stats_banner()

    def _modal_open(self) -> bool:
        return isinstance(self.screen, ModalScreen)

    @on(Input.Changed, "#search-input")
    def on_search_changed(self) -> None:
        self.apply_filters_and_render()

    @on(Input.Submitted, "#search-input")
    def on_search_submitted(self) -> None:
        self.query_one("#app-table", DataTable).focus()

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape" and not self._modal_open():
            if isinstance(self.focused, Input):
                self.query_one("#app-table", DataTable).focus()
                event.stop()

    @on(Select.Changed, "#filter-type")
    def on_filter_changed(self) -> None:
        self.apply_filters_and_render()

    @on(DataTable.RowHighlighted, "#app-table")
    def on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is not None and event.row_key.value in self.row_to_app:
            app = self.row_to_app[str(event.row_key.value)]
            self.query_one(InspectorSidebar).inspect_app(app)

    @on(DataTable.RowSelected, "#app-table")
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_toggle_selection()

    def action_focus_search(self) -> None:
        if self._modal_open():
            return
        self.query_one("#search-input", Input).focus()

    def action_toggle_inspector(self) -> None:
        if self._modal_open():
            return
        inspector = self.query_one("#inspector-sidebar", InspectorSidebar)
        currently_visible = not inspector.has_class("hidden")
        self._user_toggled_inspector = not currently_visible
        self._sync_responsive_layout()
        if self.all_apps:
            self._render_table_rows()

    def action_toggle_system_apps(self) -> None:
        if self._modal_open():
            return
        self.show_system_apps = not self.show_system_apps
        btn = self.query_one("#btn-sys-toggle", Button)
        btn.label = "S Sys:ON" if self.show_system_apps else "S Sys:OFF"
        btn.variant = "primary" if self.show_system_apps else "default"
        self.apply_filters_and_render()

    def action_toggle_selection(self) -> None:
        """Toggles selection checkbox on the highlighted row."""
        if self._modal_open():
            return
        table = self.query_one("#app-table", DataTable)
        if table.cursor_row is None or table.cursor_row < 0 or table.cursor_row >= len(self.filtered_apps):
            return

        app = self.filtered_apps[table.cursor_row]
        if app.id in self.selected_ids:
            self.selected_ids.remove(app.id)
        else:
            self.selected_ids.add(app.id)

        is_sel = app.id in self.selected_ids
        check_mark = "[bold green]✓[/bold green]" if is_sel else "[dim]□[/dim]"
        table.update_cell_at((table.cursor_row, 0), check_mark)
        self._update_stats_banner()

    def action_toggle_select_all(self) -> None:
        """Selects or deselects all currently visible applications."""
        if self._modal_open() or not self.filtered_apps:
            return
        visible_ids = {a.id for a in self.filtered_apps}
        if visible_ids.issubset(self.selected_ids):
            self.selected_ids.difference_update(visible_ids)
        else:
            self.selected_ids.update(visible_ids)
        self._render_table_rows()
        self._update_stats_banner()

    def _resolve_target_apps(self) -> List[ApplicationEntry]:
        targets = [a for a in self.all_apps if a.id in self.selected_ids]
        if not targets:
            table = self.query_one("#app-table", DataTable)
            if table.cursor_row is not None and 0 <= table.cursor_row < len(self.filtered_apps):
                targets = [self.filtered_apps[table.cursor_row]]
        return targets

    def action_uninstall_selected(self) -> None:
        """Opens the uninstallation confirmation modal for selected apps."""
        if self._modal_open():
            return
        targets = self._resolve_target_apps()
        if not targets:
            self.notify("No application selected.", severity="warning")
            return

        def handle_uninstall_result(completed: bool):
            if completed:
                self.selected_ids.clear()
                self.load_applications_async(force_refresh=True)

        self.push_screen(UninstallModal(target_apps=targets, all_apps=self.all_apps), handle_uninstall_result)

    def action_scan_junk(self) -> None:
        """Opens the Orphaned Leftovers Cleaner modal (scans broken remnants of removed apps safely)."""
        if self._modal_open():
            return
        self.push_screen(JunkModal(all_apps=self.all_apps))

    def action_open_audit(self) -> None:
        """Opens the CVE Vulnerability Audit modal."""
        if self._modal_open():
            return
        self.push_screen(AuditModal(apps=self.all_apps))

    def action_refresh_apps(self) -> None:
        """Forces a fresh discovery across all system sources."""
        if self._modal_open():
            return
        self.load_applications_async(force_refresh=True)

    @on(Button.Pressed, "#btn-uninstall-action")
    def on_uninstall_button(self) -> None:
        self.action_uninstall_selected()

    @on(Button.Pressed, "#btn-junk-action")
    def on_junk_button(self) -> None:
        self.action_scan_junk()

    @on(Button.Pressed, "#btn-audit-action")
    def on_audit_button(self) -> None:
        self.action_open_audit()

    @on(Button.Pressed, "#btn-refresh-action")
    def on_refresh_button(self) -> None:
        self.action_refresh_apps()

    @on(Button.Pressed, "#btn-sys-toggle")
    def on_sys_toggle_button(self) -> None:
        self.action_toggle_system_apps()

    @on(Button.Pressed, "#btn-inspector-toggle")
    def on_inspector_toggle_button(self) -> None:
        self.action_toggle_inspector()


def main():
    """Starts the Textual TUI Application."""
    app = BcuApp()
    app.run()


if __name__ == "__main__":
    main()
