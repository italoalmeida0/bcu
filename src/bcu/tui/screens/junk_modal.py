"""
Modal screen for reviewing and cleaning ORPHANED leftovers from already-removed apps
(BCU / Revo Uninstaller style). Never risks corrupting active installed applications.
"""

from __future__ import annotations

from typing import List, Optional, Set
from rich.markup import escape as escape_markup
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Input, Label, RichLog

from bcu.junk.cleaner import JunkCleaner
from bcu.models import ApplicationEntry, ConfidenceLevel, JunkItem
from bcu.utils.formatting import confidence_color
from bcu.utils.platform import is_admin


class JunkModal(ModalScreen[bool]):
    """
    Modal dialog for scanning & selectively cleaning orphaned leftovers.
    Mode 1 (default): System-wide scan of verified broken/orphaned items (ghost uninstall keys,
      broken shortcuts, broken startup entries, orphaned services/firewall/AppPaths/COM, crash dumps).
    Mode 2 (by name): Manual scan for remnants of an app you already uninstalled (blocked if still installed).
    """

    BINDINGS = [
        Binding("escape", "close_modal", "Close", show=True),
        Binding("space", "toggle_item", "Toggle Item", show=True),
        Binding("a", "toggle_all_items", "Toggle All", show=True),
    ]

    def __init__(
        self,
        all_apps: List[ApplicationEntry],
        target_apps: Optional[List[ApplicationEntry]] = None,
    ):
        super().__init__()
        self.all_apps = all_apps
        # target_apps is kept only for explicit post-uninstall callers; default J button opens safe orphan mode
        self.target_apps = target_apps
        self.junk_items: List[JunkItem] = []
        self.selected_indices: Set[int] = set()
        self._is_busy = False

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label("🧹 ORPHANED LEFTOVERS & JUNK CLEANER", classes="modal-title")
            yield Label(
                "Scans broken remnants of REMOVED apps only. Active installed apps are protected.",
                classes="modal-subtitle",
            )

            with Vertical(classes="modal-body"):
                with Horizontal(classes="junk-search-bar"):
                    yield Input(
                        placeholder="Removed app name (e.g. Spotify, McAfee)...",
                        id="junk-removed-input",
                    )
                    yield Button("FIND REMOVED", variant="primary", id="btn-scan-removed", classes="junk-bar-btn")
                    yield Button("SYS ORPHANS", variant="success", id="btn-scan-orphans", classes="junk-bar-btn")

                yield DataTable(id="junk-table", classes="modal-table")

                with Horizontal(classes="modal-options-row"):
                    yield Checkbox("Dry-Run Simulation (Safe Preview)", value=True, id="junk-opt-dryrun", classes="compact-cb")
                    yield Checkbox("Auto .reg Backup", value=True, id="junk-opt-backup", classes="compact-cb")

                yield RichLog(highlight=True, markup=True, wrap=True, id="junk-log", classes="modal-log-sm")

            with Horizontal(classes="modal-buttons"):
                yield Button("CLEAN SELECTED (0)", variant="warning", id="btn-start-clean", disabled=True, classes="modal-btn")
                yield Button("CLOSE", variant="default", id="btn-close-junk", classes="modal-btn")

    def on_mount(self) -> None:
        table = self.query_one("#junk-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("✓", "Type", "Conf", "Source / App", "Target Path", "Why")
        self.scan_junk_task()

    def action_close_modal(self) -> None:
        if not self._is_busy:
            self.dismiss(True)

    def _update_clean_button(self) -> None:
        btn = self.query_one("#btn-start-clean", Button)
        count = len(self.selected_indices)
        btn.label = f"CLEAN SELECTED ({count})"
        btn.disabled = self._is_busy or count == 0

    def action_toggle_item(self) -> None:
        if self._is_busy or isinstance(self.focused, Input):
            return
        table = self.query_one("#junk-table", DataTable)
        row_idx = table.cursor_row
        if row_idx is None or row_idx < 0 or row_idx >= len(self.junk_items):
            return
        if row_idx in self.selected_indices:
            self.selected_indices.remove(row_idx)
        else:
            self.selected_indices.add(row_idx)
        mark = "[bold green]✓[/bold green]" if row_idx in self.selected_indices else "[dim]□[/dim]"
        table.update_cell_at((row_idx, 0), mark)
        self._update_clean_button()

    def action_toggle_all_items(self) -> None:
        if self._is_busy or isinstance(self.focused, Input) or not self.junk_items:
            return
        table = self.query_one("#junk-table", DataTable)
        if len(self.selected_indices) == len(self.junk_items):
            self.selected_indices.clear()
        else:
            self.selected_indices = set(range(len(self.junk_items)))
        for idx in range(len(self.junk_items)):
            mark = "[bold green]✓[/bold green]" if idx in self.selected_indices else "[dim]□[/dim]"
            table.update_cell_at((idx, 0), mark)
        self._update_clean_button()

    @on(DataTable.RowSelected, "#junk-table")
    def on_junk_row_selected(self) -> None:
        self.action_toggle_item()

    @on(Input.Submitted, "#junk-removed-input")
    def on_removed_input_submitted(self) -> None:
        self._trigger_removed_app_scan()

    def _trigger_removed_app_scan(self) -> None:
        if self._is_busy:
            return
        query = self.query_one("#junk-removed-input", Input).value.strip()
        log = self.query_one("#junk-log", RichLog)
        if not query:
            log.write("[yellow]Enter the name of an already-removed app, or click SYS ORPHANS.[/yellow]")
            return

        active_matches = JunkCleaner.find_active_installed_matches(query, self.all_apps)
        if active_matches:
            names = ", ".join(escape_markup(a.display_name_trimmed) for a in active_matches[:3])
            log.write(
                f"[bold red]⛔ BLOCKED:[/bold red] '{escape_markup(query)}' matches currently installed app(s): "
                f"[bold white]{names}[/bold white].\n"
                f" [yellow]Cleaning an active app's folders/registry directly can corrupt it. "
                f"Use [bold][U] Uninstall[/bold] instead (which cleans remnants safely after uninstalling).[/yellow]"
            )
            self.notify("Blocked: app is still installed! Use [U] Uninstall instead.", severity="warning")
            return

        self.scan_removed_app_task(query)

    def _populate_table(self, items: List[JunkItem], summary_msg: str) -> None:
        self._is_busy = False
        self.junk_items = items
        self.selected_indices = set(range(len(items)))

        table = self.query_one("#junk-table", DataTable)
        table.clear()
        for idx, item in enumerate(self.junk_items):
            color = confidence_color(item.confidence_level)
            conf_text = f"[{color}]{item.confidence_level.value}[/{color}]"
            reason_short = item.reasons[0] if item.reasons else ""
            if len(reason_short) > 44:
                reason_short = reason_short[:43] + "…"
            path_short = item.path
            if len(path_short) > 48:
                path_short = "…" + path_short[-47:]
            table.add_row(
                "[bold green]✓[/bold green]",
                item.junk_type.value,
                conf_text,
                escape_markup(item.app_name[:20]),
                escape_markup(path_short),
                escape_markup(reason_short),
                key=str(idx),
            )
        log = self.query_one("#junk-log", RichLog)
        log.write(summary_msg)
        self.query_one("#btn-scan-orphans", Button).disabled = False
        self.query_one("#btn-scan-removed", Button).disabled = False
        self._update_clean_button()

    @work(thread=True)
    def scan_junk_task(self) -> None:
        """Runs safe system-wide orphaned leftovers scan on a background thread."""
        self._is_busy = True
        log = self.query_one("#junk-log", RichLog)
        self.app.call_from_thread(
            lambda: (
                setattr(self.query_one("#btn-scan-orphans", Button), "disabled", True),
                setattr(self.query_one("#btn-scan-removed", Button), "disabled", True),
                self._update_clean_button(),
            )
        )
        self.app.call_from_thread(
            log.write,
            "[cyan]Scanning system for verified orphaned leftovers (broken shortcuts, ghost uninstall keys, dead services/startup/firewall/COM)...[/cyan]",
        )
        if not is_admin():
            self.app.call_from_thread(
                log.write,
                "[dim]Tip: Running as standard user. Launch with 'wudo bcu tui' to clean HKLM/Services/Firewall orphans.[/dim]",
            )

        items = JunkCleaner.scan_system_orphans(
            all_apps=self.all_apps,
            min_confidence=ConfidenceLevel.GOOD,
            deep_scan=True,
        )

        msg = (
            f"[green]Orphan scan complete! Found {len(items)} verified orphaned leftover(s). "
            f"Use [bold]Space[/bold] to toggle items, [bold]A[/bold] to toggle all.[/green]"
        )
        self.app.call_from_thread(self._populate_table, items, msg)

    @work(thread=True)
    def scan_removed_app_task(self, removed_name: str) -> None:
        """Scans remnants for a specific previously-removed application by name."""
        self._is_busy = True
        log = self.query_one("#junk-log", RichLog)
        self.app.call_from_thread(
            lambda: (
                setattr(self.query_one("#btn-scan-orphans", Button), "disabled", True),
                setattr(self.query_one("#btn-scan-removed", Button), "disabled", True),
                self._update_clean_button(),
            )
        )
        self.app.call_from_thread(
            log.write,
            f"[cyan]Scanning leftovers for removed app '{escape_markup(removed_name)}'...[/cyan]",
        )

        ghost_entry = ApplicationEntry(id=f"removed:{removed_name.lower()}", display_name=removed_name)
        items = JunkCleaner.scan_app_junk(
            ghost_entry,
            all_apps=self.all_apps,
            min_confidence=ConfidenceLevel.GOOD,
            deep_scan=True,
        )

        msg = (
            f"[green]Found {len(items)} leftover item(s) matching removed app '{escape_markup(removed_name)}'.[/green]"
            if items
            else f"[green]No leftover remnants found for '{escape_markup(removed_name)}'.[/green]"
        )
        self.app.call_from_thread(self._populate_table, items, msg)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close-junk":
            if not self._is_busy:
                self.dismiss(True)
        elif event.button.id == "btn-scan-orphans":
            if not self._is_busy:
                self.scan_junk_task()
        elif event.button.id == "btn-scan-removed":
            self._trigger_removed_app_scan()
        elif event.button.id == "btn-start-clean":
            if self._is_busy or not self.selected_indices:
                return
            self._is_busy = True
            self.query_one("#btn-start-clean", Button).disabled = True
            self.query_one("#btn-close-junk", Button).disabled = True
            self.query_one("#btn-scan-orphans", Button).disabled = True
            self.query_one("#btn-scan-removed", Button).disabled = True
            is_dryrun = self.query_one("#junk-opt-dryrun", Checkbox).value
            backup_reg = self.query_one("#junk-opt-backup", Checkbox).value
            chosen = [self.junk_items[i] for i in sorted(self.selected_indices) if i < len(self.junk_items)]
            self.clean_junk_task(chosen_items=chosen, is_dryrun=is_dryrun, backup_reg=backup_reg)

    @work(thread=True)
    def clean_junk_task(self, chosen_items: List[JunkItem], is_dryrun: bool, backup_reg: bool) -> None:
        """Executes cleanup ONLY on user-selected orphaned items on a background thread."""
        log = self.query_one("#junk-log", RichLog)

        mode_label = "[DRY-RUN] " if is_dryrun else ""
        self.app.call_from_thread(
            log.write,
            f"\n[yellow]{mode_label}Processing {len(chosen_items)} selected orphaned item(s)...[/yellow]",
        )
        results = JunkCleaner.clean_junk(chosen_items, dry_run=is_dryrun, backup_registry=backup_reg)

        def finish():
            self._is_busy = False
            for item, ok, msg in results:
                safe_path = escape_markup(item.path)
                safe_msg = escape_markup(msg)
                if ok:
                    log.write(f" [green]✓[/green] {item.junk_type.value}: {safe_path} ({safe_msg})")
                else:
                    log.write(f" [red]✗[/red] {item.junk_type.value}: {safe_path} ({safe_msg})")
            cleaned = sum(1 for _, ok, _ in results if ok)
            log.write(f"\n[bold green]Finished! {cleaned}/{len(results)} selected items processed.[/bold green]")
            self.query_one("#btn-close-junk", Button).disabled = False
            self.query_one("#btn-scan-orphans", Button).disabled = False
            self.query_one("#btn-scan-removed", Button).disabled = False
            self._update_clean_button()

        self.app.call_from_thread(finish)
