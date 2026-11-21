"""
Modal screen for reviewing and cleaning remnant junk items.
Responsive layout ensures table, options, log, and buttons always fit cleanly at 80x24+.
"""

from __future__ import annotations

from typing import List
from rich.markup import escape as escape_markup
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Label, RichLog

from bcu.junk.cleaner import JunkCleaner
from bcu.models import ApplicationEntry, ConfidenceLevel, JunkItem
from bcu.utils.formatting import confidence_color


class JunkModal(ModalScreen[bool]):
    """Modal dialog displaying detected junk remnants with one-click cleanup."""

    BINDINGS = [
        Binding("escape", "close_modal", "Close", show=True),
    ]

    def __init__(self, target_apps: List[ApplicationEntry], all_apps: List[ApplicationEntry]):
        super().__init__()
        self.target_apps = target_apps
        self.all_apps = all_apps
        self.junk_items: List[JunkItem] = []
        self._is_busy = False

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label("🧹 CLEAN SLATE REMNANT MANAGER", classes="modal-title")
            yield Label(
                f"Scanning leftover services, registry keys, tasks & folders ({len(self.target_apps)} target app(s)).",
                classes="modal-subtitle",
            )

            with Vertical(classes="modal-body"):
                yield DataTable(id="junk-table", classes="modal-table")

                with Horizontal(classes="modal-options-row"):
                    yield Checkbox("Dry-Run Simulation", value=True, id="junk-opt-dryrun", classes="compact-cb")
                    yield Checkbox("Auto .reg Backup", value=True, id="junk-opt-backup", classes="compact-cb")

                yield RichLog(highlight=True, markup=True, wrap=True, id="junk-log", classes="modal-log-sm")

            with Horizontal(classes="modal-buttons"):
                yield Button("CLEAN DETECTED JUNK", variant="warning", id="btn-start-clean", disabled=True, classes="modal-btn")
                yield Button("CLOSE", variant="default", id="btn-close-junk", classes="modal-btn")

    def on_mount(self) -> None:
        table = self.query_one("#junk-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Type", "Conf", "Score", "App", "Target Path")
        self.scan_junk_task()

    def action_close_modal(self) -> None:
        if not self._is_busy:
            self.dismiss(True)

    @work(thread=True)
    def scan_junk_task(self) -> None:
        """Runs remnant scan on a background thread."""
        self._is_busy = True
        log = self.query_one("#junk-log", RichLog)
        table = self.query_one("#junk-table", DataTable)
        self.app.call_from_thread(log.write, "[cyan]Deep scanning for leftover remnants...[/cyan]")

        items: List[JunkItem] = []
        for app in self.target_apps:
            try:
                found = JunkCleaner.scan_app_junk(
                    app,
                    all_apps=self.all_apps,
                    min_confidence=ConfidenceLevel.GOOD,
                    deep_scan=True,
                )
                items.extend(found)
            except Exception as exc:
                self.app.call_from_thread(
                    log.write,
                    f"[yellow]Warning scanning {escape_markup(app.display_name_trimmed)}: {escape_markup(str(exc))}[/yellow]",
                )

        self.junk_items = items

        def populate_table():
            self._is_busy = False
            table.clear()
            for item in self.junk_items:
                color = confidence_color(item.confidence_level)
                conf_text = f"[{color}]{item.confidence_level.value}[/{color}]"
                table.add_row(
                    item.junk_type.value,
                    conf_text,
                    str(item.raw_score),
                    escape_markup(item.app_name[:22]),
                    escape_markup(item.path),
                )
            log.write(f"[green]Scan complete! Discovered {len(self.junk_items)} leftover remnant item(s).[/green]")
            self.query_one("#btn-start-clean", Button).disabled = len(self.junk_items) == 0

        self.app.call_from_thread(populate_table)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close-junk":
            if not self._is_busy:
                self.dismiss(True)
        elif event.button.id == "btn-start-clean":
            if self._is_busy or not self.junk_items:
                return
            self._is_busy = True
            self.query_one("#btn-start-clean", Button).disabled = True
            self.query_one("#btn-close-junk", Button).disabled = True
            is_dryrun = self.query_one("#junk-opt-dryrun", Checkbox).value
            backup_reg = self.query_one("#junk-opt-backup", Checkbox).value
            self.clean_junk_task(is_dryrun=is_dryrun, backup_reg=backup_reg)

    @work(thread=True)
    def clean_junk_task(self, is_dryrun: bool, backup_reg: bool) -> None:
        """Executes junk cleanup on a background thread."""
        log = self.query_one("#junk-log", RichLog)

        mode_label = "[DRY-RUN] " if is_dryrun else ""
        self.app.call_from_thread(
            log.write,
            f"\n[yellow]{mode_label}Beginning cleanup of {len(self.junk_items)} item(s)...[/yellow]",
        )
        results = JunkCleaner.clean_junk(self.junk_items, dry_run=is_dryrun, backup_registry=backup_reg)

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
            log.write(f"\n[bold green]Cleanup finished! {cleaned}/{len(results)} items processed.[/bold green]")
            self.query_one("#btn-start-clean", Button).disabled = False
            self.query_one("#btn-close-junk", Button).disabled = False

        self.app.call_from_thread(finish)
