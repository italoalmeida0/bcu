"""
Modal screen for reviewing and cleaning remnant junk items.
"""

from __future__ import annotations

from typing import List
from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Label, ProgressBar, RichLog

from bcu.junk.cleaner import JunkCleaner
from bcu.models import ApplicationEntry, ConfidenceLevel, JunkItem
from bcu.utils.formatting import confidence_color


class JunkModal(ModalScreen[bool]):
    """Modal dialog displaying detected junk remnants with one-click cleanup."""

    def __init__(self, target_apps: List[ApplicationEntry], all_apps: List[ApplicationEntry]):
        super().__init__()
        self.target_apps = target_apps
        self.all_apps = all_apps
        self.junk_items: List[JunkItem] = []

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label("🧹 CLEAN SLATE REMNANT MANAGER", classes="modal-title")
            yield Label("Scanning and managing leftover services, registry keys, and directories.", classes="modal-subtitle")

            yield DataTable(id="junk-table", classes="modal-table")

            with Horizontal(classes="modal-options-row"):
                yield Checkbox("Dry-Run Simulation", value=False, id="junk-opt-dryrun")
                yield Checkbox("Auto .reg Backup", value=True, id="junk-opt-backup")

            yield RichLog(highlight=True, markup=True, id="junk-log", classes="modal-log")

            with Horizontal(classes="modal-buttons"):
                yield Button("CLEAN DETECTED JUNK", variant="warning", id="btn-start-clean")
                yield Button("CLOSE", variant="default", id="btn-close-junk")

    def on_mount(self) -> None:
        table = self.query_one("#junk-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Type", "Confidence", "Score", "Application", "Remnant Target Path")
        self.scan_junk_task()

    @work(thread=True)
    def scan_junk_task(self) -> None:
        """Runs remnant scan on a background thread."""
        log = self.query_one("#junk-log", RichLog)
        table = self.query_one("#junk-table", DataTable)
        self.app.call_from_thread(log.write, "[cyan]Deep scanning for leftover remnants...[/cyan]")

        items: List[JunkItem] = []
        for app in self.target_apps:
            found = JunkCleaner.scan_app_junk(
                app,
                all_apps=self.all_apps,
                min_confidence=ConfidenceLevel.GOOD,
                deep_scan=True,
            )
            items.extend(found)

        self.junk_items = items

        def populate_table():
            for item in self.junk_items:
                color = confidence_color(item.confidence_level)
                conf_text = f"[{color}]{item.confidence_level.value}[/{color}]"
                table.add_row(
                    item.junk_type.value,
                    conf_text,
                    str(item.raw_score),
                    item.app_name,
                    item.path,
                )
            log.write(f"[green]Scan complete! Discovered {len(self.junk_items)} leftover remnant items.[/green]")

        self.app.call_from_thread(populate_table)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close-junk":
            self.dismiss(True)
        elif event.button.id == "btn-start-clean":
            self.query_one("#btn-start-clean", Button).disabled = True
            self.clean_junk_task()

    @work(thread=True)
    def clean_junk_task(self) -> None:
        """Executes junk cleanup on a background thread."""
        log = self.query_one("#junk-log", RichLog)
        is_dryrun = self.query_one("#junk-opt-dryrun", Checkbox).value
        backup_reg = self.query_one("#junk-opt-backup", Checkbox).value

        self.app.call_from_thread(log.write, f"\n[yellow]Beginning cleanup of {len(self.junk_items)} items...[/yellow]")
        results = JunkCleaner.clean_junk(self.junk_items, dry_run=is_dryrun, backup_registry=backup_reg)

        def finish():
            for item, ok, msg in results:
                if ok:
                    log.write(f" [green]✓[/green] Deleted {item.junk_type.value}: {item.path} ({msg})")
                else:
                    log.write(f" [red]✗[/red] Failed {item.junk_type.value}: {item.path} ({msg})")
            log.write(f"\n[bold green]Cleanup finished! {sum(1 for _, ok, _ in results if ok)}/{len(results)} items cleaned.[/bold green]")
            self.query_one("#btn-start-clean", Button).disabled = False

        self.app.call_from_thread(finish)
