"""
Modal screen for uninstallation confirmation and live execution progress.
"""

from __future__ import annotations

from typing import List
from textual import work
from textual.app import ComposeResult
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Label, ProgressBar, RichLog, Static

from bcu.engine.batch import BatchUninstallQueue
from bcu.models import ApplicationEntry, ConfidenceLevel, UninstallResult


class UninstallModal(ModalScreen[bool]):
    """Modal dialog managing uninstallation execution and live progress."""

    def __init__(self, target_apps: List[ApplicationEntry]):
        super().__init__()
        self.target_apps = target_apps
        self.results: List[UninstallResult] = []

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label("⚡ BULK UNINSTALLATION MANAGER", classes="modal-title")
            yield Label(
                f"You have selected {len(self.target_apps)} application(s) for uninstallation:",
                classes="modal-subtitle",
            )

            with VerticalScroll(classes="modal-app-list"):
                for app in self.target_apps:
                    yield Label(f" • [bold white]{app.display_name}[/bold white] [dim]({app.uninstaller_type.value})[/dim]")

            with Grid(classes="modal-options-grid"):
                yield Checkbox("Prefer Quiet / Silent Mode", value=True, id="opt-quiet")
                yield Checkbox("Dry-Run Simulation Only", value=False, id="opt-dryrun")
                yield Checkbox("Clean Slate Remnants (Services, Tasks, Reg)", value=True, id="opt-junk")
                yield Checkbox("Terminate Locking Processes", value=True, id="opt-kill")
                yield Checkbox("Auto .reg Registry Backup", value=True, id="opt-backup")

            yield ProgressBar(total=len(self.target_apps), id="uninstall-progress", classes="modal-progress")
            yield RichLog(highlight=True, markup=True, id="uninstall-log", classes="modal-log")

            with Horizontal(classes="modal-buttons"):
                yield Button("START UNINSTALL", variant="error", id="btn-start-uninstall")
                yield Button("CANCEL / CLOSE", variant="default", id="btn-close-modal")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close-modal":
            self.dismiss(True if self.results else False)
        elif event.button.id == "btn-start-uninstall":
            self.query_one("#btn-start-uninstall", Button).disabled = True
            self.query_one("#btn-close-modal", Button).disabled = True
            self.run_uninstall_task()

    @work(thread=True)
    def run_uninstall_task(self) -> None:
        """Runs uninstallation queue on a background thread."""
        is_quiet = self.query_one("#opt-quiet", Checkbox).value
        is_dryrun = self.query_one("#opt-dryrun", Checkbox).value
        clean_junk = self.query_one("#opt-junk", Checkbox).value
        kill_running = self.query_one("#opt-kill", Checkbox).value
        backup_reg = self.query_one("#opt-backup", Checkbox).value

        log = self.query_one("#uninstall-log", RichLog)
        progress = self.query_one("#uninstall-progress", ProgressBar)

        log.write(f"[bold cyan]Initializing batch queue for {len(self.target_apps)} applications...[/bold cyan]")
        if is_dryrun:
            log.write("[bold magenta]>>> DRY-RUN SIMULATION ACTIVE - NO CHANGES WILL BE MADE <<<[/bold magenta]")

        queue = BatchUninstallQueue(
            apps=self.target_apps,
            prefer_quiet=is_quiet,
            dry_run=is_dryrun,
            clean_junk=clean_junk,
            deep_junk=clean_junk,
            kill_running=kill_running,
            backup_registry=backup_reg,
            junk_min_confidence=ConfidenceLevel.GOOD,
        )

        def on_start(app: ApplicationEntry, idx: int, total: int):
            self.app.call_from_thread(
                log.write,
                f"\n[cyan][{idx}/{total}] Processing:[/cyan] [bold white]{app.display_name}[/bold white]...",
            )

        def on_finish(res: UninstallResult, idx: int, total: int):
            def update_ui():
                progress.advance(1)
                if res.status.value == "Completed":
                    log.write(
                        f"[green]✓ COMPLETED:[/green] {res.app_name} (Duration: {res.duration_sec:.1f}s, Cleaned: {res.junk_cleaned_count} items)"
                    )
                else:
                    log.write(f"[red]✗ FAILED:[/red] {res.app_name} (Error: {res.error_message})")

            self.app.call_from_thread(update_ui)

        def on_prog(msg: str):
            self.app.call_from_thread(log.write, f" [dim]-> {msg}[/dim]")

        self.results = queue.run(on_app_start=on_start, on_app_finish=on_finish, on_progress=on_prog)

        def finish_ui():
            successes = sum(1 for r in self.results if r.status.value == "Completed")
            log.write(f"\n[bold green]Batch Complete! {successes}/{len(self.results)} finished successfully.[/bold green]")
            self.query_one("#btn-close-modal", Button).disabled = False
            self.query_one("#btn-close-modal", Button).label = "CLOSE"

        self.app.call_from_thread(finish_ui)
