"""
Modal screen for uninstallation confirmation and live execution progress.
Responsive layout ensures all options, logs, and action buttons remain visible even at 80x24.
"""

from __future__ import annotations

from typing import List, Optional
from rich.markup import escape as escape_markup
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Label, ProgressBar, RichLog, Static

from bcu.engine.batch import BatchUninstallQueue
from bcu.models import ApplicationEntry, ConfidenceLevel, UninstallResult


class UninstallModal(ModalScreen[bool]):
    """Modal dialog managing uninstallation execution and live progress."""

    BINDINGS = [
        Binding("escape", "close_modal", "Close", show=True),
    ]

    def __init__(
        self,
        target_apps: List[ApplicationEntry],
        all_apps: Optional[List[ApplicationEntry]] = None,
    ):
        super().__init__()
        self.target_apps = target_apps
        self.all_apps = all_apps
        self.results: List[UninstallResult] = []
        self._is_running = False

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label("⚡ BULK UNINSTALLATION MANAGER", classes="modal-title")
            yield Label(
                f"Selected {len(self.target_apps)} application(s) for uninstallation:",
                classes="modal-subtitle",
            )

            with Vertical(classes="modal-body"):
                with VerticalScroll(classes="modal-app-list"):
                    for app in self.target_apps:
                        safe_name = escape_markup(app.display_name_trimmed)
                        prot = " [bold red][PROTECTED][/bold red]" if app.is_protected else ""
                        yield Static(f" • [bold white]{safe_name}[/bold white] [dim]({app.uninstaller_type.value})[/dim]{prot}")

                with Grid(classes="modal-options-grid"):
                    yield Checkbox("Prefer Quiet / Silent Mode", value=True, id="opt-quiet", classes="compact-cb")
                    yield Checkbox("Dry-Run Simulation Only", value=False, id="opt-dryrun", classes="compact-cb")
                    yield Checkbox("Clean Slate Remnants", value=True, id="opt-junk", classes="compact-cb")
                    yield Checkbox("Terminate Locking Processes", value=True, id="opt-kill", classes="compact-cb")
                    yield Checkbox("Auto .reg Registry Backup", value=True, id="opt-backup", classes="compact-cb")
                    yield Checkbox("Create Restore Point (Admin)", value=False, id="opt-restore", classes="compact-cb")

                yield ProgressBar(total=max(1, len(self.target_apps)), id="uninstall-progress", classes="modal-progress")
                yield RichLog(highlight=True, markup=True, wrap=True, id="uninstall-log", classes="modal-log")

            with Horizontal(classes="modal-buttons"):
                yield Button("START UNINSTALL", variant="error", id="btn-start-uninstall", classes="modal-btn")
                yield Button("CANCEL / CLOSE", variant="default", id="btn-close-modal", classes="modal-btn")

    def action_close_modal(self) -> None:
        if not self._is_running:
            self.dismiss(bool(self.results))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close-modal":
            if not self._is_running:
                self.dismiss(bool(self.results))
        elif event.button.id == "btn-start-uninstall":
            if self._is_running:
                return
            self._is_running = True
            self.query_one("#btn-start-uninstall", Button).disabled = True
            self.query_one("#btn-close-modal", Button).disabled = True

            # Capture checkbox values safely on the main UI thread
            opts = {
                "is_quiet": self.query_one("#opt-quiet", Checkbox).value,
                "is_dryrun": self.query_one("#opt-dryrun", Checkbox).value,
                "clean_junk": self.query_one("#opt-junk", Checkbox).value,
                "kill_running": self.query_one("#opt-kill", Checkbox).value,
                "backup_reg": self.query_one("#opt-backup", Checkbox).value,
                "restore_point": self.query_one("#opt-restore", Checkbox).value,
            }
            self.run_uninstall_task(**opts)

    @work(thread=True)
    def run_uninstall_task(
        self,
        is_quiet: bool,
        is_dryrun: bool,
        clean_junk: bool,
        kill_running: bool,
        backup_reg: bool,
        restore_point: bool,
    ) -> None:
        """Runs uninstallation queue on a background thread with thread-safe UI updates."""
        log = self.query_one("#uninstall-log", RichLog)
        progress = self.query_one("#uninstall-progress", ProgressBar)

        self.app.call_from_thread(
            log.write,
            f"[bold cyan]Initializing batch queue for {len(self.target_apps)} application(s)...[/bold cyan]",
        )
        if is_dryrun:
            self.app.call_from_thread(
                log.write,
                "[bold magenta]>>> DRY-RUN SIMULATION ACTIVE - NO CHANGES WILL BE MADE <<<[/bold magenta]",
            )

        queue = BatchUninstallQueue(
            apps=self.target_apps,
            prefer_quiet=is_quiet,
            dry_run=is_dryrun,
            clean_junk=clean_junk,
            deep_junk=clean_junk,
            kill_running=kill_running,
            backup_registry=backup_reg,
            create_restore_point=restore_point,
            junk_min_confidence=ConfidenceLevel.GOOD,
            all_apps=self.all_apps,
        )

        def on_start(app: ApplicationEntry, idx: int, total: int):
            self.app.call_from_thread(
                log.write,
                f"\n[cyan][{idx}/{total}] Processing:[/cyan] [bold white]{escape_markup(app.display_name_trimmed)}[/bold white]...",
            )

        def on_finish(res: UninstallResult, idx: int, total: int):
            def update_ui():
                progress.advance(1)
                safe_name = escape_markup(res.app_name)
                if res.status.value == "Completed":
                    log.write(
                        f"[green]✓ COMPLETED:[/green] {safe_name} "
                        f"(Duration: {res.duration_sec:.1f}s, Junk: {res.junk_cleaned_count})"
                    )
                else:
                    safe_err = escape_markup(res.error_message or "Unknown error")
                    log.write(f"[red]✗ FAILED:[/red] {safe_name} (Error: {safe_err})")

            self.app.call_from_thread(update_ui)

        def on_prog(msg: str):
            self.app.call_from_thread(log.write, f" [dim]-> {escape_markup(msg)}[/dim]")

        try:
            self.results = queue.run(on_app_start=on_start, on_app_finish=on_finish, on_progress=on_prog)
        except Exception as exc:
            self.app.call_from_thread(log.write, f"[bold red]Unexpected error: {escape_markup(str(exc))}[/bold red]")

        def finish_ui():
            self._is_running = False
            successes = sum(1 for r in self.results if r.status.value == "Completed")
            log.write(
                f"\n[bold green]Batch Complete! {successes}/{len(self.results)} finished successfully.[/bold green]"
            )
            close_btn = self.query_one("#btn-close-modal", Button)
            close_btn.disabled = False
            close_btn.label = "CLOSE"

        self.app.call_from_thread(finish_ui)
