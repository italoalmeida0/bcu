"""
Modal screen for AI Assistant system diagnostics and health overview.
"""

from __future__ import annotations

from typing import List
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static
from bcu import __version__
from bcu.junk.cleaner import get_backup_dir
from bcu.models import ApplicationEntry
from bcu.utils.formatting import format_size


class AiDiagModal(ModalScreen[None]):
    """Modal screen displaying AI Assistant system diagnosis."""

    def __init__(self, apps: List[ApplicationEntry]):
        super().__init__()
        self.apps = apps

    def compose(self) -> ComposeResult:
        total = len(self.apps)
        quiet_count = sum(1 for a in self.apps if a.quiet_uninstall_possible)
        large_apps = sorted(self.apps, key=lambda a: a.estimated_size_bytes or 0, reverse=True)[:8]

        with Vertical(classes="modal-container"):
            yield Label("🤖 AI ASSISTANT DIAGNOSTIC SUITE", classes="modal-title")
            yield Label("System software health overview & AI agent recommendations.", classes="modal-subtitle")

            with VerticalScroll(classes="diag-scroll"):
                yield Label(f"[bold cyan]BCU Version:[/bold cyan] {__version__}  |  [bold cyan]Backup Path:[/bold cyan] {get_backup_dir()}")
                yield Label(f"[bold cyan]Inventory Status:[/bold cyan] {total} apps installed  |  {quiet_count} support silent unattended uninstall")

                yield Label("\n[bold yellow]TOP LARGEST APPLICATIONS:[/bold yellow]")
                for app in large_apps:
                    yield Label(f" • [bold white]{app.display_name}[/bold white] - [green]{format_size(app.estimated_size_bytes)}[/green] [dim]({app.uninstaller_type.value})[/dim]")

                yield Label("\n[bold yellow]RECOMMENDED AI ACTIONS:[/bold yellow]")
                yield Label(" • [cyan]bcu uninstall <id> --quiet --yes --deep-junk --kill-running[/cyan] -> Clean Slate uninstall")
                yield Label(" • [cyan]bcu scan-junk <id> --deep --json[/cyan] -> Discover all remnants across Services, Tasks, Registry")
                yield Label(" • [cyan]bcu mcp[/cyan] -> Start MCP server for Claude Desktop / Cursor / Antigravity")

            with Vertical(classes="modal-buttons"):
                yield Button("CLOSE", variant="primary", id="btn-close-diag")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close-diag":
            self.dismiss(None)
