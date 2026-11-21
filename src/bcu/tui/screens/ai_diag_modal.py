"""
Modal screen for AI Assistant system diagnostics and health overview.
"""

from __future__ import annotations

from typing import List
from rich.markup import escape as escape_markup
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static
from bcu import __version__
from bcu.junk.cleaner import get_backup_dir
from bcu.models import ApplicationEntry
from bcu.utils.formatting import format_size
from bcu.utils.platform import is_admin


class AiDiagModal(ModalScreen[None]):
    """Modal screen displaying AI Assistant system diagnosis."""

    BINDINGS = [
        Binding("escape", "close_modal", "Close", show=True),
    ]

    def __init__(self, apps: List[ApplicationEntry]):
        super().__init__()
        self.apps = apps

    def compose(self) -> ComposeResult:
        total = len(self.apps)
        quiet_count = sum(1 for a in self.apps if a.quiet_uninstall_possible)
        large_apps = sorted(self.apps, key=lambda a: a.estimated_size_bytes or 0, reverse=True)[:8]
        priv_str = "[bold green]Elevated (Admin)[/bold green]" if is_admin() else "[yellow]Standard User (run with wudo for full system access)[/yellow]"

        with Vertical(classes="modal-container"):
            yield Label("🤖 AI ASSISTANT DIAGNOSTIC SUITE", classes="modal-title")
            yield Label("System software health overview & AI agent recommendations.", classes="modal-subtitle")

            with VerticalScroll(classes="diag-scroll"):
                yield Static(
                    f"[bold cyan]BCU Version:[/bold cyan] {__version__}  |  "
                    f"[bold cyan]Privileges:[/bold cyan] {priv_str}"
                )
                yield Static(f"[bold cyan]Backup Path:[/bold cyan] {escape_markup(str(get_backup_dir()))}")
                yield Static(
                    f"[bold cyan]Inventory:[/bold cyan] {total} apps installed  |  "
                    f"{quiet_count} support silent unattended uninstall"
                )

                yield Static("\n[bold yellow]TOP LARGEST APPLICATIONS:[/bold yellow]")
                if large_apps:
                    for app in large_apps:
                        safe_name = escape_markup(app.display_name_trimmed)
                        yield Static(
                            f" • [bold white]{safe_name}[/bold white] - "
                            f"[green]{format_size(app.estimated_size_bytes)}[/green] "
                            f"[dim]({app.uninstaller_type.value})[/dim]"
                        )
                else:
                    yield Static(" [dim]No applications loaded yet.[/dim]")

                yield Static("\n[bold yellow]RECOMMENDED AI & CLI ACTIONS:[/bold yellow]")
                yield Static(" • [cyan]bcu uninstall <id> --quiet --yes --deep-junk --kill-running[/cyan]")
                yield Static(" • [cyan]bcu scan-junk <id> --deep --json[/cyan]")
                yield Static(" • [cyan]bcu audit --min-severity High --json[/cyan]")
                yield Static(" • [cyan]bcu mcp[/cyan] -> Start MCP server for AI assistants")

            with Horizontal(classes="modal-buttons"):
                yield Button("CLOSE", variant="primary", id="btn-close-diag", classes="modal-btn")

    def action_close_modal(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close-diag":
            self.dismiss(None)
