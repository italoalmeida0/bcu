"""
Inspector Sidebar Widget for detailed application analysis and metadata inspection.
"""

from __future__ import annotations

from typing import Optional
from rich.markup import escape as escape_markup
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Label, Static
from bcu.models import ApplicationEntry
from bcu.utils.formatting import format_size


class InspectorSidebar(Static):
    """Right-side drawer showing full inspection details for the currently focused application."""

    def __init__(self, **kwargs):
        super().__init__(classes="inspector-sidebar", **kwargs)
        self.current_app: Optional[ApplicationEntry] = None

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="inspector-scroll"):
            yield Label("APPLICATION INSPECTOR", classes="inspector-title")
            yield Static("No application selected", id="insp-name", classes="insp-header-name")
            yield Static("", id="insp-pub", classes="insp-meta")

            with Vertical(classes="insp-section"):
                yield Label("PROPERTY OVERVIEW", classes="insp-section-title")
                yield Static("Version: -", id="insp-ver", classes="insp-field")
                yield Static("Disk Size: -", id="insp-size", classes="insp-field")
                yield Static("Type: -", id="insp-type", classes="insp-field")
                yield Static("Quiet Uninstall: -", id="insp-quiet", classes="insp-field")
                yield Static("Architecture: -", id="insp-arch", classes="insp-field")
                yield Static("Flags: -", id="insp-flags", classes="insp-field")

            with Vertical(classes="insp-section"):
                yield Label("UNINSTALL COMMAND", classes="insp-section-title")
                yield Static("-", id="insp-cmd", classes="insp-code-block")

            with Vertical(classes="insp-section"):
                yield Label("SYSTEM LOCATION", classes="insp-section-title")
                yield Static("Install Dir: -", id="insp-loc", classes="insp-code-block")
                yield Static("Registry: -", id="insp-reg", classes="insp-code-block")

    def inspect_app(self, app: Optional[ApplicationEntry]) -> None:
        """Updates inspector with selected application details (safely escaped for Rich markup)."""
        self.current_app = app
        if not app:
            self.query_one("#insp-name", Static).update("No application selected")
            self.query_one("#insp-pub", Static).update("")
            self.query_one("#insp-ver", Static).update("Version: -")
            self.query_one("#insp-size", Static).update("Disk Size: -")
            self.query_one("#insp-type", Static).update("Type: -")
            self.query_one("#insp-quiet", Static).update("Quiet Uninstall: -")
            self.query_one("#insp-arch", Static).update("Architecture: -")
            self.query_one("#insp-flags", Static).update("Flags: -")
            self.query_one("#insp-cmd", Static).update("-")
            self.query_one("#insp-loc", Static).update("Install Dir: -")
            self.query_one("#insp-reg", Static).update("Registry: -")
            return

        name_text = escape_markup(app.display_name_trimmed)
        pub_text = f"by {escape_markup(app.publisher_trimmed)}" if app.publisher_trimmed else "Publisher unknown"
        ver_text = f"Version: {escape_markup(app.display_version or 'N/A')}"
        size_text = f"Disk Size: {format_size(app.estimated_size_bytes)}"
        type_text = f"Type: {app.uninstaller_type.value} ({app.source_scanner})"
        quiet_text = (
            "Quiet: [green]Supported (Yes)[/green]"
            if app.quiet_uninstall_possible
            else "Quiet: [yellow]No (Loud Only)[/yellow]"
        )
        arch_text = f"Arch: {'64-bit Native' if app.is_64_bit else '32-bit / Universal'}"

        flags = []
        if app.is_system_component:
            flags.append("[yellow]System[/yellow]")
        if app.is_protected:
            flags.append("[red]Protected[/red]")
        flags_text = f"Flags: {', '.join(flags)}" if flags else "Flags: Standard"

        cmd_raw = app.quiet_uninstall_string or app.uninstall_string or "No uninstaller command"
        cmd_text = escape_markup(cmd_raw)
        loc_text = f"Install Dir:\n{escape_markup(app.install_location or 'Not specified')}"
        reg_text = f"Registry:\n{escape_markup(app.registry_path or 'N/A')}"

        self.query_one("#insp-name", Static).update(name_text)
        self.query_one("#insp-pub", Static).update(pub_text)
        self.query_one("#insp-ver", Static).update(ver_text)
        self.query_one("#insp-size", Static).update(size_text)
        self.query_one("#insp-type", Static).update(type_text)
        self.query_one("#insp-quiet", Static).update(quiet_text)
        self.query_one("#insp-arch", Static).update(arch_text)
        self.query_one("#insp-flags", Static).update(flags_text)
        self.query_one("#insp-cmd", Static).update(cmd_text)
        self.query_one("#insp-loc", Static).update(loc_text)
        self.query_one("#insp-reg", Static).update(reg_text)
