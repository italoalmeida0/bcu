"""
Inspector Sidebar Widget for detailed application analysis and live remnant preview.
"""

from __future__ import annotations

from typing import Optional
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Button, Label, Static
from bcu.models import ApplicationEntry
from bcu.utils.formatting import format_size


class InspectorSidebar(Static):
    """Right-side drawer showing full inspection details for the currently focused application."""

    def __init__(self):
        super().__init__(classes="inspector-sidebar")
        self.current_app: Optional[ApplicationEntry] = None

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="inspector-scroll"):
            yield Label("APPLICATION INSPECTOR", classes="inspector-title")
            yield Label("No application selected", id="insp-name", classes="insp-header-name")
            yield Label("", id="insp-pub", classes="insp-meta")

            with Vertical(classes="insp-section"):
                yield Label("PROPERTY OVERVIEW", classes="insp-section-title")
                yield Label("Version: -", id="insp-ver", classes="insp-field")
                yield Label("Disk Size: -", id="insp-size", classes="insp-field")
                yield Label("Type: -", id="insp-type", classes="insp-field")
                yield Label("Quiet Uninstall: -", id="insp-quiet", classes="insp-field")
                yield Label("64-Bit Native: -", id="insp-arch", classes="insp-field")

            with Vertical(classes="insp-section"):
                yield Label("UNINSTALL COMMAND", classes="insp-section-title")
                yield Label("-", id="insp-cmd", classes="insp-code-block")

            with Vertical(classes="insp-section"):
                yield Label("SYSTEM LOCATION", classes="insp-section-title")
                yield Label("Install Dir: -", id="insp-loc", classes="insp-code-block")
                yield Label("Registry: -", id="insp-reg", classes="insp-code-block")

    def inspect_app(self, app: Optional[ApplicationEntry]) -> None:
        """Updates inspector with selected application details."""
        self.current_app = app
        if not app:
            self.query_one("#insp-name", Label).update("No application selected")
            self.query_one("#insp-pub", Label).update("")
            self.query_one("#insp-ver", Label).update("Version: -")
            self.query_one("#insp-size", Label).update("Disk Size: -")
            self.query_one("#insp-type", Label).update("Type: -")
            self.query_one("#insp-quiet", Label).update("Quiet Uninstall: -")
            self.query_one("#insp-arch", Label).update("64-Bit Native: -")
            self.query_one("#insp-cmd", Label).update("-")
            self.query_one("#insp-loc", Label).update("Install Dir: -")
            self.query_one("#insp-reg", Label).update("Registry: -")
            return

        name_text = app.display_name_trimmed
        pub_text = f"by {app.publisher_trimmed}" if app.publisher_trimmed else "Publisher unknown"
        ver_text = f"Version: {app.display_version or 'N/A'}"
        size_text = f"Disk Size: {format_size(app.estimated_size_bytes)}"
        type_text = f"Type: {app.uninstaller_type.value} ({app.source_scanner})"
        quiet_text = "Quiet Uninstall: [green]Supported (Yes)[/green]" if app.quiet_uninstall_possible else "Quiet Uninstall: [yellow]No (Loud Only)[/yellow]"
        arch_text = f"64-Bit Native: {'Yes' if app.is_64_bit else 'No (32-bit/Universal)'}"

        cmd_text = app.quiet_uninstall_string or app.uninstall_string or "No uninstaller command"
        loc_text = f"Install Dir:\n{app.install_location or 'Not specified in registry'}"
        reg_text = f"Registry Path:\n{app.registry_path or 'N/A'}"

        self.query_one("#insp-name", Label).update(name_text)
        self.query_one("#insp-pub", Label).update(pub_text)
        self.query_one("#insp-ver", Label).update(ver_text)
        self.query_one("#insp-size", Label).update(size_text)
        self.query_one("#insp-type", Label).update(type_text)
        self.query_one("#insp-quiet", Label).update(quiet_text)
        self.query_one("#insp-arch", Label).update(arch_text)
        self.query_one("#insp-cmd", Label).update(cmd_text)
        self.query_one("#insp-loc", Label).update(loc_text)
        self.query_one("#insp-reg", Label).update(reg_text)
