"""
Modal screen for interactive Software Vulnerability & CVE Security Audit.
"""

from __future__ import annotations

from typing import List
from rich.markup import escape as escape_markup
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Label, Static

from bcu.models import ApplicationEntry, SeverityLevel, VulnerabilityReport
from bcu.security.auditor import VulnerabilityAuditor
from bcu.utils.formatting import severity_color


class AuditModal(ModalScreen[None]):
    """Modal dialog running offline/online CVE audit against discovered applications."""

    BINDINGS = [
        Binding("escape", "close_modal", "Close", show=True),
    ]

    def __init__(self, apps: List[ApplicationEntry]):
        super().__init__()
        self.apps = apps
        self._is_running = False

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label("🛡 SOFTWARE VULNERABILITY & CVE AUDIT", classes="modal-title")
            yield Label(
                f"Auditing {len(self.apps)} installed application(s) against curated CVEs & OSV.dev feeds.",
                classes="modal-subtitle",
            )

            with Vertical(classes="modal-body"):
                yield Static("[cyan]Running offline CVE audit...[/cyan]", id="audit-summary", classes="audit-summary")
                yield DataTable(id="audit-table", classes="modal-table")

                with Horizontal(classes="modal-options-row"):
                    yield Checkbox("Include Online OSV.dev Feed", value=False, id="audit-opt-online", classes="compact-cb")

            with Horizontal(classes="modal-buttons"):
                yield Button("RE-RUN AUDIT", variant="primary", id="btn-rerun-audit", classes="modal-btn")
                yield Button("CLOSE", variant="default", id="btn-close-audit", classes="modal-btn")

    def on_mount(self) -> None:
        table = self.query_one("#audit-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Sev", "CVE / ID", "Application", "Installed", "Fixed", "Advisory")
        self.run_audit_task(online=False)

    def action_close_modal(self) -> None:
        if not self._is_running:
            self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close-audit":
            if not self._is_running:
                self.dismiss(None)
        elif event.button.id == "btn-rerun-audit":
            if self._is_running:
                return
            online = self.query_one("#audit-opt-online", Checkbox).value
            self.run_audit_task(online=online)

    @work(thread=True)
    def run_audit_task(self, online: bool) -> None:
        self._is_running = True
        summary_widget = self.query_one("#audit-summary", Static)
        table = self.query_one("#audit-table", DataTable)

        def set_loading():
            self.query_one("#btn-rerun-audit", Button).disabled = True
            mode = "curated offline DB + OSV.dev" if online else "curated offline CVE DB"
            summary_widget.update(f"[cyan]Scanning {len(self.apps)} apps against {mode}...[/cyan]")
            table.clear()

        self.app.call_from_thread(set_loading)

        report: VulnerabilityReport = VulnerabilityAuditor.audit_all(
            self.apps,
            min_severity=SeverityLevel.LOW,
            online=online,
        )

        def render_report():
            self._is_running = False
            self.query_one("#btn-rerun-audit", Button).disabled = False
            table.clear()
            for f in report.findings:
                color = severity_color(f.severity)
                sev_badge = f"[{color}]{f.severity.value.upper()}[/{color}]"
                fixed = f"[green]{escape_markup(f.fixed_version)}[/green]" if f.fixed_version else "-"
                table.add_row(
                    sev_badge,
                    escape_markup(f.id),
                    escape_markup(f.app_name[:26]),
                    escape_markup(f.installed_version[:14]),
                    fixed,
                    escape_markup(f.title[:48]),
                )

            if not report.findings:
                summary_widget.update(
                    f"[bold green]✓ Security Audit Passed![/bold green] "
                    f"No known vulnerabilities across {report.total_scanned} scanned apps."
                )
            else:
                b = report.severity_breakdown
                summary_widget.update(
                    f"[bold red]{report.total_vulnerabilities} issue(s) across {report.vulnerable_apps_count} app(s)[/bold red] | "
                    f"[bold red]Crit: {b.get('Critical', 0)}[/bold red]  "
                    f"[bright_red]High: {b.get('High', 0)}[/bright_red]  "
                    f"[yellow]Med: {b.get('Medium', 0)}[/yellow]  "
                    f"[cyan]Low: {b.get('Low', 0)}[/cyan]"
                )

        self.app.call_from_thread(render_report)
