"""
Formatting utilities for CLI output, rich tables, and AI json responses.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from bcu.models import ApplicationEntry, ConfidenceLevel, JunkItem, SeverityLevel, UninstallResult, VulnerabilityFinding

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "highlight": "bold magenta",
})

console = Console(theme=custom_theme)
err_console = Console(stderr=True, theme=custom_theme)


def format_size(size_bytes: Optional[int]) -> str:
    """Formats bytes into human readable size string."""
    if size_bytes is None or size_bytes < 0:
        return "Unknown"
    if size_bytes == 0:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    size = float(size_bytes)
    while size >= 1024.0 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1
    return f"{size:.1f} {units[unit_index]}"


def confidence_color(level: ConfidenceLevel) -> str:
    """Returns color code for confidence levels."""
    if level == ConfidenceLevel.VERY_GOOD:
        return "green"
    elif level == ConfidenceLevel.GOOD:
        return "cyan"
    elif level == ConfidenceLevel.QUESTIONABLE:
        return "yellow"
    elif level == ConfidenceLevel.BAD:
        return "red"
    return "dim"


def severity_color(level: SeverityLevel) -> str:
    """Returns color code for vulnerability severity levels."""
    if level == SeverityLevel.CRITICAL:
        return "bold red"
    elif level == SeverityLevel.HIGH:
        return "bold bright_red"
    elif level == SeverityLevel.MEDIUM:
        return "bold yellow"
    elif level == SeverityLevel.LOW:
        return "bold cyan"
    return "dim"


def build_apps_table(apps: List[ApplicationEntry], title: str = "Installed Applications") -> Table:
    """Constructs a Rich Table for listing application entries."""
    table = Table(title=title, show_header=True, header_style="bold cyan", border_style="dim")
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Display Name", style="bold white", min_width=25)
    table.add_column("Version", style="dim cyan", max_width=15)
    table.add_column("Publisher", style="magenta", max_width=20)
    table.add_column("Size", justify="right", style="green")
    table.add_column("Type", style="yellow")
    table.add_column("Quiet?", justify="center")

    for i, app in enumerate(apps, 1):
        quiet_str = "[green]✓[/green]" if app.quiet_uninstall_possible else "[dim]✗[/dim]"
        name_text = app.display_name_trimmed
        if len(name_text) > 40:
            name_text = name_text[:37] + "..."

        table.add_row(
            str(i),
            name_text,
            app.display_version or "-",
            app.publisher_trimmed or "-",
            format_size(app.estimated_size_bytes),
            app.uninstaller_type.value,
            quiet_str,
        )
    return table


def build_junk_table(items: List[JunkItem], title: str = "Detected Junk Remnants") -> Table:
    """Constructs a Rich Table for displaying remnant junk items."""
    table = Table(title=title, show_header=True, header_style="bold yellow", border_style="dim")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Application", style="bold cyan", max_width=25)
    table.add_column("Type", style="magenta")
    table.add_column("Confidence", justify="center")
    table.add_column("Score", justify="right", style="dim")
    table.add_column("Target Path / Key", style="white")

    for i, item in enumerate(items, 1):
        color = confidence_color(item.confidence_level)
        conf_text = f"[{color}]{item.confidence_level.value}[/{color}]"
        path_text = item.path
        if len(path_text) > 60:
            path_text = "..." + path_text[-57:]

        table.add_row(
            str(i),
            item.app_name,
            item.junk_type.value,
            conf_text,
            str(item.raw_score),
            path_text,
        )
    return table


def build_vuln_table(findings: List[VulnerabilityFinding], title: str = "Software Vulnerability Audit") -> Table:
    """Constructs a Rich Table for displaying security vulnerability findings."""
    table = Table(title=title, show_header=True, header_style="bold red", border_style="dim")
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("CVE / ID", style="bold cyan", no_wrap=True)
    table.add_column("Application", style="bold white", min_width=20)
    table.add_column("Installed", style="dim white", no_wrap=True)
    table.add_column("Affected", style="dim yellow", no_wrap=True)
    table.add_column("Fixed In", style="bold green", no_wrap=True)
    table.add_column("Title / Advisory", style="white")

    for i, f in enumerate(findings, 1):
        color = severity_color(f.severity)
        sev_badge = f"[{color}]{f.severity.value.upper()}[/{color}]"
        fixed = f"[bold green]{f.fixed_version}[/bold green]" if f.fixed_version else "[dim]-[/dim]"

        table.add_row(
            str(i),
            sev_badge,
            f.id,
            f.app_name,
            f.installed_version,
            f.affected_range,
            fixed,
            f.title,
        )
    return table


def to_json_output(data: Any, pretty: bool = True) -> str:
    """Serializes data models to JSON string."""
    if hasattr(data, "model_dump"):
        raw = data.model_dump()
    elif isinstance(data, list):
        raw = [item.model_dump() if hasattr(item, "model_dump") else item for item in data]
    else:
        raw = data
    return json.dumps(raw, indent=2 if pretty else None, ensure_ascii=False)
