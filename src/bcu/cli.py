"""
Command Line Interface for BCU (Bulk Crap Uninstaller) Python CLI.
Supports human-friendly rich terminal formatting and machine-readable JSON for AI agents.
"""

from __future__ import annotations

from contextlib import nullcontext
import sys
from typing import List, Optional
import click
from rich.markup import escape as escape_markup
from rich.prompt import Confirm

from bcu import __version__
from bcu.config import DEFAULT_PROCESS_TIMEOUT_SEC
from bcu.engine.batch import BatchUninstallQueue
from bcu.engine.uninstaller import UninstallerExecutor
from bcu.export.serializer import ApplicationSerializer
from bcu.junk.cleaner import JunkCleaner, get_backup_dir
from bcu.models import (
    ApplicationEntry,
    ConfidenceLevel,
    FilterCriteria,
    SeverityLevel,
    UninstallerType,
)
from bcu.scanners.manager import ScannerManager
from bcu.security.auditor import VulnerabilityAuditor
from bcu.utils.formatting import (
    build_apps_table,
    build_junk_table,
    build_vuln_table,
    console,
    err_console,
    to_json_output,
)


def parse_size_str(size_str: Optional[str]) -> Optional[int]:
    """Parses a string like '500MB', '1.5GB', '2TB', '100KB' into bytes."""
    if not size_str:
        return None
    s = size_str.strip().upper()
    multiplier = 1
    for suffix, mult in (
        ("TB", 1024 * 1024 * 1024 * 1024),
        ("T", 1024 * 1024 * 1024 * 1024),
        ("GB", 1024 * 1024 * 1024),
        ("G", 1024 * 1024 * 1024),
        ("MB", 1024 * 1024),
        ("M", 1024 * 1024),
        ("KB", 1024),
        ("K", 1024),
        ("B", 1),
    ):
        if s.endswith(suffix):
            multiplier = mult
            s = s[: -len(suffix)]
            break

    try:
        val = float(s.strip())
        if val < 0:
            return None
        return int(val * multiplier)
    except ValueError:
        return None


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="BCU-CLI")
def main():
    """Bulk Crap Uninstaller (BCU) - Python CLI & AI Agent Uninstallation Engine."""
    pass


@main.command(name="list")
@click.option("-q", "--query", help="Filter by text in app name, id, or publisher.")
@click.option("-p", "--publisher", help="Filter by publisher name.")
@click.option("-t", "--type", "uninstaller_type", type=click.Choice([t.value for t in UninstallerType], case_sensitive=False), help="Filter by uninstaller type.")
@click.option("--system/--no-system", default=False, help="Include Windows system components.")
@click.option("--protected/--no-protected", default=False, help="Include protected system applications.")
@click.option("--quiet-only/--all", default=False, help="Show only applications that support silent uninstallation.")
@click.option("--min-size", help="Minimum application size (e.g. 50MB, 1GB).")
@click.option("--sort", type=click.Choice(["name", "size", "publisher", "type"], case_sensitive=False), default="name", help="Sort order.")
@click.option("-n", "--limit", type=int, default=None, help="Limit number of results.")
@click.option("--json", "json_mode", is_flag=True, help="Output results in JSON format for AI agents.")
def list_apps(
    query: Optional[str],
    publisher: Optional[str],
    uninstaller_type: Optional[str],
    system: bool,
    protected: bool,
    quiet_only: bool,
    min_size: Optional[str],
    sort: str,
    limit: Optional[int],
    json_mode: bool,
):
    """List installed applications discovered across Registry, Store, Steam, and Package Managers."""
    mgr = ScannerManager()
    with console.status("[bold cyan]Scanning installed applications...", spinner="dots") if not json_mode else nullcontext():
        apps = mgr.scan_all()

    u_type = UninstallerType(uninstaller_type) if uninstaller_type else None
    criteria = FilterCriteria(
        query=query,
        publisher=publisher,
        uninstaller_type=u_type,
        include_system=system,
        include_protected=protected,
        has_quiet_only=quiet_only,
        min_size_bytes=parse_size_str(min_size),
    )
    filtered = ScannerManager.filter_entries(apps, criteria)

    # Sorting
    if sort == "name":
        filtered.sort(key=lambda a: a.display_name_trimmed.lower())
    elif sort == "size":
        filtered.sort(key=lambda a: a.estimated_size_bytes or 0, reverse=True)
    elif sort == "publisher":
        filtered.sort(key=lambda a: (a.publisher or "").lower())
    elif sort == "type":
        filtered.sort(key=lambda a: a.uninstaller_type.value)

    if limit is not None and limit > 0:
        filtered = filtered[:limit]

    if json_mode:
        click.echo(to_json_output(filtered))
    else:
        table = build_apps_table(filtered, title=f"Installed Applications ({len(filtered)} found)")
        console.print(table)


@main.command(name="search")
@click.argument("query")
@click.option("--regex", is_flag=True, help="Treat query as regular expression.")
@click.option("--system", is_flag=True, default=False, help="Include system components.")
@click.option("--json", "json_mode", is_flag=True, help="Output results in JSON format.")
def search_apps(query: str, regex: bool, system: bool, json_mode: bool):
    """Search for applications matching a keyword or regular expression."""
    mgr = ScannerManager()
    with console.status(f"[bold cyan]Searching applications for '{query}'...", spinner="dots") if not json_mode else nullcontext():
        apps = mgr.scan_all()

    criteria = FilterCriteria(query=query, regex_match=regex, include_system=system)
    results = ScannerManager.filter_entries(apps, criteria)

    if json_mode:
        click.echo(to_json_output(results))
    else:
        table = build_apps_table(results, title=f"Search Results for '{query}' ({len(results)} matches)")
        console.print(table)


@main.command(name="info")
@click.argument("target")
@click.option("--json", "json_mode", is_flag=True, help="Output detailed JSON metadata.")
def app_info(target: str, json_mode: bool):
    """Display comprehensive information about a specific application."""
    mgr = ScannerManager()
    apps = mgr.scan_all()

    matched = next((a for a in apps if a.id.lower() == target.lower()), None)
    if not matched:
        matches = [a for a in apps if target.lower() in a.display_name_trimmed.lower()]
        if len(matches) == 1:
            matched = matches[0]
        elif len(matches) > 1:
            if json_mode:
                click.echo(to_json_output({"error": "Ambiguous target", "matches": [a.id for a in matches]}))
            else:
                err_console.print(f"[bold red]Multiple applications matched '{target}'. Please specify the exact ID:[/bold red]")
                for m in matches:
                    err_console.print(f" - [bold white]{m.display_name}[/bold white] (ID: [cyan]{m.id}[/cyan])")
            sys.exit(1)

    if not matched:
        if json_mode:
            click.echo(to_json_output({"error": f"Application '{target}' not found"}))
        else:
            err_console.print(f"[bold red]No application found matching '{target}'.[/bold red]")
        sys.exit(1)

    if json_mode:
        click.echo(to_json_output(matched))
    else:
        console.print(f"\n[bold cyan]Application Details:[/bold cyan] [bold white]{escape_markup(matched.display_name)}[/bold white]")
        console.print(f" [bold]ID:[/bold]                   {escape_markup(matched.id)}")
        console.print(f" [bold]Version:[/bold]              {escape_markup(matched.display_version or 'N/A')}")
        console.print(f" [bold]Publisher:[/bold]            {escape_markup(matched.publisher or 'N/A')}")
        console.print(f" [bold]Uninstaller Type:[/bold]     {matched.uninstaller_type.value}")
        console.print(f" [bold]Install Location:[/bold]     {escape_markup(matched.install_location or 'N/A')}")
        console.print(f" [bold]Uninstall Command:[/bold]    {escape_markup(matched.uninstall_string or 'N/A')}")
        console.print(f" [bold]Quiet Command:[/bold]        {escape_markup(matched.quiet_uninstall_string or 'N/A')}")
        console.print(f" [bold]Quiet Supported:[/bold]      {'Yes' if matched.quiet_uninstall_possible else 'No'}")
        console.print(f" [bold]Registry Path:[/bold]        {escape_markup(matched.registry_path or 'N/A')}")
        console.print(f" [bold]Source Scanner:[/bold]       {matched.source_scanner}\n")


@main.command(name="scan-junk")
@click.argument("target", required=False)
@click.option("--orphans", is_flag=True, default=False, help="Scan system-wide verified orphaned leftovers from already-removed apps.")
@click.option("-c", "--min-confidence", type=click.Choice([l.value for l in ConfidenceLevel], case_sensitive=False), default=ConfidenceLevel.GOOD.value, help="Minimum confidence level threshold.")
@click.option("-d/-f", "--deep/--fast", default=True, help="Perform deep clean-slate scan (Services, Tasks, Firewall, Startup, AppPaths).")
@click.option("--json", "json_mode", is_flag=True, help="Output junk remnants in JSON.")
def scan_junk(target: Optional[str], orphans: bool, min_confidence: str, deep: bool, json_mode: bool):
    """Scan for orphaned leftovers across the system (default) or remnants for a removed application."""
    mgr = ScannerManager()
    apps = mgr.scan_all()
    conf_level = ConfidenceLevel.parse(min_confidence) or ConfidenceLevel.GOOD

    if orphans or not target:
        with console.status("[bold yellow]Scanning system for verified orphaned leftovers...", spinner="dots") if not json_mode else nullcontext():
            all_junk = JunkCleaner.scan_system_orphans(
                all_apps=apps,
                min_confidence=conf_level,
                deep_scan=deep,
            )
        title = f"Verified System Orphaned Leftovers ({len(all_junk)} items, Min Confidence: {conf_level.value})"
    else:
        active_matches = JunkCleaner.find_active_installed_matches(target, apps)
        if active_matches and not json_mode:
            names = ", ".join(escape_markup(a.display_name_trimmed) for a in active_matches[:3])
            err_console.print(
                f"[bold yellow]⚠ Warning:[/bold yellow] '{escape_markup(target)}' matches currently installed app(s): {names}.\n"
                f"  The items below include active application files. Use [bold]bcu uninstall[/bold] to remove safely."
            )
        found = [a for a in apps if target.lower() in a.display_name_trimmed.lower() or target.lower() == a.id.lower()]
        if not found:
            found = [ApplicationEntry(id=f"removed:{target.lower()}", display_name=target)]

        all_junk = []
        with console.status("[bold yellow]Scanning for leftover remnants...", spinner="dots") if not json_mode else nullcontext():
            for app in found:
                junk_items = JunkCleaner.scan_app_junk(
                    app,
                    all_apps=apps,
                    min_confidence=conf_level,
                    deep_scan=deep,
                )
                all_junk.extend(junk_items)
        title = f"Detected Remnants for '{target}' ({len(all_junk)} items, Min Confidence: {conf_level.value}, Deep: {deep})"

    if json_mode:
        click.echo(to_json_output(all_junk))
    else:
        table = build_junk_table(all_junk, title=title)
        console.print(table)


@main.command(name="uninstall")
@click.argument("targets", nargs=-1, required=True)
@click.option("-q/-l", "--quiet/--loud", default=True, help="Prefer silent/quiet uninstallation (default: True).")
@click.option("-y", "--yes", "--unattended", is_flag=True, help="Do not ask for interactive confirmation.")
@click.option("--dry-run", is_flag=True, help="Simulate uninstallation and junk cleanup without making changes.")
@click.option("--clean-junk/--no-clean-junk", default=True, help="Automatically clean leftover junk remnants after uninstall.")
@click.option("-d/-f", "--deep-junk/--fast-junk", default=True, help="Perform deep clean-slate scan (Services, Tasks, Firewall, Startup, AppPaths).")
@click.option("-k", "--kill-running", is_flag=True, default=False, help="Terminate blocking background processes before uninstallation.")
@click.option("--backup/--no-backup", default=True, help="Export automatic .reg backup before modifying registry.")
@click.option("--restore-point/--no-restore-point", default=False, help="Create a Windows System Restore Point before uninstallation.")
@click.option("-c", "--junk-confidence", type=click.Choice([l.value for l in ConfidenceLevel], case_sensitive=False), default=ConfidenceLevel.GOOD.value, help="Minimum confidence level for junk cleaner.")
@click.option("--timeout", type=int, default=DEFAULT_PROCESS_TIMEOUT_SEC, help="Timeout per uninstaller process in seconds.")
@click.option("--json", "json_mode", is_flag=True, help="Output JSON execution report for AI agents.")
def uninstall_apps(
    targets: tuple[str, ...],
    quiet: bool,
    yes: bool,
    dry_run: bool,
    clean_junk: bool,
    deep_junk: bool,
    kill_running: bool,
    backup: bool,
    restore_point: bool,
    junk_confidence: str,
    timeout: int,
    json_mode: bool,
):
    """Uninstall one or more applications with automatic quiet mode, process termination, and clean slate cleanup."""
    mgr = ScannerManager()
    all_apps = mgr.scan_all()
    target_apps: List[ApplicationEntry] = []
    seen_target_ids = set()

    import re as _re
    from bcu.junk.confidence import ConfidenceCalculator

    for t in targets:
        t_lower = t.strip().lower()
        t_clean = ConfidenceCalculator.clean_name(t)
        # Priority 1: Exact ID match
        matched = [a for a in all_apps if a.id.lower() == t_lower]
        # Priority 2: Exact display name or exact clean name match (so "Steam" never matches "MSTeams")
        if not matched:
            matched = [
                a
                for a in all_apps
                if a.display_name_trimmed.lower() == t_lower
                or (t_clean and ConfidenceCalculator.clean_name(a.display_name_trimmed) == t_clean)
            ]
        # Priority 3: Word-boundary match (prevents "steam" matching "msteams")
        if not matched and t_lower:
            wb_pat = _re.compile(r"(?:^|[\s\-_\.])" + _re.escape(t_lower) + r"(?:$|[\s\-_\.])", _re.IGNORECASE)
            matched = [a for a in all_apps if wb_pat.search(a.display_name_trimmed)]
        # Priority 4: Substring fallback only if unique
        if not matched and t_lower:
            sub = [a for a in all_apps if t_lower in a.display_name_trimmed.lower()]
            if len(sub) == 1:
                matched = sub
            elif len(sub) > 1:
                if json_mode:
                    click.echo(
                        to_json_output(
                            {
                                "error": f"Ambiguous target '{t}'. Specify exact ID.",
                                "matches": [{"id": m.id, "name": m.display_name_trimmed} for m in sub],
                            }
                        )
                    )
                else:
                    err_console.print(f"[bold red]Multiple apps matched '{escape_markup(t)}'. Please specify the exact ID:[/bold red]")
                    for m in sub:
                        err_console.print(f" - [bold white]{escape_markup(m.display_name_trimmed)}[/bold white] (ID: [cyan]{escape_markup(m.id)}[/cyan])")
                sys.exit(1)

        for m in matched:
            if m.id not in seen_target_ids:
                seen_target_ids.add(m.id)
                target_apps.append(m)

    if not target_apps:
        if json_mode:
            click.echo(to_json_output({"error": "No matching applications found for uninstallation"}))
        else:
            err_console.print("[bold red]No matching applications found to uninstall.[/bold red]")
        sys.exit(1)

    if not json_mode:
        console.print(f"\n[bold yellow]Target applications for uninstallation ({len(target_apps)}):[/bold yellow]")
        for app in target_apps:
            console.print(f" - [bold white]{escape_markup(app.display_name)}[/bold white] (Type: {app.uninstaller_type.value}, Silent: {app.quiet_uninstall_possible})")
        if dry_run:
            console.print("\n[bold magenta][DRY-RUN MODE ACTIVATED - NO CHANGES WILL BE MADE][/bold magenta]")

    if not yes and not dry_run and not json_mode:
        if not Confirm.ask("\nAre you sure you want to permanently uninstall these applications?"):
            console.print("[yellow]Uninstallation cancelled by user.[/yellow]")
            sys.exit(1223)

    conf_level = ConfidenceLevel.parse(junk_confidence) or ConfidenceLevel.GOOD
    queue = BatchUninstallQueue(
        apps=target_apps,
        prefer_quiet=quiet,
        dry_run=dry_run,
        clean_junk=clean_junk,
        deep_junk=deep_junk,
        kill_running=kill_running,
        backup_registry=backup,
        create_restore_point=restore_point,
        junk_min_confidence=conf_level,
        timeout_sec=timeout,
        all_apps=all_apps,
    )

    def on_start(app: ApplicationEntry, idx: int, total: int):
        if not json_mode:
            console.print(f"\n[bold cyan][{idx}/{total}] Uninstalling:[/bold cyan] [bold white]{escape_markup(app.display_name)}[/bold white]...")

    def on_finish(res, idx: int, total: int):
        if not json_mode:
            if res.status.value == "Completed":
                console.print(f"[bold green]✓ Completed:[/bold green] {escape_markup(res.app_name)} (Duration: {res.duration_sec:.1f}s, Cleaned Junk: {res.junk_cleaned_count})")
            else:
                console.print(f"[bold red]✗ Failed:[/bold red] {escape_markup(res.app_name)} (Error: {escape_markup(res.error_message or 'Unknown error')})")

    results = queue.run(on_app_start=on_start, on_app_finish=on_finish)

    if json_mode:
        click.echo(to_json_output(results))
    else:
        success_count = sum(1 for r in results if r.status.value == "Completed")
        console.print(f"\n[bold green]Batch finished: {success_count}/{len(results)} successful.[/bold green]\n")


@main.command(name="clean-junk")
@click.argument("targets", nargs=-1, required=False)
@click.option("--orphans", is_flag=True, default=False, help="Clean verified system-wide orphaned leftovers from already-removed apps.")
@click.option("-c", "--min-confidence", type=click.Choice([l.value for l in ConfidenceLevel], case_sensitive=False), default=ConfidenceLevel.GOOD.value, help="Minimum confidence level.")
@click.option("-d/-f", "--deep/--fast", default=True, help="Perform deep clean-slate scan (Services, Tasks, Firewall, Startup, AppPaths).")
@click.option("-k", "--kill-running", is_flag=True, default=False, help="Terminate blocking background processes before cleaning.")
@click.option("--backup/--no-backup", default=True, help="Export automatic .reg backup before deleting registry keys.")
@click.option("--force", is_flag=True, default=False, help="Allow cleaning remnants even if the target app appears to still be installed (DANGEROUS).")
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation prompt.")
@click.option("--dry-run", is_flag=True, help="Simulate deletion without making changes.")
@click.option("--json", "json_mode", is_flag=True, help="Output JSON results.")
def clean_app_junk(
    targets: tuple[str, ...],
    orphans: bool,
    min_confidence: str,
    deep: bool,
    kill_running: bool,
    backup: bool,
    force: bool,
    yes: bool,
    dry_run: bool,
    json_mode: bool,
):
    """Clean orphaned leftovers (--orphans) or remnants of previously removed apps. Protects active installed apps."""
    if not orphans and not targets:
        err_console.print("[bold red]Provide one or more removed app names, or pass --orphans to clean verified system leftovers.[/bold red]")
        sys.exit(2)

    mgr = ScannerManager()
    apps = mgr.scan_all()
    conf_level = ConfidenceLevel.parse(min_confidence) or ConfidenceLevel.GOOD

    junk_items: List = []
    if orphans:
        junk_items.extend(
            JunkCleaner.scan_system_orphans(
                all_apps=apps,
                min_confidence=conf_level,
                deep_scan=deep,
            )
        )

    for t in targets:
        active_matches = JunkCleaner.find_active_installed_matches(t, apps)
        if active_matches and not force:
            names = [a.display_name_trimmed for a in active_matches[:5]]
            err_msg = (
                f"Refusing to clean active files of currently installed app(s): {', '.join(names)}. "
                "Use 'bcu uninstall <target> --clean-junk' to uninstall safely, or pass --force to override."
            )
            if json_mode:
                click.echo(to_json_output({"error": err_msg, "installed_matches": names}))
            else:
                err_console.print(f"[bold red]⛔ BLOCKED:[/bold red] {escape_markup(err_msg)}")
            sys.exit(1)

        matched = [a for a in apps if t.lower() in a.display_name_trimmed.lower() or t.lower() == a.id.lower()]
        if not matched:
            matched = [ApplicationEntry(id=f"removed:{t.lower()}", display_name=t)]

        for m in matched:
            if kill_running and not dry_run:
                UninstallerExecutor.terminate_locking_processes(m)
            items = JunkCleaner.scan_app_junk(
                m,
                all_apps=apps,
                min_confidence=conf_level,
                deep_scan=deep,
            )
            junk_items.extend(items)

    if not junk_items:
        if json_mode:
            click.echo(to_json_output({"message": "No junk remnants found matching criteria"}))
        else:
            console.print("[green]No junk remnants found matching criteria.[/green]")
        return

    if not json_mode:
        table = build_junk_table(junk_items, title=f"Junk Items to Clean ({len(junk_items)} items, Deep: {deep})")
        console.print(table)

    if not yes and not dry_run and not json_mode:
        if not Confirm.ask("\nAre you sure you want to permanently delete these items?"):
            console.print("[yellow]Cleanup cancelled by user.[/yellow]")
            sys.exit(1223)

    clean_results = JunkCleaner.clean_junk(junk_items, dry_run=dry_run, backup_registry=backup)

    if json_mode:
        out = [
            {
                "path": item.path,
                "type": item.junk_type.value,
                "success": ok,
                "message": msg,
                "backup_file": item.backup_file_path,
            }
            for item, ok, msg in clean_results
        ]
        click.echo(to_json_output(out))
    else:
        successes = sum(1 for _, ok, _ in clean_results if ok)
        console.print(f"[bold green]Cleaned {successes}/{len(clean_results)} junk remnants.[/bold green]")


@main.command(name="export")
@click.argument("output_file", type=click.Path(writable=True))
@click.option("-f", "--format", "export_format", type=click.Choice(["json", "csv"], case_sensitive=False), default="json", help="Export format (json or csv).")
@click.option("-q", "--query", help="Filter applications to export.")
def export_apps(output_file: str, export_format: str, query: Optional[str]):
    """Export list of installed applications to a JSON or CSV file."""
    mgr = ScannerManager()
    with console.status("[bold cyan]Gathering application data...", spinner="dots"):
        apps = mgr.scan_all()

    if query:
        apps = ScannerManager.filter_entries(apps, FilterCriteria(query=query))

    if export_format.lower() == "csv":
        ApplicationSerializer.export_csv(apps, output_file)
    else:
        ApplicationSerializer.export_json(apps, output_file)

    console.print(f"[bold green]Successfully exported {len(apps)} applications to '{output_file}'[/bold green]")


@main.command(name="summary")
@click.option("--json", "json_mode", is_flag=True, help="Output inventory summary in JSON format.")
def system_summary(json_mode: bool):
    """Display a system software inventory summary (counts, uninstaller types, and largest apps)."""
    mgr = ScannerManager()
    with console.status("[bold cyan]Gathering system inventory summary...", spinner="dots") if not json_mode else nullcontext():
        apps = mgr.scan_all()

    large_apps = sorted(apps, key=lambda a: a.estimated_size_bytes or 0, reverse=True)[:10]
    uninstaller_breakdown = {}
    for a in apps:
        uninstaller_breakdown[a.uninstaller_type.value] = uninstaller_breakdown.get(a.uninstaller_type.value, 0) + 1

    summary = {
        "bcu_version": __version__,
        "platform": sys.platform,
        "backup_directory": str(get_backup_dir()),
        "total_installed_apps": len(apps),
        "quiet_uninstall_supported_apps": sum(1 for a in apps if a.quiet_uninstall_possible),
        "uninstaller_types_breakdown": uninstaller_breakdown,
        "top_10_largest_apps": [
            {
                "id": a.id,
                "name": a.display_name_trimmed,
                "size_bytes": a.estimated_size_bytes,
                "uninstaller_type": a.uninstaller_type.value,
                "quiet_possible": a.quiet_uninstall_possible,
            }
            for a in large_apps
        ],
    }

    if json_mode:
        click.echo(to_json_output(summary))
    else:
        from bcu.utils.formatting import format_size

        console.print(f"\n[bold cyan]BCU System Inventory Summary[/bold cyan] (v{__version__})")
        console.print(f" [bold]Total Installed Apps:[/bold] {summary['total_installed_apps']}")
        console.print(f" [bold]Quiet Uninstall Ready:[/bold] {summary['quiet_uninstall_supported_apps']}")
        console.print(f" [bold]Registry Backup Dir:[/bold]  {escape_markup(summary['backup_directory'])}")
        console.print("\n[bold yellow]Top Largest Applications:[/bold yellow]")
        for app in large_apps:
            console.print(
                f" - [bold white]{escape_markup(app.display_name_trimmed)}[/bold white] "
                f"[green]{format_size(app.estimated_size_bytes)}[/green] [dim]({app.uninstaller_type.value})[/dim]"
            )
        console.print()


@main.command(name="audit")
@click.argument("target", required=False)
@click.option("-s", "--min-severity", type=click.Choice([l.value for l in SeverityLevel if l != SeverityLevel.UNKNOWN], case_sensitive=False), default=SeverityLevel.LOW.value, help="Minimum vulnerability severity to report (Low, Medium, High, Critical).")
@click.option("--online/--no-online", default=True, help="Query live OSV.dev vulnerability feeds in addition to curated offline database.")
@click.option("--json", "json_mode", is_flag=True, help="Output results in JSON format for AI agents.")
def audit_vulns(target: Optional[str], min_severity: str, online: bool, json_mode: bool):
    """Audit installed applications against known CVEs and security advisories (like npm audit)."""
    mgr = ScannerManager()
    with console.status("[bold red]Auditing installed software for security vulnerabilities...", spinner="dots") if not json_mode else nullcontext():
        apps = mgr.scan_all()

    if target:
        apps = [a for a in apps if target.lower() in a.display_name_trimmed.lower() or target.lower() == a.id.lower()]
        if not apps:
            if json_mode:
                click.echo(to_json_output({"error": f"No application found matching '{target}'"}))
            else:
                err_console.print(f"[bold red]No application found matching '{target}'.[/bold red]")
            sys.exit(1)

    sev = SeverityLevel(min_severity.capitalize())
    report = VulnerabilityAuditor.audit_all(apps, min_severity=sev, online=online)

    if json_mode:
        click.echo(to_json_output(report))
    else:
        if not report.findings:
            console.print(f"\n[bold green]✓ Security Audit Passed![/bold green] No known vulnerabilities found across {report.total_scanned} scanned applications (Min Severity: {sev.value}).\n")
        else:
            table = build_vuln_table(report.findings, title=f"Vulnerability Audit Report ({report.total_vulnerabilities} vulnerabilities found across {report.vulnerable_apps_count} apps)")
            console.print("\n", table)
            console.print(f"\n[bold red]Vulnerability Summary:[/bold red] Critical: [bold red]{report.severity_breakdown.get('Critical', 0)}[/bold red] | High: [bold bright_red]{report.severity_breakdown.get('High', 0)}[/bold bright_red] | Medium: [bold yellow]{report.severity_breakdown.get('Medium', 0)}[/bold yellow] | Low: [bold cyan]{report.severity_breakdown.get('Low', 0)}[/bold cyan]\n")


@main.command(name="mcp")
def run_mcp_server():
    """Start the Model Context Protocol (MCP) stdio server for AI assistants."""
    from bcu.mcp_server import main as run_server
    run_server()


@main.command(name="tui")
def run_tui_app():
    """Launch the interactive Big-Tech tier Textual Terminal User Interface (TUI)."""
    from bcu.tui.app import main as run_app
    run_app()


@main.command(name="gui")
def run_gui_app():
    """Alias for 'bcu tui' - Launch the interactive Textual TUI interface."""
    from bcu.tui.app import main as run_app
    run_app()


if __name__ == "__main__":
    main()
