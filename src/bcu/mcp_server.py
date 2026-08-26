"""
Model Context Protocol (MCP) Server for BCU (Bulk Crap Uninstaller).
Exposes native tools for AI assistants to discover, inspect, safely uninstall,
and deep-clean application footprints.
"""

from __future__ import annotations

import json
import threading
from typing import Any, Dict, List, Optional
from mcp.server.fastmcp import FastMCP

from bcu import __version__
from bcu.engine.uninstaller import UninstallerExecutor
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

# Initialize FastMCP server
mcp = FastMCP(
    "BCU Uninstaller",
    instructions=(
        "Bulk Crap Uninstaller (BCU) MCP Server. "
        "Provides tools to list installed Windows software, inspect uninstallers, "
        "synthesize quiet commands, scan deep remnants (files, registry, services, tasks, startup), "
        "simulate dry-runs, and safely execute clean-slate uninstalls with auto .reg backups."
    ),
)

# Pre-warm scanner cache in background on server startup for instant tool response
def _prewarm_inventory():
    try:
        ScannerManager().scan_all()
    except Exception:
        pass

threading.Thread(target=_prewarm_inventory, daemon=True).start()


@mcp.tool()
def get_system_inventory_summary(force_refresh: bool = False) -> Dict[str, Any]:
    """
    Returns an executive inventory summary of installed software on the host system,
    including the top largest applications, uninstaller type breakdown, and backup directory.
    
    Args:
        force_refresh: Force a fresh rescan of system sources (default: False, uses fast memory cache).
    """
    mgr = ScannerManager()
    apps = mgr.scan_all(force_refresh=force_refresh)

    large_apps = sorted(apps, key=lambda a: a.estimated_size_bytes or 0, reverse=True)[:10]
    uninstaller_breakdown = {}
    for a in apps:
        uninstaller_breakdown[a.uninstaller_type.value] = uninstaller_breakdown.get(a.uninstaller_type.value, 0) + 1

    return {
        "bcu_version": __version__,
        "total_installed_apps": len(apps),
        "quiet_uninstall_supported_apps": sum(1 for a in apps if a.quiet_uninstall_possible),
        "backup_directory": str(get_backup_dir()),
        "uninstaller_types_breakdown": uninstaller_breakdown,
        "top_10_largest_apps": [
            {
                "id": a.id,
                "name": a.display_name_trimmed,
                "publisher": a.publisher_trimmed,
                "size_bytes": a.estimated_size_bytes,
                "uninstaller_type": a.uninstaller_type.value,
                "quiet_possible": a.quiet_uninstall_possible,
            }
            for a in large_apps
        ],
    }


@mcp.tool()
def list_applications(
    query: Optional[str] = None,
    publisher: Optional[str] = None,
    uninstaller_type: Optional[str] = None,
    min_size_mb: Optional[int] = None,
    include_system: bool = False,
    quiet_only: bool = False,
    limit: Optional[int] = 50,
    force_refresh: bool = False,
) -> List[Dict[str, Any]]:
    """
    Lists installed applications with filtering options (instant from memory cache).
    
    Args:
        query: Optional substring to search in name, id, or publisher.
        publisher: Optional filter for publisher name.
        uninstaller_type: Optional filter (e.g. Msiexec, InnoSetup, Nsis, StoreApp, Steam, Scoop, Chocolatey).
        min_size_mb: Optional minimum size filter in Megabytes.
        include_system: Whether to include Windows system components (default: False).
        quiet_only: Whether to list only applications supporting silent uninstallation.
        limit: Max number of applications to return (default: 50).
        force_refresh: Force a fresh rescan of system sources (default: False).
    """
    mgr = ScannerManager()
    apps = mgr.scan_all(force_refresh=force_refresh)

    u_type = None
    if uninstaller_type:
        try:
            u_type = UninstallerType(uninstaller_type)
        except ValueError:
            pass

    min_bytes = min_size_mb * 1024 * 1024 if min_size_mb is not None else None
    criteria = FilterCriteria(
        query=query,
        publisher=publisher,
        uninstaller_type=u_type,
        include_system=include_system,
        has_quiet_only=quiet_only,
        min_size_bytes=min_bytes,
    )
    filtered = ScannerManager.filter_entries(apps, criteria)
    if limit is not None and limit > 0:
        filtered = filtered[:limit]

    return [app.model_dump() for app in filtered]


@mcp.tool()
def search_applications(
    query: str,
    regex: bool = False,
    include_system: bool = False,
    force_refresh: bool = False,
) -> List[Dict[str, Any]]:
    """
    Searches for applications matching a query keyword or regex (instant from memory cache).
    
    Args:
        query: Search string or regular expression.
        regex: Treat query as a regex pattern.
        include_system: Include system components in results.
        force_refresh: Force a fresh rescan of system sources (default: False).
    """
    mgr = ScannerManager()
    apps = mgr.scan_all(force_refresh=force_refresh)
    criteria = FilterCriteria(query=query, regex_match=regex, include_system=include_system)
    results = ScannerManager.filter_entries(apps, criteria)
    return [app.model_dump() for app in results]


@mcp.tool()
def get_application_info(target: str, force_refresh: bool = False) -> Dict[str, Any]:
    """
    Retrieves detailed metadata for a specific application by its ID or name.
    
    Args:
        target: Application ID or display name.
        force_refresh: Force a fresh rescan of system sources (default: False).
    """
    mgr = ScannerManager()
    apps = mgr.scan_all(force_refresh=force_refresh)

    matched = next((a for a in apps if a.id.lower() == target.lower()), None)
    if not matched:
        matches = [a for a in apps if target.lower() in a.display_name_trimmed.lower()]
        if len(matches) == 1:
            matched = matches[0]
        elif len(matches) > 1:
            return {
                "error": "Ambiguous target",
                "matching_candidates": [{"id": m.id, "name": m.display_name} for m in matches],
            }

    if not matched:
        return {"error": f"Application '{target}' not found"}

    return matched.model_dump()


@mcp.tool()
def scan_application_junk(
    target: Optional[str] = None,
    min_confidence: str = "Good",
    deep: bool = True,
    force_refresh: bool = False,
) -> List[Dict[str, Any]]:
    """
    Performs a deep remnant scan for leftover files, registry keys, Windows services,
    scheduled tasks, startup items, firewall rules, and dotfolders (instant from memory cache).
    
    Args:
        target: Optional target app ID or name (scans all apps if omitted).
        min_confidence: Minimum confidence threshold ('VeryGood', 'Good', 'Questionable', 'Bad').
        deep: Perform clean-slate scan (includes services, tasks, firewall, startup).
        force_refresh: Force a fresh rescan of system sources (default: False).
    """
    mgr = ScannerManager()
    apps = mgr.scan_all(force_refresh=force_refresh)
    target_apps: List[ApplicationEntry] = []

    if target:
        found = [a for a in apps if target.lower() in a.display_name_trimmed.lower() or target.lower() == a.id.lower()]
        if not found:
            found = [ApplicationEntry(id=f"custom:{target}", display_name=target)]
        target_apps = found
    else:
        target_apps = apps

    try:
        conf_level = ConfidenceLevel(min_confidence)
    except ValueError:
        conf_level = ConfidenceLevel.GOOD

    all_junk = []
    for app in target_apps:
        items = JunkCleaner.scan_app_junk(
            app,
            all_apps=apps,
            min_confidence=conf_level,
            deep_scan=deep,
        )
        all_junk.extend(items)

    return [item.model_dump() for item in all_junk]


@mcp.tool()
def uninstall_application(
    target: str,
    dry_run: bool = True,
    prefer_quiet: bool = True,
    clean_junk: bool = True,
    deep_junk: bool = True,
    kill_running: bool = True,
    backup_registry: bool = True,
    create_restore_point: bool = False,
    junk_min_confidence: str = "Good",
) -> Dict[str, Any]:
    """
    Uninstalls an application with quiet execution, process lock termination, and clean-slate cleanup.
    Defaults to dry_run=True for safety.
    
    Args:
        target: Application ID or display name.
        dry_run: If True, simulates uninstallation without making changes (default: True).
        prefer_quiet: Use silent uninstallation flags (default: True).
        clean_junk: Clean leftover remnants after uninstall (default: True).
        deep_junk: Perform deep clean-slate cleanup of services, tasks, and startup entries (default: True).
        kill_running: Terminate blocking processes before uninstallation (default: True).
        backup_registry: Export .reg backup before deleting registry keys (default: True).
        create_restore_point: Create a Windows System Restore Point before uninstallation (default: False).
        junk_min_confidence: Confidence threshold ('VeryGood', 'Good', 'Questionable').
    """
    mgr = ScannerManager()
    apps = mgr.scan_all()

    matched = next((a for a in apps if a.id.lower() == target.lower()), None)
    if not matched:
        matches = [a for a in apps if target.lower() in a.display_name_trimmed.lower()]
        if len(matches) == 1:
            matched = matches[0]
        elif len(matches) > 1:
            return {
                "error": "Ambiguous target",
                "matching_candidates": [{"id": m.id, "name": m.display_name} for m in matches],
            }

    if not matched:
        return {"error": f"Application '{target}' not found"}

    if create_restore_point and not dry_run:
        from bcu.utils.platform import create_system_restore_point
        create_system_restore_point(f"BCU Uninstall: {matched.display_name}")

    try:
        conf_level = ConfidenceLevel(junk_min_confidence)
    except ValueError:
        conf_level = ConfidenceLevel.GOOD

    result = UninstallerExecutor.execute_uninstall(
        app=matched,
        prefer_quiet=prefer_quiet,
        dry_run=dry_run,
        clean_junk=clean_junk,
        deep_junk=deep_junk,
        backup_registry=backup_registry,
        kill_running=kill_running,
        junk_min_confidence=conf_level,
    )

    if not dry_run:
        ScannerManager.invalidate_cache()

    return result.model_dump()


@mcp.tool()
def clean_application_junk(
    target: str,
    min_confidence: str = "Good",
    deep: bool = True,
    kill_running: bool = True,
    backup_registry: bool = True,
    dry_run: bool = True,
) -> List[Dict[str, Any]]:
    """
    Cleans remnant files, registry keys, services, and tasks for an application that was already removed.
    Defaults to dry_run=True for safety.
    
    Args:
        target: Application name or ID.
        min_confidence: Minimum confidence threshold ('VeryGood', 'Good', 'Questionable').
        deep: Perform deep clean-slate scan (includes services, tasks, firewall, startup).
        kill_running: Terminate blocking processes before cleaning (default: True).
        backup_registry: Export .reg backup before deleting registry keys (default: True).
        dry_run: If True, simulates deletion without modifying the system (default: True).
    """
    mgr = ScannerManager()
    apps = mgr.scan_all()

    matched = [a for a in apps if target.lower() in a.display_name_trimmed.lower() or target.lower() == a.id.lower()]
    if not matched:
        matched = [ApplicationEntry(id=f"custom:{target}", display_name=target)]

    try:
        conf_level = ConfidenceLevel(min_confidence)
    except ValueError:
        conf_level = ConfidenceLevel.GOOD

    junk_items = []
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

    clean_results = JunkCleaner.clean_junk(junk_items, dry_run=dry_run, backup_registry=backup_registry)

    if not dry_run:
        ScannerManager.invalidate_cache()

    return [
        {
            "path": item.path,
            "type": item.junk_type.value,
            "confidence": item.confidence_level.value,
            "success": ok,
            "message": msg,
            "backup_file": item.backup_file_path,
        }
        for item, ok, msg in clean_results
    ]


@mcp.tool()
def audit_vulnerabilities(
    target: Optional[str] = None,
    min_severity: str = "Low",
    online: bool = False,
    force_refresh: bool = False,
) -> Dict[str, Any]:
    """
    Audits installed applications against known CVEs and security advisories (like npm audit).
    Fast and instant using curated zero-latency CVE database (or optional live OSV feeds).
    
    Args:
        target: Optional specific application name or ID to audit (audits all apps if omitted).
        min_severity: Minimum severity threshold ('Critical', 'High', 'Medium', 'Low').
        online: Query live OSV.dev vulnerability feeds in addition to curated offline database (default: False for instant response).
        force_refresh: Force a fresh rescan of system sources (default: False).
    """
    mgr = ScannerManager()
    apps = mgr.scan_all(force_refresh=force_refresh)

    if target:
        apps = [a for a in apps if target.lower() in a.display_name_trimmed.lower() or target.lower() == a.id.lower()]
        if not apps:
            return {"error": f"No application found matching '{target}'"}

    try:
        sev = SeverityLevel(min_severity.capitalize())
    except ValueError:
        sev = SeverityLevel.LOW

    report = VulnerabilityAuditor.audit_all(apps, min_severity=sev, online=online)
    return report.model_dump()


def main():
    """Main entrypoint for running the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
