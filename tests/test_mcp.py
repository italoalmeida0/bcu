"""
Unit tests for BCU MCP (Model Context Protocol) Server tools.
"""

from bcu.mcp_server import (
    clean_application_junk,
    get_application_info,
    get_system_inventory_summary,
    list_applications,
    scan_application_junk,
    search_applications,
    uninstall_application,
)


def test_mcp_system_inventory_summary():
    summary = get_system_inventory_summary()
    assert "bcu_version" in summary
    assert "total_installed_apps" in summary
    assert "top_10_largest_apps" in summary
    assert isinstance(summary["top_10_largest_apps"], list)


def test_mcp_list_applications():
    apps = list_applications(limit=3)
    assert isinstance(apps, list)
    if apps:
        assert "display_name" in apps[0]
        assert "id" in apps[0]


def test_mcp_search_applications():
    apps = search_applications(query="Microsoft", include_system=True)
    assert isinstance(apps, list)


def test_mcp_get_application_info():
    apps = list_applications(limit=1)
    if apps:
        app_id = apps[0]["id"]
        info = get_application_info(target=app_id)
        assert "display_name" in info
        assert "uninstaller_type" in info


def test_mcp_scan_junk():
    apps = list_applications(limit=1)
    target = apps[0]["id"] if apps else "Notepad++"
    junk = scan_application_junk(target=target, min_confidence="Good", deep=True)
    assert isinstance(junk, list)


def test_mcp_uninstall_dry_run():
    apps = list_applications(limit=1)
    if apps:
        app_id = apps[0]["id"]
        result = uninstall_application(target=app_id, dry_run=True)
        assert result["status"] == "Completed"
        assert result["exit_code"] == 0


def test_mcp_clean_junk_dry_run():
    clean_res = clean_application_junk(target="TestNonExistentApp", dry_run=True)
    assert isinstance(clean_res, list)
