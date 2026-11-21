"""
Unit tests for the CLI interface using Click's CliRunner.
"""

import json
from pathlib import Path
from click.testing import CliRunner
from bcu.cli import main


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "BCU-CLI" in result.output


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "list" in result.output
    assert "uninstall" in result.output
    assert "clean-junk" in result.output
    assert "summary" in result.output


def test_cli_list_json():
    runner = CliRunner()
    result = runner.invoke(main, ["list", "--json", "--limit", "3"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)


def test_cli_search_json():
    runner = CliRunner()
    result = runner.invoke(main, ["search", "Windows", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)


def test_cli_summary_json():
    runner = CliRunner()
    result = runner.invoke(main, ["summary", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "total_installed_apps" in data
    assert "uninstaller_types_breakdown" in data


def test_cli_export(tmp_path: Path):
    out_json = tmp_path / "apps.json"
    out_csv = tmp_path / "apps.csv"
    runner = CliRunner()

    res_json = runner.invoke(main, ["export", str(out_json), "--format", "json"])
    assert res_json.exit_code == 0
    assert out_json.exists()

    res_csv = runner.invoke(main, ["export", str(out_csv), "--format", "csv"])
    assert res_csv.exit_code == 0
    assert out_csv.exists()


def test_cli_uninstall_dry_run():
    runner = CliRunner()
    # Search for an installed app first to dry run
    list_res = runner.invoke(main, ["list", "--json", "--limit", "1"])
    apps = json.loads(list_res.output)
    if apps:
        app_id = apps[0]["id"]
        res = runner.invoke(main, ["uninstall", app_id, "--dry-run", "--json"])
        assert res.exit_code == 0
        data = json.loads(res.output)
        assert isinstance(data, list)
        assert data[0]["status"] == "Completed"


def test_cli_clean_junk_dry_run():
    runner = CliRunner()
    res = runner.invoke(main, ["clean-junk", "NonExistentApp", "--dry-run", "--json"])
    assert res.exit_code == 0


def test_cli_parse_size_str():
    from bcu.cli import parse_size_str

    assert parse_size_str("100B") == 100
    assert parse_size_str("2KB") == 2048
    assert parse_size_str("5MB") == 5 * 1024 * 1024
    assert parse_size_str("1.5GB") == int(1.5 * 1024 * 1024 * 1024)
    assert parse_size_str("1TB") == 1024 * 1024 * 1024 * 1024
    assert parse_size_str("invalid") is None


def test_cli_summary_human():
    runner = CliRunner()
    res = runner.invoke(main, ["summary"])
    assert res.exit_code == 0
    assert "Inventory Summary" in res.output


def test_cli_scan_orphans_json():
    runner = CliRunner()
    res = runner.invoke(main, ["scan-junk", "--orphans", "--fast", "--json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert isinstance(data, list)


def test_cli_clean_junk_blocks_installed_app():
    runner = CliRunner()
    list_res = runner.invoke(main, ["list", "--json", "--limit", "5"])
    apps = json.loads(list_res.output)
    # Pick a non-ghost active app (e.g. Scoop/StoreApp/Winget or live Registry app)
    active = next((a for a in apps if a.get("source_scanner") in ("StoreApp", "Scoop", "Winget")), None)
    if active:
        res = runner.invoke(main, ["clean-junk", active["id"], "--dry-run", "--json"])
        assert res.exit_code == 1
        data = json.loads(res.output)
        assert "error" in data
        assert "installed" in data["error"].lower()


def test_cli_uninstall_steam_does_not_match_msteams(monkeypatch):
    from bcu.models import ApplicationEntry, UninstallerType
    from bcu.scanners.manager import ScannerManager

    mock_apps = [
        ApplicationEntry(
            id="reg:hklm:steam",
            display_name="Steam",
            uninstall_string=r"C:\Program Files (x86)\Steam\uninstall.exe",
            uninstaller_type=UninstallerType.NSIS,
        ),
        ApplicationEntry(
            id="store:msteams",
            display_name="MSTeams (Store App)",
            uninstaller_type=UninstallerType.STORE_APP,
        ),
    ]
    monkeypatch.setattr(ScannerManager, "scan_all", lambda self, **kw: mock_apps)
    runner = CliRunner()
    res = runner.invoke(main, ["uninstall", "Steam", "--dry-run", "--json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert len(data) == 1
    assert data[0]["app_id"] == "reg:hklm:steam"
