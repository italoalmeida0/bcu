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
    assert "ai-helper" in result.output


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


def test_cli_ai_helper():
    runner = CliRunner()
    result = runner.invoke(main, ["ai-helper", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "total_installed_apps" in data
    assert "guidance_for_ai" in data


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
