"""
Unit tests for the Vulnerability and Security Audit engine.
"""

from click.testing import CliRunner
from bcu.cli import main
from bcu.models import ApplicationEntry, SeverityLevel
from bcu.security.auditor import VulnerabilityAuditor
from bcu.security.version_matcher import (
    compare_versions,
    match_version_constraint,
    parse_version_tuple,
)


def test_parse_version_tuple():
    assert parse_version_tuple("6.23") == (6, 23)
    assert parse_version_tuple("v23.01") == (23, 1)
    assert parse_version_tuple("8.5.7.1") == (8, 5, 7, 1)
    assert parse_version_tuple("2.45.1.windows.1") == (2, 45, 1, 1)
    assert parse_version_tuple("") is None
    assert parse_version_tuple(None) is None


def test_compare_versions():
    assert compare_versions("6.20", "6.23") == -1
    assert compare_versions("6.23", "6.23") == 0
    assert compare_versions("6.24", "6.23") == 1
    assert compare_versions("23.01", "22.00") == 1
    assert compare_versions("0.80", "0.81") == -1


def test_match_version_constraint():
    assert match_version_constraint("6.20", "< 6.23") is True
    assert match_version_constraint("6.23", "< 6.23") is False
    assert match_version_constraint("6.24", "< 6.23") is False

    assert match_version_constraint("0.75", ">= 0.68, < 0.81") is True
    assert match_version_constraint("0.65", ">= 0.68, < 0.81") is False
    assert match_version_constraint("0.81", ">= 0.68, < 0.81") is False


def test_vulnerability_audit_vulnerable_app():
    vulnerable_winrar = ApplicationEntry(
        id="reg:hklm:winrar",
        display_name="WinRAR 6.20 (64-bit)",
        display_version="6.20.0",
        publisher="win.rar GmbH",
    )

    findings = VulnerabilityAuditor.audit_app(vulnerable_winrar, min_severity=SeverityLevel.LOW, online=False)
    assert len(findings) >= 2
    cve_ids = [f.id for f in findings]
    assert "CVE-2023-38831" in cve_ids
    assert "CVE-2023-40477" in cve_ids
    assert any(f.severity == SeverityLevel.CRITICAL for f in findings)


def test_vulnerability_audit_patched_app():
    patched_winrar = ApplicationEntry(
        id="reg:hklm:winrar",
        display_name="WinRAR 6.24 (64-bit)",
        display_version="6.24.0",
        publisher="win.rar GmbH",
    )

    findings = VulnerabilityAuditor.audit_app(patched_winrar, min_severity=SeverityLevel.LOW, online=False)
    assert len(findings) == 0


def test_vulnerability_audit_putty_and_7zip():
    putty_vuln = ApplicationEntry(
        id="reg:hklm:putty",
        display_name="PuTTY release 0.80",
        display_version="0.80",
        publisher="Simon Tatham",
    )
    findings = VulnerabilityAuditor.audit_app(putty_vuln, min_severity=SeverityLevel.HIGH, online=False)
    assert len(findings) == 1
    assert findings[0].id == "CVE-2024-31497"
    assert findings[0].fixed_version == "0.81"

    zip_vuln = ApplicationEntry(
        id="reg:hklm:7zip",
        display_name="7-Zip 22.01 (x64)",
        display_version="22.01",
        publisher="Igor Pavlov",
    )
    findings_zip = VulnerabilityAuditor.audit_app(zip_vuln, min_severity=SeverityLevel.HIGH, online=False)
    assert len(findings_zip) >= 1
    assert any(f.id == "CVE-2023-31102" for f in findings_zip)


def test_vulnerability_audit_all_summary():
    apps = [
        ApplicationEntry(id="app:1", display_name="WinRAR", display_version="6.20"),
        ApplicationEntry(id="app:2", display_name="Notepad++", display_version="8.5.6"),
        ApplicationEntry(id="app:3", display_name="CleanApp", display_version="1.0.0"),
    ]
    report = VulnerabilityAuditor.audit_all(apps, min_severity=SeverityLevel.LOW, online=False)
    assert report.total_scanned == 3
    assert report.vulnerable_apps_count == 2
    assert report.total_vulnerabilities >= 3
    assert report.severity_breakdown.get("Critical", 0) >= 1


def test_cli_audit_command():
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "--json", "--no-online"])
    assert result.exit_code == 0
    assert "total_scanned" in result.output
