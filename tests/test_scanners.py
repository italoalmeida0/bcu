"""
Unit tests for scanner discovery and mock integration.
"""

from typing import List
from bcu.models import ApplicationEntry, UninstallerType
from bcu.scanners.base import BaseScanner
from bcu.scanners.manager import ScannerManager


class MockScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Mock"

    def is_available(self) -> bool:
        return True

    def scan(self) -> List[ApplicationEntry]:
        return [
            ApplicationEntry(
                id="mock:app1",
                display_name="Mock App One",
                publisher="Mock Publisher",
                uninstall_string="C:\\Mock\\uninstall.exe",
                source_scanner=self.name,
            ),
            ApplicationEntry(
                id="mock:app2",
                display_name="Mock App Two",
                publisher="Mock Publisher",
                uninstall_string="MsiExec.exe /X{11111111-2222-3333-4444-555555555555}",
                source_scanner=self.name,
            ),
        ]


def test_scanner_manager_with_mock():
    mgr = ScannerManager(scanners=[MockScanner()])
    apps = mgr.scan_all()
    assert len(apps) == 2

    app1 = next(a for a in apps if a.id == "mock:app1")
    assert app1.uninstaller_type in (UninstallerType.NSIS, UninstallerType.INNO_SETUP, UninstallerType.CUSTOM)

    app2 = next(a for a in apps if a.id == "mock:app2")
    assert app2.uninstaller_type == UninstallerType.MSIEXEC
    assert app2.quiet_uninstall_string is not None
    assert "/qn" in app2.quiet_uninstall_string


def test_windows_feature_scanner_mock(monkeypatch):
    from bcu.scanners.windows_feature import WindowsFeatureScanner
    scanner = WindowsFeatureScanner()

    mock_json = '[{"FeatureName": "TelnetClient", "State": "Enabled", "Description": "Telnet Client"}]'
    monkeypatch.setattr(
        "bcu.scanners.windows_feature.run_powershell_command",
        lambda cmd, timeout_sec: (0, mock_json, "")
    )
    monkeypatch.setattr(scanner, "is_available", lambda: True)

    apps = scanner.scan()
    assert len(apps) == 1
    assert apps[0].id == "feature:telnetclient"
    assert apps[0].uninstaller_type == UninstallerType.WINDOWS_FEATURE
    assert "dism.exe" in apps[0].quiet_uninstall_string


def test_windows_update_scanner_mock(monkeypatch):
    from bcu.scanners.win_update import WindowsUpdateScanner
    scanner = WindowsUpdateScanner()

    mock_json = '[{"HotFixID": "KB5034441", "Description": "Security Update", "InstalledOn": "2024-01-10", "InstalledBy": "NT AUTHORITY"}]'
    monkeypatch.setattr(
        "bcu.scanners.win_update.run_powershell_command",
        lambda cmd, timeout_sec: (0, mock_json, "")
    )
    monkeypatch.setattr(scanner, "is_available", lambda: True)

    apps = scanner.scan()
    assert len(apps) == 1
    assert apps[0].id == "update:kb5034441"
    assert apps[0].uninstaller_type == UninstallerType.WINDOWS_UPDATE
    assert apps[0].is_protected is True
    assert "wusa.exe" in apps[0].quiet_uninstall_string


def test_oculus_scanner_available(monkeypatch):
    from bcu.scanners.oculus import OculusScanner
    scanner = OculusScanner()
    monkeypatch.setattr(scanner, "is_available", lambda: False)
    assert scanner.scan() == []


def test_winget_parser_unbroken_separator_and_localization():
    from bcu.scanners.package_mgr import WingetScanner

    sample_stdout = (
        "   - \r   \\ \rNome                        Id                                      Versão      Disponível  Origem\n"
        "---------------------------------------------------------------------------------------------------\n"
        "Affinity                    Canva.Affinity                          3.2.3       3.3.3       winget\n"
        "Android Studio              ARP\\Machine\\Arm64\\Android Studio        2025.3\n"
        "AutoHotkey                  AutoHotkey.AutoHotkey                   2.0.26      2.0.32      winget\n"
        "AV1 Extension               MSIX\\Microsoft.AV1_1.0_arm64__abc       1.0\n"
    )
    apps = WingetScanner.parse_winget_output(sample_stdout)
    assert len(apps) == 2
    assert {a.id for a in apps} == {"winget:canva.affinity", "winget:autohotkey.autohotkey"}
    assert "--exact" in (apps[0].quiet_uninstall_string or "")


def test_windows_update_datetime_dict(monkeypatch):
    from bcu.scanners.win_update import WindowsUpdateScanner
    scanner = WindowsUpdateScanner()
    mock_json = '[{"HotFixID": "KB5099999", "Description": "Update", "InstalledOn": {"value": "/Date(1792537200000)/", "DateTime": "2026-10-21"}, "InstalledBy": "SYSTEM"}]'
    monkeypatch.setattr(
        "bcu.scanners.win_update.run_powershell_command",
        lambda cmd, timeout_sec: (0, mock_json, ""),
    )
    monkeypatch.setattr(scanner, "is_available", lambda: True)
    apps = scanner.scan()
    assert len(apps) == 1
    assert apps[0].install_date == "2026-10-21"


def test_scanner_manager_dedup_directory_and_unique_ids():
    mgr = ScannerManager(scanners=[])
    entries = [
        ApplicationEntry(
            id="reg:hklm:notepad++",
            display_name="Notepad++",
            install_location=r"C:\Program Files\Notepad++",
            source_scanner="Registry",
        ),
        ApplicationEntry(
            id="dir:notepad++",
            display_name="Notepad++ (Directory)",
            install_location=r"C:\Program Files\Notepad++",
            source_scanner="Directory",
        ),
        ApplicationEntry(
            id="reg:hklm:notepad++",
            display_name="Duplicate ID Entry",
            source_scanner="Registry",
        ),
    ]
    deduped = mgr._deduplicate_entries(entries)
    assert len(deduped) == 1
    assert deduped[0].id == "reg:hklm:notepad++"
