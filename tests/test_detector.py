"""
Unit tests for uninstaller type detection and quiet string generation.
"""

from bcu.enrichers.detector import detect_uninstaller_type, enrich_app_uninstaller_type, extract_executable_path
from bcu.enrichers.quiet_args import generate_quiet_uninstall_string
from bcu.models import ApplicationEntry, UninstallerType


def test_detect_msi():
    cmd = "MsiExec.exe /X{12345678-ABCD-1234-ABCD-1234567890AB}"
    u_type = detect_uninstaller_type(cmd)
    assert u_type == UninstallerType.MSIEXEC


def test_detect_inno_setup():
    cmd = '"C:\\Program Files\\App\\unins000.exe"'
    u_type = detect_uninstaller_type(cmd)
    assert u_type == UninstallerType.INNO_SETUP


def test_detect_store_app():
    u_type = detect_uninstaller_type(raw_metadata={"IsStoreApp": True})
    assert u_type == UninstallerType.STORE_APP


def test_extract_unquoted_path_with_spaces():
    cmd = r"C:\Program Files (x86)\Steam\uninstall.exe /S"
    assert extract_executable_path(cmd) == r"C:\Program Files (x86)\Steam\uninstall.exe"
    cmd_no_args = r"C:\Program Files\Android\Android Studio1\uninstall.exe"
    assert extract_executable_path(cmd_no_args) == r"C:\Program Files\Android\Android Studio1\uninstall.exe"
    dll_path = r"C:\Program Files\Common Files\System\Ole DB\oledb32.dll"
    assert extract_executable_path(dll_path) == dll_path


def test_wix_burn_bundle_quiet_args():
    burn_cmd = r'"C:\ProgramData\Package Cache\{9527D1A5-8CB4-4BC5-9F25-1AA7418042FF}\Setup.exe" /uninstall'
    assert detect_uninstaller_type(burn_cmd) != UninstallerType.MSIEXEC
    app = ApplicationEntry(
        id="test:burn",
        display_name="Cyberduck",
        uninstall_string=burn_cmd,
        uninstaller_type=UninstallerType.CUSTOM,
    )
    quiet_cmd = generate_quiet_uninstall_string(app)
    assert quiet_cmd is not None
    assert "/uninstall /quiet /norestart" in quiet_cmd
    assert "msiexec" not in quiet_cmd.lower()


def test_powershell_quiet_not_double_wrapped():
    app = ApplicationEntry(
        id="test:ps",
        display_name="PS App",
        uninstall_string="powershell.exe -File C:\\app\\remove.ps1",
        uninstaller_type=UninstallerType.POWER_SHELL,
    )
    quiet_cmd = generate_quiet_uninstall_string(app)
    assert quiet_cmd == "powershell.exe -File C:\\app\\remove.ps1"


def test_generate_inno_quiet_string():
    app = ApplicationEntry(
        id="test:inno",
        display_name="Test Inno App",
        uninstall_string='"C:\\Program Files\\App\\unins000.exe"',
        uninstaller_type=UninstallerType.INNO_SETUP,
    )
    quiet_cmd = generate_quiet_uninstall_string(app)
    assert quiet_cmd is not None
    assert "/VERYSILENT" in quiet_cmd
    assert "/SUPPRESSMSGBOXES" in quiet_cmd
    assert "/NORESTART" in quiet_cmd


def test_generate_msi_quiet_string():
    app = ApplicationEntry(
        id="test:msi",
        display_name="Test MSI App",
        uninstall_string="MsiExec.exe /I{12345678-ABCD-1234-ABCD-1234567890AB}",
        uninstaller_type=UninstallerType.MSIEXEC,
    )
    quiet_cmd = generate_quiet_uninstall_string(app)
    assert quiet_cmd is not None
    assert "/qn" in quiet_cmd
    assert "{12345678-ABCD-1234-ABCD-1234567890AB}" in quiet_cmd
