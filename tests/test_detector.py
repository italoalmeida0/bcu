"""
Unit tests for uninstaller type detection and quiet string generation.
"""

from bcu.enrichers.detector import detect_uninstaller_type, enrich_app_uninstaller_type
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
