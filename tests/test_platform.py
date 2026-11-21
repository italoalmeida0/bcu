"""
Unit tests for platform utilities: Recycle Bin, Restore Points, and Authenticode signatures.
"""

from bcu.utils.platform import (
    create_system_restore_point,
    delete_path_permanent,
    delete_path_safe,
    delete_path_to_recycle_bin,
    normalize_path,
    verify_authenticode_signature,
)


def test_normalize_path():
    assert normalize_path(r'"C:\Program Files\App"') == "c:\\program files\\app"
    assert normalize_path(None) == ""
    assert normalize_path("   ") == ""


def test_delete_path_safe_nonexistent(tmp_path):
    non_existent = str(tmp_path / "does_not_exist.txt")
    ok, msg = delete_path_safe(non_existent)
    assert ok is True


def test_delete_path_permanent_file(tmp_path):
    test_file = tmp_path / "sample.txt"
    test_file.write_text("hello", encoding="utf-8")
    assert test_file.exists()

    ok, msg = delete_path_permanent(str(test_file))
    assert ok is True
    assert not test_file.exists()


def test_create_system_restore_point_mock(monkeypatch):
    monkeypatch.setattr(
        "bcu.utils.platform.run_powershell_command",
        lambda cmd, timeout_sec: (0, "Success", "")
    )
    ok, msg = create_system_restore_point("Test Restore Point")
    assert ok is True
    assert "Restore Point created" in msg


def test_verify_authenticode_signature_mock(monkeypatch, tmp_path):
    dummy_exe = tmp_path / "dummy.exe"
    dummy_exe.write_text("binary", encoding="utf-8")

    mock_json = '{"Status": "Valid", "Signer": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"}'
    monkeypatch.setattr(
        "bcu.utils.platform.run_powershell_command",
        lambda cmd, timeout_sec: (0, mock_json, "")
    )

    is_valid, signer = verify_authenticode_signature(str(dummy_exe))
    assert is_valid is True
    assert "Microsoft" in signer

    # Also verify PowerShell 5.1 integer enum Status == 0 ("Valid")
    mock_int_json = '{"Status": 0, "Signer": "CN=Microsoft Windows"}'
    monkeypatch.setattr(
        "bcu.utils.platform.run_powershell_command",
        lambda cmd, timeout_sec: (0, mock_int_json, ""),
    )
    is_valid2, signer2 = verify_authenticode_signature(str(dummy_exe))
    assert is_valid2 is True
    assert signer2 == "CN=Microsoft Windows"


def test_delete_path_permanent_readonly_file(tmp_path):
    import os
    import stat

    ro_dir = tmp_path / "ro_dir"
    ro_dir.mkdir()
    ro_file = ro_dir / "locked.txt"
    ro_file.write_text("readonly", encoding="utf-8")
    os.chmod(ro_file, stat.S_IREAD)

    ok, _ = delete_path_permanent(str(ro_dir))
    assert ok is True
    assert not ro_dir.exists()
