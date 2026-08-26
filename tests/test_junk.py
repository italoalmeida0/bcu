"""
Unit tests for junk remnants safety validation, clean slate finders, and cleaner logic.
"""

from bcu.junk.cleaner import JunkCleaner, export_registry_backup, get_backup_dir
from bcu.junk.finders import (
    AppPathsJunkFinder,
    FileSystemJunkFinder,
    FirewallRuleJunkFinder,
    RegistryJunkFinder,
    ScheduledTaskJunkFinder,
    ServiceJunkFinder,
    StartupJunkFinder,
    UserProfileDotfolderFinder,
)
from bcu.models import ApplicationEntry, ConfidenceLevel, JunkItem, JunkType


def test_prohibited_directories_safety():
    # Attempting to delete C:\Windows must be strictly rejected
    bad_dir_item = JunkItem(
        app_id="test:bad",
        app_name="Malicious App",
        junk_type=JunkType.DIRECTORY,
        path="C:\\Windows",
        confidence_level=ConfidenceLevel.VERY_GOOD,
    )
    is_safe, reason = JunkCleaner.is_safe_to_delete(bad_dir_item)
    assert is_safe is False
    assert "prohibited" in reason.lower()


def test_prohibited_system32_safety():
    # Attempting to delete C:\Windows\System32 must be strictly rejected
    bad_sys32 = JunkItem(
        app_id="test:bad",
        app_name="Malicious App",
        junk_type=JunkType.DIRECTORY,
        path="C:\\Windows\\System32",
        confidence_level=ConfidenceLevel.VERY_GOOD,
    )
    is_safe, reason = JunkCleaner.is_safe_to_delete(bad_sys32)
    assert is_safe is False


def test_prohibited_registry_key_safety():
    # Attempting to delete top-level Microsoft key must be strictly rejected
    bad_reg = JunkItem(
        app_id="test:bad",
        app_name="Malicious App",
        junk_type=JunkType.REGISTRY_KEY,
        path="HKLM\\SOFTWARE\\Microsoft",
        confidence_level=ConfidenceLevel.VERY_GOOD,
    )
    is_safe, reason = JunkCleaner.is_safe_to_delete(bad_reg)
    assert is_safe is False


def test_prohibited_service_safety():
    # Attempting to delete core Windows Service (e.g. RpcSs, WinDefend) must be rejected
    bad_svc = JunkItem(
        app_id="test:bad",
        app_name="Malicious App",
        junk_type=JunkType.SERVICE,
        path="WinDefend",
        confidence_level=ConfidenceLevel.VERY_GOOD,
    )
    is_safe, reason = JunkCleaner.is_safe_to_delete(bad_svc)
    assert is_safe is False
    assert "prohibited" in reason.lower()


def test_safe_junk_item():
    safe_item = JunkItem(
        app_id="test:safe",
        app_name="Old Vendor App",
        junk_type=JunkType.DIRECTORY,
        path="C:\\Users\\italo\\AppData\\Local\\OldVendorApp",
        confidence_level=ConfidenceLevel.VERY_GOOD,
    )
    is_safe, _ = JunkCleaner.is_safe_to_delete(safe_item)
    assert is_safe is True


def test_dry_run_junk_cleaning():
    safe_item = JunkItem(
        app_id="test:safe",
        app_name="Old Vendor App",
        junk_type=JunkType.DIRECTORY,
        path="C:\\Users\\italo\\AppData\\Local\\OldVendorApp",
        confidence_level=ConfidenceLevel.VERY_GOOD,
    )
    success, msg = JunkCleaner.delete_junk_item(safe_item, dry_run=True)
    assert success is True
    assert "[DRY-RUN]" in msg


def test_clean_slate_junk_types_safety():
    # Scheduled task
    task_item = JunkItem(
        app_id="test:task",
        app_name="Vendor App",
        junk_type=JunkType.SCHEDULED_TASK,
        path="\\VendorApp\\AutoUpdater",
        confidence_level=ConfidenceLevel.VERY_GOOD,
    )
    is_safe, _ = JunkCleaner.is_safe_to_delete(task_item)
    assert is_safe is True
    success, msg = JunkCleaner.delete_junk_item(task_item, dry_run=True)
    assert success is True
    assert "[DRY-RUN]" in msg

    # Service
    service_item = JunkItem(
        app_id="test:svc",
        app_name="Vendor App",
        junk_type=JunkType.SERVICE,
        path="VendorAppService",
        confidence_level=ConfidenceLevel.VERY_GOOD,
    )
    is_safe, _ = JunkCleaner.is_safe_to_delete(service_item)
    assert is_safe is True
    success, msg = JunkCleaner.delete_junk_item(service_item, dry_run=True)
    assert success is True
    assert "[DRY-RUN]" in msg


def test_backup_dir_creation():
    b_dir = get_backup_dir()
    assert b_dir.exists()


def test_advanced_junk_types_safety():
    # COM CLSID safety
    com_item = JunkItem(
        app_id="test:com",
        app_name="Test App",
        junk_type=JunkType.COM_CLSID,
        path="HKCU\\Software\\Classes\\CLSID\\{12345678-1234-1234-1234-123456789012}",
        confidence_level=ConfidenceLevel.VERY_GOOD,
    )
    is_safe, _ = JunkCleaner.is_safe_to_delete(com_item)
    assert is_safe is True
    success, msg = JunkCleaner.delete_junk_item(com_item, dry_run=True)
    assert success is True
    assert "[DRY-RUN]" in msg

    # Crash Dump safety
    dump_item = JunkItem(
        app_id="test:dump",
        app_name="Test App",
        junk_type=JunkType.CRASH_DUMP,
        path="C:\\Users\\italo\\AppData\\Local\\CrashDumps\\testapp.exe.1234.dmp",
        confidence_level=ConfidenceLevel.VERY_GOOD,
    )
    is_safe, _ = JunkCleaner.is_safe_to_delete(dump_item)
    assert is_safe is True
    success, msg = JunkCleaner.delete_junk_item(dump_item, dry_run=True)
    assert success is True
    assert "[DRY-RUN]" in msg

    # Prefetch safety
    pf_item = JunkItem(
        app_id="test:pf",
        app_name="Test App",
        junk_type=JunkType.PREFETCH,
        path="C:\\Windows\\Prefetch\\TESTAPP.EXE-12345678.pf",
        confidence_level=ConfidenceLevel.GOOD,
    )
    # Prefetch file inside Prefetch folder is safe to delete
    is_safe, _ = JunkCleaner.is_safe_to_delete(pf_item)
    assert is_safe is True
    success, msg = JunkCleaner.delete_junk_item(pf_item, dry_run=True)
    assert success is True
    assert "[DRY-RUN]" in msg

    # Audio Policy safety
    audio_item = JunkItem(
        app_id="test:audio",
        app_name="Test App",
        junk_type=JunkType.AUDIO_POLICY,
        path="HKCU\\Software\\Microsoft\\Internet Explorer\\LowRegistry\\Audio\\PolicyConfig\\PropertyStore\\12345",
        confidence_level=ConfidenceLevel.VERY_GOOD,
    )
    is_safe, _ = JunkCleaner.is_safe_to_delete(audio_item)
    assert is_safe is True
    success, msg = JunkCleaner.delete_junk_item(audio_item, dry_run=True)
    assert success is True
    assert "[DRY-RUN]" in msg
