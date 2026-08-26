"""
Junk Cleaner orchestrates finding, backup creation, safety validation,
and removal of remnant items (including Services, Startup entries, Tasks, and Registry).
"""

from __future__ import annotations

import datetime
import os
import subprocess
from pathlib import Path
from typing import List, Optional, Set, Tuple
from bcu.config import PROHIBITED_DIRECTORIES, PROHIBITED_REGISTRY_KEYS, USE_RECYCLE_BIN
from bcu.junk.finders import (
    AppCompatJunkFinder,
    AppPathsJunkFinder,
    AudioPolicyJunkFinder,
    ComClsidJunkFinder,
    FileSystemJunkFinder,
    FirewallRuleJunkFinder,
    PrefetchJunkFinder,
    RegistryJunkFinder,
    ScheduledTaskJunkFinder,
    ServiceJunkFinder,
    ShortcutJunkFinder,
    StartupJunkFinder,
    UserProfileDotfolderFinder,
    WerCrashDumpJunkFinder,
)
from bcu.models import ApplicationEntry, ConfidenceLevel, JunkItem, JunkType
from bcu.utils.platform import IS_WINDOWS, RegistryHelper, delete_path_safe, normalize_path


def get_backup_dir() -> Path:
    """Returns local app data backup directory for registry rollbacks."""
    local_app_data = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    b_dir = Path(local_app_data) / "bcu" / "backups"
    b_dir.mkdir(parents=True, exist_ok=True)
    return b_dir


def export_registry_backup(reg_path: str, app_name: str) -> Optional[str]:
    """Exports a registry key to a .reg file before deletion for instant rollback."""
    if not IS_WINDOWS:
        return None

    try:
        clean_app = "".join(c if c.isalnum() else "_" for c in app_name)[:30]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = get_backup_dir() / f"reg_{clean_app}_{timestamp}.reg"

        cmd = ["reg.exe", "export", reg_path, str(backup_file), "/y"]
        subprocess.run(cmd, capture_output=True, timeout=10)
        if backup_file.exists() and backup_file.stat().st_size > 0:
            return str(backup_file)
    except Exception:
        pass
    return None


class JunkCleaner:
    """Finds and safely removes all junk leftovers (including Services, Tasks, and Registry)."""

    @classmethod
    def is_safe_to_delete(cls, item: JunkItem) -> Tuple[bool, str]:
        """Validates if a junk item is completely safe to delete."""
        path_str = item.path.strip()

        # 1. Check Filesystem & Directories (including Dumps and Prefetch)
        if item.junk_type in (JunkType.DIRECTORY, JunkType.FILE, JunkType.SHORTCUT, JunkType.CRASH_DUMP, JunkType.PREFETCH):
            norm = normalize_path(path_str)
            if not norm:
                return False, "Empty path"

            if norm in PROHIBITED_DIRECTORIES:
                return False, f"Prohibited protected system path: {path_str}"

            p = Path(path_str)
            if len(p.parts) <= 1 or p.parent == p:
                return False, f"Cannot delete root volume: {path_str}"

        # 2. Check Registry Keys / App Paths / COM CLSIDs / Audio Policy
        elif item.junk_type in (JunkType.REGISTRY_KEY, JunkType.APP_PATH, JunkType.COM_CLSID, JunkType.AUDIO_POLICY):
            hive_name, subpath = RegistryHelper.split_hive_and_subpath(path_str)
            if not hive_name or not subpath:
                return False, "Invalid registry path"

            subpath_parts = subpath.lower().split("\\")
            last_segment = subpath_parts[-1]
            if last_segment in PROHIBITED_REGISTRY_KEYS:
                return False, f"Prohibited protected registry key: {last_segment}"

            if len(subpath_parts) <= 1:
                return False, "Cannot delete top-level registry key"

        # 3. Check Windows Services
        elif item.junk_type == JunkType.SERVICE:
            if path_str.lower() in PROHIBITED_REGISTRY_KEYS or path_str.lower() in (
                "rpcss", "dcomlaunch", "eventlog", "lanmanworkstation", "lanmanserver", "wuauserv", "windefend"
            ):
                return False, f"Prohibited core Windows Service: {path_str}"

        return True, "Safe"

    @classmethod
    def scan_app_junk(
        cls,
        app: ApplicationEntry,
        all_apps: Optional[List[ApplicationEntry]] = None,
        min_confidence: ConfidenceLevel = ConfidenceLevel.GOOD,
        deep_scan: bool = True,
    ) -> List[JunkItem]:
        """
        Scans for all junk items belonging to the target application.
        If deep_scan is True, performs a clean-slate sweep across Services, Tasks, Firewall, Startup, AppPaths, COM, AppCompat, Dumps, Prefetch, and AudioPolicy.
        """
        all_apps = all_apps or []
        items: List[JunkItem] = []

        # Standard file system & registry remnants
        items.extend(FileSystemJunkFinder.find_junk(app, all_apps))
        items.extend(RegistryJunkFinder.find_junk(app, all_apps))
        items.extend(ShortcutJunkFinder.find_junk(app))

        # Deep Clean Slate Remnants
        if deep_scan:
            items.extend(StartupJunkFinder.find_junk(app))
            items.extend(ServiceJunkFinder.find_junk(app))
            items.extend(ScheduledTaskJunkFinder.find_junk(app))
            items.extend(FirewallRuleJunkFinder.find_junk(app))
            items.extend(AppPathsJunkFinder.find_junk(app))
            items.extend(UserProfileDotfolderFinder.find_junk(app))
            items.extend(ComClsidJunkFinder.find_junk(app))
            items.extend(AppCompatJunkFinder.find_junk(app))
            items.extend(WerCrashDumpJunkFinder.find_junk(app))
            items.extend(PrefetchJunkFinder.find_junk(app))
            items.extend(AudioPolicyJunkFinder.find_junk(app))

        # Deduplicate and filter by confidence & safety
        seen_paths: Set[str] = set()
        filtered: List[JunkItem] = []

        for item in items:
            key = f"{item.junk_type.value}:{item.path.lower()}"
            if key in seen_paths:
                continue
            seen_paths.add(key)

            if item.confidence_level >= min_confidence:
                is_safe, reason = cls.is_safe_to_delete(item)
                if is_safe:
                    filtered.append(item)

        return filtered

    @classmethod
    def delete_junk_item(
        cls,
        item: JunkItem,
        dry_run: bool = False,
        backup_registry: bool = True,
    ) -> Tuple[bool, str]:
        """Deletes an individual junk item with automatic safety checks and registry backup."""
        is_safe, reason = cls.is_safe_to_delete(item)
        if not is_safe:
            return False, reason

        if dry_run:
            return True, f"[DRY-RUN] Would delete {item.junk_type.value}: {item.path}"

        # 1. Filesystem Directory, File, Shortcut, Crash Dump, Prefetch
        if item.junk_type in (JunkType.DIRECTORY, JunkType.FILE, JunkType.SHORTCUT, JunkType.CRASH_DUMP, JunkType.PREFETCH):
            return delete_path_safe(item.path, use_recycle_bin=USE_RECYCLE_BIN)

        # 2. Registry Key, App Path, COM CLSID, Audio Policy
        elif item.junk_type in (JunkType.REGISTRY_KEY, JunkType.APP_PATH, JunkType.COM_CLSID, JunkType.AUDIO_POLICY):
            if backup_registry:
                item.backup_file_path = export_registry_backup(item.path, item.app_name)

            hive, subpath = RegistryHelper.split_hive_and_subpath(item.path)
            if hive is None:
                return False, "Invalid registry hive"
            success = RegistryHelper.delete_key_recursively(hive, subpath)
            msg = f"Deleted {item.junk_type.value} registry key"
            if item.backup_file_path:
                msg += f" (Backup: {item.backup_file_path})"
            return (True, msg) if success else (False, "Failed to delete registry key")

        # 3. Startup Entry or AppCompat Entry (Registry value or file)
        elif item.junk_type in (JunkType.STARTUP_ENTRY, JunkType.APP_COMPAT):
            if "\\" in item.path and (item.path.startswith("HKCU") or item.path.startswith("HKLM")):
                hive_name, full_subpath = item.path.split("\\", 1)
                subpath, val_name = full_subpath.rsplit("\\", 1)
                hive = RegistryHelper.HIVE_MAP.get(hive_name)
                if hive:
                    success = RegistryHelper.delete_value(hive, subpath, val_name)
                    return (True, f"Deleted registry value '{val_name}'") if success else (False, "Failed to delete registry value")
            else:
                return delete_path_safe(item.path, use_recycle_bin=USE_RECYCLE_BIN)

        # 4. Windows Service
        elif item.junk_type == JunkType.SERVICE:
            try:
                subprocess.run(["sc.exe", "stop", item.path], capture_output=True, timeout=5)
                proc = subprocess.run(["sc.exe", "delete", item.path], capture_output=True, timeout=5)
                if proc.returncode == 0:
                    return True, f"Unregistered Windows Service '{item.path}'"
                # Fallback to direct registry removal
                hive = RegistryHelper.HIVE_MAP.get("HKLM")
                if hive:
                    RegistryHelper.delete_key_recursively(hive, f"SYSTEM\\CurrentControlSet\\Services\\{item.path}")
                    return True, f"Deleted Service registry key '{item.path}'"
            except Exception as e:
                return False, f"Failed to delete service: {e}"

        # 5. Scheduled Task
        elif item.junk_type == JunkType.SCHEDULED_TASK:
            try:
                proc = subprocess.run(
                    ["schtasks.exe", "/Delete", "/TN", item.path, "/F"],
                    capture_output=True,
                    timeout=8,
                )
                if proc.returncode == 0:
                    return True, f"Deleted Scheduled Task '{item.path}'"
                return False, "Failed to delete scheduled task"
            except Exception as e:
                return False, f"Error deleting scheduled task: {e}"

        # 6. Firewall Rule
        elif item.junk_type == JunkType.FIREWALL_RULE:
            hive = RegistryHelper.HIVE_MAP.get("HKLM")
            if hive:
                fw_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
                success = RegistryHelper.delete_value(hive, fw_path, item.path)
                return (True, f"Removed Firewall Rule '{item.path}'") if success else (False, "Failed to remove firewall rule")

        return False, "Unsupported junk type"

    @classmethod
    def clean_junk(
        cls,
        items: List[JunkItem],
        dry_run: bool = False,
        backup_registry: bool = True,
    ) -> List[Tuple[JunkItem, bool, str]]:
        """Cleans a list of junk items and returns results."""
        results = []
        for item in items:
            success, msg = cls.delete_junk_item(item, dry_run=dry_run, backup_registry=backup_registry)
            results.append((item, success, msg))
        return results
