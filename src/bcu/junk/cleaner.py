"""
Junk Cleaner orchestrates finding, backup creation, safety validation,
and removal of remnant items (including Services, Startup entries, Tasks, and Registry).
"""

from __future__ import annotations

import datetime
import hashlib
import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional, Set, Tuple
from bcu.config import (
    PROHIBITED_DIRECTORIES,
    PROHIBITED_REGISTRY_KEYS,
    PROHIBITED_SUBTREE_PREFIXES,
    USE_RECYCLE_BIN,
)
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
from bcu.utils.platform import (
    IS_WINDOWS,
    SUBPROCESS_NO_WINDOW_FLAGS,
    RegistryHelper,
    delete_path_safe,
    normalize_path,
)


def get_backup_dir() -> Path:
    """Returns local app data backup directory for registry rollbacks."""
    local_app_data = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    b_dir = Path(local_app_data) / "bcu" / "backups"
    b_dir.mkdir(parents=True, exist_ok=True)
    return b_dir


def export_registry_backup(reg_path: str, app_name: str) -> Optional[str]:
    """Exports a registry key to a unique .reg file before deletion for instant rollback."""
    if not IS_WINDOWS:
        return None

    try:
        clean_app = "".join(c if c.isalnum() else "_" for c in app_name)[:30]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        key_hash = hashlib.sha1(reg_path.encode("utf-8", errors="ignore")).hexdigest()[:6]
        backup_file = get_backup_dir() / f"reg_{clean_app}_{timestamp}_{key_hash}.reg"

        cmd = ["reg.exe", "export", reg_path, str(backup_file), "/y"]
        subprocess.run(cmd, capture_output=True, timeout=10, creationflags=SUBPROCESS_NO_WINDOW_FLAGS)
        if backup_file.exists() and backup_file.stat().st_size > 0:
            return str(backup_file)
    except Exception:
        pass
    return None


def _split_registry_value_path(item_path: str) -> Tuple[Optional[int], str, str]:
    """
    Splits a registry value path like `HKCU\\SubKey\\ValueName` into (hive, subpath, value_name).
    Properly handles AppCompat / Startup values whose names are full Windows file paths containing backslashes.
    """
    known_prefixes = list(AppCompatJunkFinder.COMPAT_PATHS) + list(StartupJunkFinder.RUN_KEYS)
    normalized = item_path.replace("/", "\\")
    norm_lower = normalized.lower()

    for hive_name, known_subpath in known_prefixes:
        prefix = f"{hive_name}\\{known_subpath}\\".lower()
        if norm_lower.startswith(prefix):
            hive = RegistryHelper.HIVE_MAP.get(hive_name.upper())
            val_name = normalized[len(prefix):]
            return hive, known_subpath, val_name

    # Generic fallback for standard registry values without backslashes in value name
    hive, full_subpath = RegistryHelper.split_hive_and_subpath(normalized)
    if hive is None or "\\" not in full_subpath:
        return None, "", ""
    subpath, val_name = full_subpath.rsplit("\\", 1)
    return hive, subpath, val_name


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

            # Block anything inside core OS subtrees (System32, SysWOW64, WinSxS, etc.)
            for prefix in PROHIBITED_SUBTREE_PREFIXES:
                if norm == prefix or norm.startswith(prefix + "\\"):
                    return False, f"Prohibited protected OS subtree: {path_str}"

            # Block deleting arbitrary files inside Windows root unless it's a .pf Prefetch file
            win_root = normalize_path(os.environ.get("SystemRoot", "C:\\Windows"))
            if win_root and norm.startswith(win_root + "\\"):
                prefetch_prefix = os.path.join(win_root, "prefetch") + "\\"
                if not (item.junk_type == JunkType.PREFETCH and norm.startswith(prefetch_prefix) and norm.endswith(".pf")):
                    return False, f"Prohibited Windows directory path: {path_str}"

            p = Path(path_str)
            if len(p.parts) <= 1 or p.parent == p:
                return False, f"Cannot delete root volume: {path_str}"

        # 2. Check Registry Keys / App Paths / COM CLSIDs / Audio Policy
        elif item.junk_type in (JunkType.REGISTRY_KEY, JunkType.APP_PATH, JunkType.COM_CLSID, JunkType.AUDIO_POLICY):
            hive_name, subpath = RegistryHelper.split_hive_and_subpath(path_str)
            if not hive_name or not subpath:
                return False, "Invalid registry path"

            subpath_parts = [part for part in subpath.lower().split("\\") if part]
            if len(subpath_parts) <= 1:
                return False, "Cannot delete top-level registry key"

            last_segment = subpath_parts[-1]
            if last_segment in PROHIBITED_REGISTRY_KEYS:
                return False, f"Prohibited protected registry key: {last_segment}"

        # 3. Check Startup & AppCompat registry values / files
        elif item.junk_type in (JunkType.STARTUP_ENTRY, JunkType.APP_COMPAT):
            if path_str.upper().startswith(("HKCU\\", "HKLM\\", "HKEY_")):
                hive, subpath, val_name = _split_registry_value_path(path_str)
                if hive is None or not subpath or not val_name:
                    return False, f"Invalid registry value path: {path_str}"
            else:
                norm = normalize_path(path_str)
                if not norm or norm in PROHIBITED_DIRECTORIES:
                    return False, f"Prohibited protected startup path: {path_str}"

        # 4. Check Windows Services
        elif item.junk_type == JunkType.SERVICE:
            if path_str.lower() in PROHIBITED_REGISTRY_KEYS or path_str.lower() in (
                "rpcss", "dcomlaunch", "eventlog", "lanmanworkstation", "lanmanserver", "wuauserv", "windefend", "bfe", "mpssvc", "dhcp", "dnscache", "trustedinstaller"
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
    def scan_system_orphans(
        cls,
        all_apps: Optional[List[ApplicationEntry]] = None,
        min_confidence: ConfidenceLevel = ConfidenceLevel.GOOD,
        deep_scan: bool = True,
    ) -> List[JunkItem]:
        """
        Scans the system for verified orphaned leftovers from already-removed or broken software.
        Safe to run at any time without risking corruption of currently installed applications.
        """
        from bcu.junk.orphans import OrphanJunkScanner

        return OrphanJunkScanner.scan_system_orphans(
            all_apps=all_apps,
            min_confidence=min_confidence,
            deep_scan=deep_scan,
        )

    @classmethod
    def find_active_installed_matches(
        cls,
        target: str,
        all_apps: List[ApplicationEntry],
    ) -> List[ApplicationEntry]:
        """
        Returns currently installed (non-ghost) applications matching `target` by ID or clean name.
        Used to prevent accidental remnant deletion against active, healthy installations.
        """
        from bcu.junk.confidence import ConfidenceCalculator
        from bcu.junk.orphans import OrphanJunkScanner

        q_raw = target.strip().lower()
        q_clean = ConfidenceCalculator.clean_name(target)
        if not q_raw:
            return []

        ghost_items = OrphanJunkScanner.find_ghost_uninstall_keys(all_apps)
        ghost_ids = {item.app_id for item in ghost_items}
        ghost_clean_names = {
            ConfidenceCalculator.clean_name(app.display_name_trimmed)
            for app in all_apps
            if app.id in ghost_ids
        }
        live_registry_clean_names = {
            ConfidenceCalculator.clean_name(app.display_name_trimmed)
            for app in all_apps
            if app.source_scanner == "Registry" and app.id not in ghost_ids
        }

        active_matches: List[ApplicationEntry] = []
        for app in all_apps:
            if app.id in ghost_ids:
                continue
            app_name_low = app.display_name_trimmed.lower()
            app_clean = ConfidenceCalculator.clean_name(app.display_name_trimmed)
            # If a Winget entry only mirrors a Ghost Registry key with no healthy Registry entry, don't treat as active
            if app.source_scanner == "Winget" and app_clean in ghost_clean_names and app_clean not in live_registry_clean_names:
                continue
            if (
                app.id.lower() == q_raw
                or app_name_low == q_raw
                or (q_clean and app_clean == q_clean)
                or (len(q_clean) >= 4 and re.search(r"(?:^|[\s\-_])" + re.escape(q_clean) + r"(?:$|[\s\-_])", app_clean))
            ):
                active_matches.append(app)
        return active_matches

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
            if item.path.upper().startswith(("HKCU\\", "HKLM\\", "HKEY_")):
                hive, subpath, val_name = _split_registry_value_path(item.path)
                if hive is not None and subpath and val_name:
                    success = RegistryHelper.delete_value(hive, subpath, val_name)
                    return (
                        (True, f"Deleted registry value '{val_name}'")
                        if success
                        else (False, f"Failed to delete registry value '{val_name}'")
                    )
                return False, f"Could not parse registry value path: {item.path}"
            else:
                return delete_path_safe(item.path, use_recycle_bin=USE_RECYCLE_BIN)

        # 4. Windows Service
        elif item.junk_type == JunkType.SERVICE:
            try:
                subprocess.run(
                    ["sc.exe", "stop", item.path],
                    capture_output=True,
                    timeout=5,
                    creationflags=SUBPROCESS_NO_WINDOW_FLAGS,
                )
                proc = subprocess.run(
                    ["sc.exe", "delete", item.path],
                    capture_output=True,
                    timeout=5,
                    creationflags=SUBPROCESS_NO_WINDOW_FLAGS,
                )
                if proc.returncode == 0:
                    return True, f"Unregistered Windows Service '{item.path}'"
                # Fallback to direct registry removal (only report success if deletion actually succeeded!)
                hive = RegistryHelper.HIVE_MAP.get("HKLM")
                if hive:
                    svc_reg_path = f"SYSTEM\\CurrentControlSet\\Services\\{item.path}"
                    if backup_registry:
                        item.backup_file_path = export_registry_backup(f"HKLM\\{svc_reg_path}", item.app_name)
                    deleted = RegistryHelper.delete_key_recursively(hive, svc_reg_path)
                    if deleted:
                        return True, f"Deleted Service registry key '{item.path}'"
                return False, f"Failed to delete service '{item.path}' (Admin privileges may be required)"
            except Exception as e:
                return False, f"Failed to delete service: {e}"

        # 5. Scheduled Task
        elif item.junk_type == JunkType.SCHEDULED_TASK:
            try:
                proc = subprocess.run(
                    ["schtasks.exe", "/Delete", "/TN", item.path, "/F"],
                    capture_output=True,
                    timeout=8,
                    creationflags=SUBPROCESS_NO_WINDOW_FLAGS,
                )
                if proc.returncode == 0:
                    return True, f"Deleted Scheduled Task '{item.path}'"
                return False, "Failed to delete scheduled task (Admin privileges may be required)"
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
