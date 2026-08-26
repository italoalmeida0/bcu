"""
Junk remnant finders for Registry, File System, Shortcuts, Windows Services,
Startup items, Scheduled Tasks, Firewall Rules, and User Profile dotfolders.
"""

from __future__ import annotations

import csv
import io
import os
import subprocess
from pathlib import Path
from typing import List, Optional, Set
from bcu.config import PROHIBITED_DIRECTORIES, PROHIBITED_REGISTRY_KEYS
from bcu.junk.confidence import ConfidenceCalculator
from bcu.models import ApplicationEntry, ConfidenceLevel, JunkItem, JunkType
from bcu.utils.platform import IS_WINDOWS, RegistryHelper, normalize_path


class FileSystemJunkFinder:
    """Finds leftover files and directories in standard application locations."""

    @classmethod
    def get_search_locations(cls) -> List[Path]:
        locations: List[Path] = []
        env_vars = [
            "ProgramFiles",
            "ProgramFiles(x86)",
            "APPDATA",
            "LOCALAPPDATA",
            "ProgramData",
        ]
        for env_name in env_vars:
            val = os.environ.get(env_name)
            if val:
                p = Path(val)
                if p.exists() and p not in locations:
                    locations.append(p)

        # LocalLow under AppData
        user_prof = os.environ.get("USERPROFILE")
        if user_prof:
            locallow = Path(user_prof) / "AppData" / "LocalLow"
            if locallow.exists():
                locations.append(locallow)

        return locations

    @classmethod
    def find_junk(
        cls,
        target_app: ApplicationEntry,
        all_apps: Optional[List[ApplicationEntry]] = None,
    ) -> List[JunkItem]:
        all_apps = all_apps or []
        results: List[JunkItem] = []
        search_dirs = cls.get_search_locations()
        other_app_names = {
            a.display_name_trimmed.lower()
            for a in all_apps
            if a.id != target_app.id and a.display_name_trimmed
        }

        # 1. Target's own known install location (if it still exists after uninstall)
        if target_app.install_location:
            norm_loc = normalize_path(target_app.install_location)
            if (
                os.path.exists(target_app.install_location)
                and norm_loc not in PROHIBITED_DIRECTORIES
            ):
                item = JunkItem(
                    app_id=target_app.id,
                    app_name=target_app.display_name_trimmed,
                    junk_type=JunkType.DIRECTORY,
                    path=target_app.install_location,
                    confidence_level=ConfidenceLevel.VERY_GOOD,
                    raw_score=15,
                    reasons=["Target application original install directory remnant (+15)"],
                )
                results.append(item)

        # 2. Search common folders
        for base_dir in search_dirs:
            try:
                for entry in base_dir.iterdir():
                    if not entry.is_dir() or entry.name.startswith((".", "$")):
                        continue

                    norm_path = normalize_path(str(entry))
                    if norm_path in PROHIBITED_DIRECTORIES:
                        continue

                    # Direct folder check (depth 0)
                    folder_name = entry.name
                    is_used_by_other = folder_name.lower() in other_app_names
                    is_empty = False
                    has_execs = False

                    try:
                        children = list(entry.iterdir())
                        is_empty = len(children) == 0
                        has_execs = any(
                            c.is_file() and c.suffix.lower() in (".exe", ".dll") for c in children
                        )
                    except (PermissionError, OSError):
                        pass

                    level, score, reasons = ConfidenceCalculator.evaluate_confidence(
                        app=target_app,
                        item_name=folder_name,
                        item_parent_path=str(base_dir),
                        depth_level=0,
                        is_empty_dir=is_empty,
                        has_executables=has_execs,
                        is_still_used_by_other=is_used_by_other,
                    )

                    if level >= ConfidenceLevel.QUESTIONABLE:
                        results.append(
                            JunkItem(
                                app_id=target_app.id,
                                app_name=target_app.display_name_trimmed,
                                junk_type=JunkType.DIRECTORY,
                                path=str(entry),
                                confidence_level=level,
                                raw_score=score,
                                reasons=reasons,
                            )
                        )
                    elif not is_empty and not has_execs:
                        # Inspect subfolders (e.g. Publisher\AppName)
                        try:
                            for subentry in entry.iterdir():
                                if not subentry.is_dir():
                                    continue
                                sub_name = subentry.name
                                sub_level, sub_score, sub_reasons = (
                                    ConfidenceCalculator.evaluate_confidence(
                                        app=target_app,
                                        item_name=sub_name,
                                        item_parent_path=str(entry),
                                        depth_level=1,
                                        is_still_used_by_other=sub_name.lower() in other_app_names,
                                    )
                                )
                                if sub_level >= ConfidenceLevel.QUESTIONABLE:
                                    results.append(
                                        JunkItem(
                                            app_id=target_app.id,
                                            app_name=target_app.display_name_trimmed,
                                            junk_type=JunkType.DIRECTORY,
                                            path=str(subentry),
                                            confidence_level=sub_level,
                                            raw_score=sub_score,
                                            reasons=sub_reasons,
                                        )
                                    )
                        except (PermissionError, OSError):
                            pass

            except (PermissionError, OSError):
                continue

        return results


class RegistryJunkFinder:
    """Finds leftover registry keys in HKCU\\Software and HKLM\\Software."""

    REG_ROOTS = [
        ("HKCU", r"SOFTWARE"),
        ("HKLM", r"SOFTWARE"),
        ("HKCU", r"SOFTWARE\Wow6432Node"),
        ("HKLM", r"SOFTWARE\Wow6432Node"),
    ]

    @classmethod
    def find_junk(
        cls,
        target_app: ApplicationEntry,
        all_apps: Optional[List[ApplicationEntry]] = None,
    ) -> List[JunkItem]:
        if not IS_WINDOWS:
            return []

        all_apps = all_apps or []
        results: List[JunkItem] = []
        other_app_names = {
            a.display_name_trimmed.lower()
            for a in all_apps
            if a.id != target_app.id and a.display_name_trimmed
        }

        # 1. Uninstaller Registry key itself
        if target_app.registry_path:
            results.append(
                JunkItem(
                    app_id=target_app.id,
                    app_name=target_app.display_name_trimmed,
                    junk_type=JunkType.REGISTRY_KEY,
                    path=target_app.registry_path,
                    confidence_level=ConfidenceLevel.VERY_GOOD,
                    raw_score=20,
                    reasons=["Application uninstaller registration key (+20)"],
                )
            )

        # 2. Search Software keys
        for hive_name, subpath in cls.REG_ROOTS:
            hive = RegistryHelper.HIVE_MAP.get(hive_name)
            if not hive:
                continue

            subkeys = RegistryHelper.enum_subkeys(hive, subpath, view_64=True)
            for subkey in subkeys:
                if subkey.lower() in PROHIBITED_REGISTRY_KEYS:
                    continue

                level, score, reasons = ConfidenceCalculator.evaluate_confidence(
                    app=target_app,
                    item_name=subkey,
                    item_parent_path=subpath,
                    depth_level=0,
                    is_registry_key=True,
                    is_still_used_by_other=subkey.lower() in other_app_names,
                )

                if level >= ConfidenceLevel.QUESTIONABLE:
                    results.append(
                        JunkItem(
                            app_id=target_app.id,
                            app_name=target_app.display_name_trimmed,
                            junk_type=JunkType.REGISTRY_KEY,
                            path=f"{hive_name}\\{subpath}\\{subkey}",
                            confidence_level=level,
                            raw_score=score,
                            reasons=reasons,
                        )
                    )
                else:
                    # Check 1 level under publisher folder (e.g. HKCU\Software\Publisher\AppName)
                    pub_path = f"{subpath}\\{subkey}"
                    child_keys = RegistryHelper.enum_subkeys(hive, pub_path, view_64=True)
                    for child in child_keys:
                        sub_level, sub_score, sub_reasons = (
                            ConfidenceCalculator.evaluate_confidence(
                                app=target_app,
                                item_name=child,
                                item_parent_path=pub_path,
                                depth_level=1,
                                is_registry_key=True,
                                is_still_used_by_other=child.lower() in other_app_names,
                            )
                        )
                        if sub_level >= ConfidenceLevel.QUESTIONABLE:
                            results.append(
                                JunkItem(
                                    app_id=target_app.id,
                                    app_name=target_app.display_name_trimmed,
                                    junk_type=JunkType.REGISTRY_KEY,
                                    path=f"{hive_name}\\{pub_path}\\{child}",
                                    confidence_level=sub_level,
                                    raw_score=sub_score,
                                    reasons=sub_reasons,
                                )
                            )

        return results


class ShortcutJunkFinder:
    """Finds leftover shortcuts on Desktop and Start Menu."""

    @classmethod
    def get_shortcut_roots(cls) -> List[Path]:
        roots: List[Path] = []
        user_prof = os.environ.get("USERPROFILE")
        app_data = os.environ.get("APPDATA")
        prog_data = os.environ.get("ProgramData")

        if user_prof:
            desktop = Path(user_prof) / "Desktop"
            if desktop.exists():
                roots.append(desktop)

        if app_data:
            start_menu = Path(app_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
            if start_menu.exists():
                roots.append(start_menu)

        if prog_data:
            all_start_menu = Path(prog_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
            if all_start_menu.exists():
                roots.append(all_start_menu)

        return roots

    @classmethod
    def find_junk(cls, target_app: ApplicationEntry) -> List[JunkItem]:
        results: List[JunkItem] = []
        app_name = target_app.display_name_trimmed

        for root in cls.get_shortcut_roots():
            try:
                for file_path in root.glob("**/*.lnk"):
                    stem = file_path.stem
                    level, score, reasons = ConfidenceCalculator.evaluate_confidence(
                        app=target_app,
                        item_name=stem,
                        item_parent_path=str(file_path.parent),
                        depth_level=0,
                    )
                    if level >= ConfidenceLevel.QUESTIONABLE:
                        results.append(
                            JunkItem(
                                app_id=target_app.id,
                                app_name=app_name,
                                junk_type=JunkType.SHORTCUT,
                                path=str(file_path),
                                confidence_level=level,
                                raw_score=score,
                                reasons=reasons,
                            )
                        )
            except (PermissionError, OSError):
                continue

        return results


class StartupJunkFinder:
    """Finds leftover autostart entries in Run/RunOnce registry keys and Startup folders."""

    RUN_KEYS = [
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    @classmethod
    def find_junk(cls, target_app: ApplicationEntry) -> List[JunkItem]:
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        app_name = target_app.display_name_trimmed
        loc = target_app.install_location.lower() if target_app.install_location else None

        # 1. Registry Run Keys
        for hive_name, subpath in cls.RUN_KEYS:
            hive = RegistryHelper.HIVE_MAP.get(hive_name)
            if not hive:
                continue

            values = RegistryHelper.read_key_values(hive, subpath, view_64=True)
            for val_name, val_data in values.items():
                val_data_str = str(val_data).lower()

                # Check if value name or target executable path matches app
                match_val_name = ConfidenceCalculator.match_string_to_product(target_app, val_name)
                matched_by_path = loc and loc in val_data_str

                if match_val_name >= 0 or matched_by_path:
                    reasons = ["Startup Run entry matches application (+8)"]
                    if matched_by_path:
                        reasons.append("Command path points directly into install directory (+10)")
                    results.append(
                        JunkItem(
                            app_id=target_app.id,
                            app_name=app_name,
                            junk_type=JunkType.STARTUP_ENTRY,
                            path=f"{hive_name}\\{subpath}\\{val_name}",
                            confidence_level=ConfidenceLevel.VERY_GOOD,
                            raw_score=10 if matched_by_path else 8,
                            reasons=reasons,
                        )
                    )

        # 2. Startup Folders
        for env_name in ["APPDATA", "ProgramData"]:
            env_dir = os.environ.get(env_name)
            if env_dir:
                startup_dir = Path(env_dir) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
                if startup_dir.exists():
                    try:
                        for entry in startup_dir.iterdir():
                            if entry.is_file():
                                stem = entry.stem
                                match = ConfidenceCalculator.match_string_to_product(target_app, stem)
                                if match >= 0:
                                    results.append(
                                        JunkItem(
                                            app_id=target_app.id,
                                            app_name=app_name,
                                            junk_type=JunkType.STARTUP_ENTRY,
                                            path=str(entry),
                                            confidence_level=ConfidenceLevel.VERY_GOOD,
                                            raw_score=8,
                                            reasons=["Startup folder item matches application name (+8)"],
                                        )
                                    )
                    except (PermissionError, OSError):
                        pass

        return results


class ServiceJunkFinder:
    """Finds leftover Windows Services associated with the target application."""

    @classmethod
    def find_junk(cls, target_app: ApplicationEntry) -> List[JunkItem]:
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        app_name = target_app.display_name_trimmed
        loc = target_app.install_location.lower() if target_app.install_location else None

        hive = RegistryHelper.HIVE_MAP.get("HKLM")
        if not hive:
            return []

        services_path = r"SYSTEM\CurrentControlSet\Services"
        subkeys = RegistryHelper.enum_subkeys(hive, services_path, view_64=True)

        for service_key_name in subkeys:
            if service_key_name.lower() in PROHIBITED_REGISTRY_KEYS:
                continue

            full_service_path = f"{services_path}\\{service_key_name}"
            vals = RegistryHelper.read_key_values(hive, full_service_path, view_64=True)

            image_path = str(vals.get("ImagePath", "")).lower()
            display_name = str(vals.get("DisplayName", "")).strip()

            # Check if ImagePath points to application install location
            matched_by_image_path = bool(loc and loc in image_path)
            match_disp_name = (
                ConfidenceCalculator.match_string_to_product(target_app, display_name)
                if display_name
                else -1
            )
            match_key_name = ConfidenceCalculator.match_string_to_product(target_app, service_key_name)

            if matched_by_image_path or match_disp_name >= 0 or match_key_name >= 0:
                reasons = [f"Windows Service '{service_key_name}' matches application (+12)"]
                if matched_by_image_path:
                    reasons.append("Service ImagePath binary points to application directory (+15)")

                score = 15 if matched_by_image_path else 10
                results.append(
                    JunkItem(
                        app_id=target_app.id,
                        app_name=app_name,
                        junk_type=JunkType.SERVICE,
                        path=service_key_name,
                        confidence_level=ConfidenceLevel.VERY_GOOD,
                        raw_score=score,
                        reasons=reasons,
                    )
                )

        return results


class ScheduledTaskJunkFinder:
    """Finds leftover Windows Scheduled Tasks associated with the application."""

    @classmethod
    def find_junk(cls, target_app: ApplicationEntry) -> List[JunkItem]:
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        app_name = target_app.display_name_trimmed
        loc = target_app.install_location.lower() if target_app.install_location else None

        try:
            cmd = ["schtasks.exe", "/Query", "/FO", "CSV", "/V", "/NH"]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                encoding="utf-8",
                errors="replace",
            )
            if proc.returncode != 0 or not proc.stdout:
                return []

            reader = csv.reader(io.StringIO(proc.stdout))
            for row in reader:
                if len(row) < 9:
                    continue

                task_name = row[1].strip() if len(row) > 1 else ""
                task_to_run = row[8].strip().lower() if len(row) > 8 else ""

                # Ignore default Windows core tasks
                if task_name.startswith("\\Microsoft\\Windows\\"):
                    continue

                clean_task_name = task_name.lstrip("\\")
                matched_by_path = loc and loc in task_to_run
                match_name = ConfidenceCalculator.match_string_to_product(target_app, clean_task_name)

                if matched_by_path or match_name >= 0:
                    reasons = [f"Scheduled Task '{task_name}' matches application (+10)"]
                    if matched_by_path:
                        reasons.append("Task command executable is inside application directory (+12)")

                    score = 12 if matched_by_path else 9
                    results.append(
                        JunkItem(
                            app_id=target_app.id,
                            app_name=app_name,
                            junk_type=JunkType.SCHEDULED_TASK,
                            path=task_name,
                            confidence_level=ConfidenceLevel.VERY_GOOD,
                            raw_score=score,
                            reasons=reasons,
                        )
                    )
        except Exception:
            pass

        return results


class FirewallRuleJunkFinder:
    """Finds leftover Windows Defender Firewall rules created for the application."""

    @classmethod
    def find_junk(cls, target_app: ApplicationEntry) -> List[JunkItem]:
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        loc = target_app.install_location.lower() if target_app.install_location else None
        if not loc:
            return []

        hive = RegistryHelper.HIVE_MAP.get("HKLM")
        if not hive:
            return []

        fw_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        values = RegistryHelper.read_key_values(hive, fw_path, view_64=True)

        for rule_id, rule_data in values.items():
            rule_str = str(rule_data).lower()
            if loc in rule_str or f"|app={loc}" in rule_str:
                results.append(
                    JunkItem(
                        app_id=target_app.id,
                        app_name=target_app.display_name_trimmed,
                        junk_type=JunkType.FIREWALL_RULE,
                        path=rule_id,
                        confidence_level=ConfidenceLevel.VERY_GOOD,
                        raw_score=10,
                        reasons=["Firewall rule binary path points to application directory (+10)"],
                    )
                )

        return results


class AppPathsJunkFinder:
    """Finds leftover App Paths binary alias registry entries."""

    @classmethod
    def find_junk(cls, target_app: ApplicationEntry) -> List[JunkItem]:
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        app_name = target_app.display_name_trimmed
        loc = target_app.install_location.lower() if target_app.install_location else None

        for hive_name in ["HKLM", "HKCU"]:
            hive = RegistryHelper.HIVE_MAP.get(hive_name)
            if not hive:
                continue

            app_paths = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
            subkeys = RegistryHelper.enum_subkeys(hive, app_paths, view_64=True)

            for key in subkeys:
                full_path = f"{app_paths}\\{key}"
                vals = RegistryHelper.read_key_values(hive, full_path, view_64=True)
                default_val = str(vals.get("", "")).lower()

                matched_by_path = loc and loc in default_val
                match_name = ConfidenceCalculator.match_string_to_product(target_app, key.replace(".exe", ""))

                if matched_by_path or match_name >= 0:
                    results.append(
                        JunkItem(
                            app_id=target_app.id,
                            app_name=app_name,
                            junk_type=JunkType.APP_PATH,
                            path=f"{hive_name}\\{full_path}",
                            confidence_level=ConfidenceLevel.VERY_GOOD,
                            raw_score=10,
                            reasons=["App Paths registration matches application (+10)"],
                        )
                    )

        return results


class UserProfileDotfolderFinder:
    """Finds leftover dotfolders and root configuration dirs in %USERPROFILE%."""

    @classmethod
    def find_junk(cls, target_app: ApplicationEntry) -> List[JunkItem]:
        results: List[JunkItem] = []
        user_prof = os.environ.get("USERPROFILE")
        if not user_prof:
            return results

        p = Path(user_prof)
        if not p.exists():
            return results

        try:
            for item in p.iterdir():
                if item.is_dir() and item.name.startswith("."):
                    folder_name = item.name.lstrip(".")
                    match = ConfidenceCalculator.match_string_to_product(target_app, folder_name)
                    if match >= 0:
                        results.append(
                            JunkItem(
                                app_id=target_app.id,
                                app_name=target_app.display_name_trimmed,
                                junk_type=JunkType.DIRECTORY,
                                path=str(item),
                                confidence_level=ConfidenceLevel.VERY_GOOD if match <= 1 else ConfidenceLevel.GOOD,
                                raw_score=8,
                                reasons=[f"User profile configuration dotfolder '~/{item.name}' (+8)"],
                            )
                        )
        except (PermissionError, OSError):
            pass

        return results


class ComClsidJunkFinder:
    """Finds leftover COM CLSID and Typelib registrations in the registry."""

    CLSID_PATHS = [
        ("HKCU", r"Software\Classes\CLSID"),
        ("HKLM", r"SOFTWARE\Classes\CLSID"),
        ("HKLM", r"SOFTWARE\Classes\WOW6432Node\CLSID"),
    ]

    @classmethod
    def find_junk(cls, target_app: ApplicationEntry) -> List[JunkItem]:
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        loc = target_app.install_location.lower() if target_app.install_location else None
        if not loc or len(loc) < 4:
            return results

        app_name = target_app.display_name_trimmed

        for hive_name, subpath in cls.CLSID_PATHS:
            hive = RegistryHelper.HIVE_MAP.get(hive_name)
            if not hive:
                continue

            try:
                clsids = RegistryHelper.enum_subkeys(hive, subpath, view_64=True)
                for clsid in clsids:
                    for server_key in ["InprocServer32", "LocalServer32"]:
                        server_path = f"{subpath}\\{clsid}\\{server_key}"
                        vals = RegistryHelper.read_key_values(hive, server_path, view_64=True)
                        server_binary = str(vals.get("", "")).lower()

                        if loc in server_binary:
                            results.append(
                                JunkItem(
                                    app_id=target_app.id,
                                    app_name=app_name,
                                    junk_type=JunkType.COM_CLSID,
                                    path=f"{hive_name}\\{subpath}\\{clsid}",
                                    confidence_level=ConfidenceLevel.VERY_GOOD,
                                    raw_score=12,
                                    reasons=[f"COM {server_key} points to application install directory (+12)"],
                                )
                            )
                            break
            except Exception:
                continue

        return results


class AppCompatJunkFinder:
    """Finds leftover Application Compatibility Flags and Layer entries."""

    COMPAT_PATHS = [
        ("HKCU", r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"),
        ("HKCU", r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"),
    ]

    @classmethod
    def find_junk(cls, target_app: ApplicationEntry) -> List[JunkItem]:
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        loc = target_app.install_location.lower() if target_app.install_location else None
        if not loc or len(loc) < 4:
            return results

        app_name = target_app.display_name_trimmed

        for hive_name, subpath in cls.COMPAT_PATHS:
            hive = RegistryHelper.HIVE_MAP.get(hive_name)
            if not hive:
                continue

            vals = RegistryHelper.read_key_values(hive, subpath, view_64=True)
            for val_name in vals.keys():
                if loc in val_name.lower():
                    results.append(
                        JunkItem(
                            app_id=target_app.id,
                            app_name=app_name,
                            junk_type=JunkType.APP_COMPAT,
                            path=f"{hive_name}\\{subpath}\\{val_name}",
                            confidence_level=ConfidenceLevel.VERY_GOOD,
                            raw_score=10,
                            reasons=["AppCompat flag path points to application binary (+10)"],
                        )
                    )

        return results


class WerCrashDumpJunkFinder:
    """Finds leftover crash dumps and Windows Error Reporting logs for the application."""

    @classmethod
    def find_junk(cls, target_app: ApplicationEntry) -> List[JunkItem]:
        results: List[JunkItem] = []
        local_app = os.environ.get("LOCALAPPDATA")
        if not local_app:
            return results

        app_name = target_app.display_name_trimmed
        app_name_clean = "".join(c for c in app_name.lower() if c.isalnum())
        if len(app_name_clean) < 3:
            return results

        # 1. CrashDumps folder
        crash_dumps_dir = Path(local_app) / "CrashDumps"
        if crash_dumps_dir.exists():
            try:
                for dump_file in crash_dumps_dir.glob("*.dmp"):
                    stem_clean = "".join(c for c in dump_file.stem.lower() if c.isalnum())
                    if app_name_clean in stem_clean:
                        results.append(
                            JunkItem(
                                app_id=target_app.id,
                                app_name=app_name,
                                junk_type=JunkType.CRASH_DUMP,
                                path=str(dump_file),
                                confidence_level=ConfidenceLevel.VERY_GOOD,
                                raw_score=9,
                                reasons=["Application crash dump file (+9)"],
                            )
                        )
            except Exception:
                pass

        # 2. WER ReportArchive / ReportQueue
        for wer_sub in ["ReportArchive", "ReportQueue"]:
            wer_dir = Path(local_app) / "Microsoft" / "Windows" / "WER" / wer_sub
            if wer_dir.exists():
                try:
                    for report_folder in wer_dir.iterdir():
                        if report_folder.is_dir():
                            clean_folder = "".join(c for c in report_folder.name.lower() if c.isalnum())
                            if app_name_clean in clean_folder:
                                results.append(
                                    JunkItem(
                                        app_id=target_app.id,
                                        app_name=app_name,
                                        junk_type=JunkType.CRASH_DUMP,
                                        path=str(report_folder),
                                        confidence_level=ConfidenceLevel.VERY_GOOD,
                                        raw_score=8,
                                        reasons=["Windows Error Reporting log archive (+8)"],
                                    )
                                )
                except Exception:
                    pass

        return results


class PrefetchJunkFinder:
    """Finds leftover Windows Prefetch (.pf) entries."""

    @classmethod
    def find_junk(cls, target_app: ApplicationEntry) -> List[JunkItem]:
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        prefetch_dir = Path(os.environ.get("SystemRoot", "C:/Windows")) / "Prefetch"
        if not prefetch_dir.exists():
            return results

        app_name = target_app.display_name_trimmed
        app_name_clean = "".join(c for c in app_name.lower() if c.isalnum())
        if len(app_name_clean) < 3:
            return results

        try:
            for pf_file in prefetch_dir.glob("*.pf"):
                stem_clean = "".join(c for c in pf_file.stem.lower() if c.isalnum())
                if app_name_clean in stem_clean:
                    results.append(
                        JunkItem(
                            app_id=target_app.id,
                            app_name=app_name,
                            junk_type=JunkType.PREFETCH,
                            path=str(pf_file),
                            confidence_level=ConfidenceLevel.GOOD,
                            raw_score=7,
                            reasons=["Windows Prefetch cache file (+7)"],
                        )
                    )
        except Exception:
            pass

        return results


class AudioPolicyJunkFinder:
    """Finds leftover audio volume/endpoint registry policy configurations."""

    AUDIO_POLICY_PATH = r"Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore"

    @classmethod
    def find_junk(cls, target_app: ApplicationEntry) -> List[JunkItem]:
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        loc = target_app.install_location.lower() if target_app.install_location else None
        if not loc or len(loc) < 4:
            return results

        hive = RegistryHelper.HIVE_MAP.get("HKCU")
        if not hive:
            return []

        try:
            subkeys = RegistryHelper.enum_subkeys(hive, cls.AUDIO_POLICY_PATH, view_64=True)
            for subkey in subkeys:
                full_path = f"{cls.AUDIO_POLICY_PATH}\\{subkey}"
                vals = RegistryHelper.read_key_values(hive, full_path, view_64=True)
                for val_data in vals.values():
                    if loc in str(val_data).lower():
                        results.append(
                            JunkItem(
                                app_id=target_app.id,
                                app_name=target_app.display_name_trimmed,
                                junk_type=JunkType.AUDIO_POLICY,
                                path=f"HKCU\\{full_path}",
                                confidence_level=ConfidenceLevel.VERY_GOOD,
                                raw_score=9,
                                reasons=["Audio policy endpoint points to application binary (+9)"],
                            )
                        )
                        break
        except Exception:
            pass

        return results
