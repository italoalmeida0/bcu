"""
System-wide Orphaned Leftovers Scanner (BCU / Revo Uninstaller style).
Detects ONLY proven broken/orphaned remnants whose target executables or directories
no longer exist on disk — guaranteeing zero risk of corrupting active installed software.
"""

from __future__ import annotations

import os
import re
import struct
from pathlib import Path
from typing import List, Optional, Set
from bcu.config import PROHIBITED_DIRECTORIES, PROHIBITED_REGISTRY_KEYS, PROHIBITED_SUBTREE_PREFIXES
from bcu.enrichers.detector import extract_executable_path
from bcu.junk.finders import AppCompatJunkFinder, ComClsidJunkFinder, StartupJunkFinder
from bcu.models import ApplicationEntry, ConfidenceLevel, JunkItem, JunkType
from bcu.utils.platform import IS_WINDOWS, RegistryHelper, normalize_path

_WINDOWS_GENERIC_EXECUTABLES = {
    "msiexec.exe",
    "rundll32.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wusa.exe",
    "dism.exe",
    "svchost.exe",
    "explorer.exe",
    "conhost.exe",
    "regsvr32.exe",
    "wscript.exe",
    "cscript.exe",
    "schtasks.exe",
    "mmc.exe",
    "control.exe",
    "hh.exe",
    "notepad.exe",
    "dllhost.exe",
}

_DRIVE_PATH_RE = re.compile(r"^[a-zA-Z]:\\")
_UNEXPANDED_ENV_RE = re.compile(r"%[^%]+%")
_FW_APP_RE = re.compile(r"(?:^|\|)App=([^|]+)", re.IGNORECASE)


_WINDOWS_BUILTIN_PF_MARKERS = (
    "\\program files\\windowsapps\\",
    "\\program files\\windows media player\\",
    "\\program files (x86)\\windows media player\\",
    "\\program files\\windows defender\\",
    "\\program files\\windows defender advanced threat protection\\",
    "\\program files\\windows mail\\",
    "\\program files\\windows photo viewer\\",
    "\\program files\\internet explorer\\",
    "\\program files (x86)\\internet explorer\\",
    "\\program files\\windowspowershell\\",
    "\\program files (x86)\\windowspowershell\\",
    "\\program files\\windows security\\",
    "\\program files\\windows sidebar\\",
    "\\program files\\windows portable devices\\",
    "\\program files\\common files\\system\\",
    "\\program files (x86)\\common files\\system\\",
    "\\program files\\common files\\microsoft shared\\",
    "\\program files (x86)\\common files\\microsoft shared\\",
    "\\program files\\common files\\ink\\",
    "\\program files (x86)\\common files\\ink\\",
    "\\program files\\common files\\speech engines\\",
    "\\program files (x86)\\common files\\speech engines\\",
    "\\program files\\microsoft office\\",
    "\\program files (x86)\\microsoft office\\",
    "\\program files\\microsoft\\edge\\application\\",
    "\\program files (x86)\\microsoft\\edge\\application\\",
    "\\programdata\\microsoft\\windows defender\\",
)

_COM_BINARY_EXTS = (".dll", ".exe", ".ocx", ".ax", ".tlb")


def _is_windows_or_protected_path(path_str: str) -> bool:
    """Returns True if path points inside Windows OS directories, WindowsApps (ACL-restricted), or built-in Windows folders."""
    norm = normalize_path(path_str)
    if not norm:
        return True
    if norm in PROHIBITED_DIRECTORIES:
        return True
    win_root = normalize_path(os.environ.get("SystemRoot", "C:\\Windows"))
    if win_root and (norm == win_root or norm.startswith(win_root + "\\")):
        return True
    for pref in PROHIBITED_SUBTREE_PREFIXES:
        if norm == pref or norm.startswith(pref + "\\"):
            return True
    norm_slash = norm + "\\"
    if any(marker in norm_slash for marker in _WINDOWS_BUILTIN_PF_MARKERS):
        return True
    return False


def _is_verified_missing_local_file(raw_path: Optional[str]) -> bool:
    """
    Returns True ONLY when raw_path resolves to a concrete, local, non-Windows file path
    on a currently mounted drive AND that file does NOT exist on disk.
    """
    if not raw_path:
        return False
    cleaned = raw_path.strip().strip('"').strip("'").replace("/", "\\")
    if not cleaned:
        return False

    expanded = os.path.expandvars(cleaned)
    # If an unknown %ENVVAR% couldn't be expanded, never treat as missing
    if _UNEXPANDED_ENV_RE.search(expanded):
        return False

    # Must be a concrete local drive path (e.g. C:\...), never UNC \\server\... or relative
    if not _DRIVE_PATH_RE.match(expanded):
        return False

    # Never touch Windows core binaries or protected system paths
    if _is_windows_or_protected_path(expanded):
        return False

    # Ensure the drive itself is currently mounted (so unplugged external drives aren't flagged)
    drive_root = expanded[:3]
    if not os.path.exists(drive_root):
        return False

    # Check if the file (or path) exists
    return not os.path.exists(expanded)


def parse_lnk_target(lnk_path: Path) -> Optional[str]:
    """
    Pure-Python, thread-safe MS-SHLLINK (.lnk) target extractor.
    Reads LinkInfo (LocalBasePathUnicode / LocalBasePath + CommonPathSuffix) and
    EnvironmentVariableDataBlock (0xA0000001). Returns None for MSI advertised shortcuts,
    UWP/Shell-only links, or network shares.
    """
    try:
        data = lnk_path.read_bytes()
        if len(data) < 0x4C:
            return None
        header_size = struct.unpack_from("<I", data, 0)[0]
        if header_size != 0x4C:
            return None
        link_flags = struct.unpack_from("<I", data, 0x14)[0]
        has_id_list = bool(link_flags & 0x01)
        has_link_info = bool(link_flags & 0x02)
        has_name = bool(link_flags & 0x04)
        has_rel_path = bool(link_flags & 0x08)
        has_work_dir = bool(link_flags & 0x10)
        has_args = bool(link_flags & 0x20)
        has_icon = bool(link_flags & 0x40)
        is_unicode = bool(link_flags & 0x80)
        has_exp_string = bool(link_flags & 0x200)

        offset = 0x4C
        if has_id_list:
            if offset + 2 > len(data):
                return None
            id_list_size = struct.unpack_from("<H", data, offset)[0]
            offset += 2 + id_list_size

        link_info_target: Optional[str] = None
        if has_link_info:
            if offset + 28 > len(data):
                return None
            li_size, li_header_size, li_flags = struct.unpack_from("<III", data, offset)
            if li_size >= 28 and offset + li_size <= len(data) and (li_flags & 0x01):
                base_path_off = struct.unpack_from("<I", data, offset + 16)[0]
                common_suffix_off = struct.unpack_from("<I", data, offset + 24)[0]

                def _read_cstr(start: int) -> str:
                    end = data.find(b"\x00", start)
                    if end == -1 or end > offset + li_size:
                        end = offset + li_size
                    return data[start:end].decode("mbcs", errors="replace")

                def _read_wstr(start: int) -> str:
                    end = start
                    limit = offset + li_size
                    while end + 1 < limit:
                        if data[end] == 0 and data[end + 1] == 0:
                            break
                        end += 2
                    return data[start:end].decode("utf-16-le", errors="replace")

                base_path = ""
                suffix = ""
                if li_header_size >= 0x24 and offset + 36 <= len(data):
                    u_base_off, u_suffix_off = struct.unpack_from("<II", data, offset + 28)
                    if u_base_off:
                        base_path = _read_wstr(offset + u_base_off)
                    if u_suffix_off:
                        suffix = _read_wstr(offset + u_suffix_off)
                if not base_path and base_path_off:
                    base_path = _read_cstr(offset + base_path_off)
                if not suffix and common_suffix_off:
                    suffix = _read_cstr(offset + common_suffix_off)

                full = os.path.join(base_path, suffix) if suffix else base_path
                link_info_target = full.strip() or None
            offset += li_size

        # If EnvironmentVariableDataBlock exists, check it so shortcuts pointing via %ProgramFiles% aren't misread
        if has_exp_string:
            # Skip StringData sections
            for flag in (has_name, has_rel_path, has_work_dir, has_args, has_icon):
                if flag and offset + 2 <= len(data):
                    char_count = struct.unpack_from("<H", data, offset)[0]
                    offset += 2 + char_count * (2 if is_unicode else 1)

            while offset + 8 <= len(data):
                blk_size, blk_sig = struct.unpack_from("<II", data, offset)
                if blk_size < 4 or offset + blk_size > len(data):
                    break
                if blk_sig == 0xA0000001 and blk_size >= 788:
                    # TargetUnicode starts at offset + 268 (520 bytes UTF-16LE)
                    raw_u = data[offset + 268 : offset + 788]
                    u_str = raw_u.decode("utf-16-le", errors="replace").split("\x00", 1)[0].strip()
                    if u_str:
                        exp = os.path.expandvars(u_str)
                        if os.path.exists(exp):
                            return exp
                        if not link_info_target:
                            link_info_target = exp
                offset += blk_size

        return link_info_target
    except Exception:
        return None


class OrphanJunkScanner:
    """Scans the system for verified orphaned leftovers left behind by removed/broken software."""

    @classmethod
    def find_ghost_uninstall_keys(cls, all_apps: List[ApplicationEntry]) -> List[JunkItem]:
        """Finds Registry Uninstall entries whose uninstaller exe and install directory no longer exist."""
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        for app in all_apps:
            if app.source_scanner != "Registry" or app.is_system_component or app.is_protected:
                continue
            if not app.registry_path:
                continue

            # If install_location exists on disk, the app is still present — never flag!
            if app.install_location and os.path.exists(app.install_location):
                continue

            exe = extract_executable_path(app.uninstall_string or "")
            if not exe:
                continue
            exe_name = os.path.basename(exe).lower()
            if exe_name in _WINDOWS_GENERIC_EXECUTABLES:
                continue

            if _is_verified_missing_local_file(exe):
                # Double-check DisplayIcon isn't pointing to a live app binary
                if app.display_icon:
                    icon_clean = app.display_icon.rsplit(",", 1)[0]
                    icon_exe = extract_executable_path(icon_clean)
                    if icon_exe and os.path.exists(os.path.expandvars(icon_exe)):
                        continue

                results.append(
                    JunkItem(
                        app_id=app.id,
                        app_name=f"{app.display_name_trimmed} [Ghost]",
                        junk_type=JunkType.REGISTRY_KEY,
                        path=app.registry_path,
                        confidence_level=ConfidenceLevel.VERY_GOOD,
                        raw_score=14,
                        reasons=[f"Ghost uninstall key: uninstaller '{exe}' no longer exists on disk (+14)"],
                    )
                )
        return results

    @classmethod
    def find_broken_shortcuts(cls) -> List[JunkItem]:
        """Finds Desktop and Start Menu .lnk shortcuts whose target file no longer exists on disk."""
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        roots: List[Path] = []
        user_prof = os.environ.get("USERPROFILE")
        app_data = os.environ.get("APPDATA")
        prog_data = os.environ.get("ProgramData")

        if user_prof:
            d = Path(user_prof) / "Desktop"
            if d.exists():
                roots.append(d)
        if app_data:
            sm = Path(app_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
            if sm.exists():
                roots.append(sm)
        if prog_data:
            asm = Path(prog_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
            if asm.exists():
                roots.append(asm)

        for root in roots:
            try:
                for lnk in root.glob("**/*.lnk"):
                    target = parse_lnk_target(lnk)
                    if target and _is_verified_missing_local_file(target):
                        results.append(
                            JunkItem(
                                app_id="orphan:shortcut",
                                app_name=lnk.stem,
                                junk_type=JunkType.SHORTCUT,
                                path=str(lnk),
                                confidence_level=ConfidenceLevel.VERY_GOOD,
                                raw_score=12,
                                reasons=[f"Broken shortcut: target '{target}' no longer exists (+12)"],
                            )
                        )
            except (PermissionError, OSError):
                continue

        return results

    @classmethod
    def find_broken_startup_entries(cls) -> List[JunkItem]:
        """Finds Registry Run/RunOnce entries pointing to executables that no longer exist."""
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        for hive_name, subpath in StartupJunkFinder.RUN_KEYS:
            hive = RegistryHelper.HIVE_MAP.get(hive_name)
            if not hive:
                continue
            values = RegistryHelper.read_key_values(hive, subpath, view_64=True)
            for val_name, val_data in values.items():
                expanded_raw = os.path.expandvars(str(val_data or ""))
                exe = extract_executable_path(expanded_raw)
                if not exe:
                    continue
                if os.path.basename(exe).lower() in _WINDOWS_GENERIC_EXECUTABLES:
                    continue
                if _is_verified_missing_local_file(exe):
                    results.append(
                        JunkItem(
                            app_id="orphan:startup",
                            app_name=val_name,
                            junk_type=JunkType.STARTUP_ENTRY,
                            path=f"{hive_name}\\{subpath}\\{val_name}",
                            confidence_level=ConfidenceLevel.VERY_GOOD,
                            raw_score=12,
                            reasons=[f"Broken startup entry: '{exe}' no longer exists (+12)"],
                        )
                    )
        return results

    @classmethod
    def find_broken_app_paths(cls) -> List[JunkItem]:
        """Finds App Paths registry registrations pointing to executables that no longer exist."""
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        app_paths = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
        for hive_name in ("HKLM", "HKCU"):
            hive = RegistryHelper.HIVE_MAP.get(hive_name)
            if not hive:
                continue
            for subkey in RegistryHelper.enum_subkeys(hive, app_paths, view_64=True):
                full_sub = f"{app_paths}\\{subkey}"
                default_val = os.path.expandvars(str(RegistryHelper.read_default_value(hive, full_sub, view_64=True) or ""))
                exe = extract_executable_path(default_val)
                if not exe or os.path.basename(exe).lower() in _WINDOWS_GENERIC_EXECUTABLES:
                    continue
                if _is_verified_missing_local_file(exe):
                    results.append(
                        JunkItem(
                            app_id="orphan:apppath",
                            app_name=Path(subkey).stem,
                            junk_type=JunkType.APP_PATH,
                            path=f"{hive_name}\\{full_sub}",
                            confidence_level=ConfidenceLevel.VERY_GOOD,
                            raw_score=11,
                            reasons=[f"Orphaned App Path: '{exe}' no longer exists (+11)"],
                        )
                    )
        return results

    @classmethod
    def find_orphaned_services(cls) -> List[JunkItem]:
        """Finds user-mode Win32 services whose ImagePath executable no longer exists on disk."""
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        hive = RegistryHelper.HIVE_MAP.get("HKLM")
        if not hive:
            return []

        services_path = r"SYSTEM\CurrentControlSet\Services"
        for svc_name in RegistryHelper.enum_subkeys(hive, services_path, view_64=True):
            if svc_name.lower() in PROHIBITED_REGISTRY_KEYS:
                continue
            vals = RegistryHelper.read_key_values(hive, f"{services_path}\\{svc_name}", view_64=True)
            # Only inspect Win32 user-mode services (0x10 OwnProcess / 0x20 ShareProcess) — NEVER kernel drivers
            svc_type = vals.get("Type")
            try:
                if int(svc_type) not in (16, 32):
                    continue
            except (TypeError, ValueError):
                continue

            image_path = os.path.expandvars(str(vals.get("ImagePath", "")).strip())
            if not image_path or image_path.startswith("\\"):
                continue
            exe = extract_executable_path(image_path)
            if not exe or os.path.basename(exe).lower() in _WINDOWS_GENERIC_EXECUTABLES:
                continue
            if _is_verified_missing_local_file(exe):
                disp = str(vals.get("DisplayName") or svc_name).strip()
                results.append(
                    JunkItem(
                        app_id="orphan:service",
                        app_name=disp[:30],
                        junk_type=JunkType.SERVICE,
                        path=svc_name,
                        confidence_level=ConfidenceLevel.VERY_GOOD,
                        raw_score=13,
                        reasons=[f"Orphaned service: binary '{exe}' no longer exists (+13)"],
                    )
                )
        return results

    @classmethod
    def find_orphaned_firewall_rules(cls) -> List[JunkItem]:
        """Finds Windows Defender Firewall rules referencing executables that no longer exist."""
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        hive = RegistryHelper.HIVE_MAP.get("HKLM")
        if not hive:
            return []

        fw_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        values = RegistryHelper.read_key_values(hive, fw_path, view_64=True)
        for rule_id, rule_data in values.items():
            rule_str = str(rule_data or "")
            m = _FW_APP_RE.search(rule_str)
            if not m:
                continue
            app_bin = m.group(1).strip()
            if os.path.basename(app_bin).lower() in _WINDOWS_GENERIC_EXECUTABLES:
                continue
            if _is_verified_missing_local_file(app_bin):
                name_m = re.search(r"(?:^|\|)Name=([^|]+)", rule_str, re.IGNORECASE)
                rule_label = name_m.group(1).strip() if name_m else Path(app_bin).stem
                if rule_label.startswith("@"):
                    rule_label = Path(app_bin).stem
                results.append(
                    JunkItem(
                        app_id="orphan:firewall",
                        app_name=rule_label[:30],
                        junk_type=JunkType.FIREWALL_RULE,
                        path=rule_id,
                        confidence_level=ConfidenceLevel.VERY_GOOD,
                        raw_score=10,
                        reasons=[f"Orphaned firewall rule: '{app_bin}' no longer exists (+10)"],
                    )
                )
        return results

    @classmethod
    def find_orphaned_appcompat_entries(cls) -> List[JunkItem]:
        """Finds AppCompatFlags entries referencing executables that no longer exist on disk."""
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        for hive_name, subpath in AppCompatJunkFinder.COMPAT_PATHS:
            hive = RegistryHelper.HIVE_MAP.get(hive_name)
            if not hive:
                continue
            vals = RegistryHelper.read_key_values(hive, subpath, view_64=True)
            for val_name in vals.keys():
                if _is_verified_missing_local_file(val_name):
                    # Ignore temporary installer exes in Temp if already gone? Actually those ARE classic leftover entries!
                    results.append(
                        JunkItem(
                            app_id="orphan:appcompat",
                            app_name=Path(val_name).stem[:30],
                            junk_type=JunkType.APP_COMPAT,
                            path=f"{hive_name}\\{subpath}\\{val_name}",
                            confidence_level=ConfidenceLevel.GOOD,
                            raw_score=9,
                            reasons=[f"Orphaned AppCompat entry: '{val_name}' no longer exists (+9)"],
                        )
                    )
        return results

    @classmethod
    def find_orphaned_com_clsids(cls) -> List[JunkItem]:
        """Finds user/app COM CLSIDs pointing to missing binaries in Program Files / AppData / ProgramData."""
        if not IS_WINDOWS:
            return []

        results: List[JunkItem] = []
        safe_app_prefixes = tuple(
            normalize_path(os.environ.get(var, "")) + "\\"
            for var in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA", "APPDATA", "ProgramData")
            if os.environ.get(var)
        )

        for hive_name, subpath in ComClsidJunkFinder.CLSID_PATHS:
            hive = RegistryHelper.HIVE_MAP.get(hive_name)
            if not hive:
                continue
            try:
                for clsid in RegistryHelper.enum_subkeys(hive, subpath, view_64=True):
                    for server_key in ("InprocServer32", "LocalServer32"):
                        val = RegistryHelper.read_default_value(hive, f"{subpath}\\{clsid}\\{server_key}", view_64=True)
                        if not val:
                            continue
                        raw_expanded = os.path.expandvars(str(val).strip())
                        # InprocServer32 holds a direct DLL/OCX file path (never CLI flags)
                        if server_key == "InprocServer32":
                            candidate = raw_expanded.strip('"').strip("'")
                        else:
                            candidate = extract_executable_path(raw_expanded) or ""
                        if not candidate or not candidate.lower().endswith(_COM_BINARY_EXTS):
                            continue
                        norm_exp = normalize_path(candidate)
                        if not any(norm_exp.startswith(pref) for pref in safe_app_prefixes):
                            continue
                        if _is_verified_missing_local_file(candidate):
                            results.append(
                                JunkItem(
                                    app_id="orphan:com",
                                    app_name=Path(candidate).stem[:30],
                                    junk_type=JunkType.COM_CLSID,
                                    path=f"{hive_name}\\{subpath}\\{clsid}",
                                    confidence_level=ConfidenceLevel.VERY_GOOD,
                                    raw_score=11,
                                    reasons=[f"Orphaned COM {server_key}: '{candidate}' no longer exists (+11)"],
                                )
                            )
                            break
            except Exception:
                continue
        return results

    @classmethod
    def find_crash_dumps(cls) -> List[JunkItem]:
        """Finds diagnostic crash dump (.dmp) files in %LOCALAPPDATA%\\CrashDumps."""
        results: List[JunkItem] = []
        local_app = os.environ.get("LOCALAPPDATA")
        if not local_app:
            return results

        crash_dir = Path(local_app) / "CrashDumps"
        if not crash_dir.exists():
            return results

        try:
            for dmp in crash_dir.glob("*.dmp"):
                if dmp.is_file():
                    size_b = None
                    try:
                        size_b = dmp.stat().st_size
                    except OSError:
                        pass
                    results.append(
                        JunkItem(
                            app_id="orphan:crashdump",
                            app_name=dmp.stem.split(".", 1)[0][:30],
                            junk_type=JunkType.CRASH_DUMP,
                            path=str(dmp),
                            confidence_level=ConfidenceLevel.GOOD,
                            raw_score=8,
                            size_bytes=size_b,
                            reasons=["Diagnostic application crash dump (.dmp) (+8)"],
                        )
                    )
        except (PermissionError, OSError):
            pass
        return results

    @classmethod
    def scan_system_orphans(
        cls,
        all_apps: Optional[List[ApplicationEntry]] = None,
        min_confidence: ConfidenceLevel = ConfidenceLevel.GOOD,
        deep_scan: bool = True,
    ) -> List[JunkItem]:
        """
        Performs a safe, system-wide scan for verified orphaned leftovers from already-removed software.
        Never touches active installed applications.
        """
        from bcu.junk.cleaner import JunkCleaner

        all_apps = all_apps or []
        items: List[JunkItem] = []

        items.extend(cls.find_ghost_uninstall_keys(all_apps))
        items.extend(cls.find_broken_shortcuts())
        items.extend(cls.find_broken_startup_entries())
        items.extend(cls.find_broken_app_paths())
        items.extend(cls.find_crash_dumps())

        if deep_scan:
            items.extend(cls.find_orphaned_services())
            items.extend(cls.find_orphaned_firewall_rules())
            items.extend(cls.find_orphaned_appcompat_entries())
            items.extend(cls.find_orphaned_com_clsids())

        seen: Set[str] = set()
        safe_items: List[JunkItem] = []
        for item in items:
            dedup_key = f"{item.junk_type.value}:{item.path.lower()}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            if item.confidence_level >= min_confidence:
                is_safe, _ = JunkCleaner.is_safe_to_delete(item)
                if is_safe:
                    safe_items.append(item)

        # Sort highest-value / most obvious orphans first (Ghost Uninstall, Service, Shortcut, Startup, AppPath, Firewall, COM, Dump, AppCompat)
        safe_items.sort(key=lambda i: (-i.raw_score, i.junk_type.value, i.path.lower()))
        return safe_items
