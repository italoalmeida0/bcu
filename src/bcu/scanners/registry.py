"""
Windows Registry scanner for installed applications.
Reads both 64-bit and 32-bit uninstall keys across HKLM and HKCU.
"""

from __future__ import annotations

import os
from typing import List, Optional
from bcu.config import PROHIBITED_DIRECTORIES, PROHIBITED_SUBTREE_PREFIXES
from bcu.enrichers.detector import extract_executable_path
from bcu.models import ApplicationEntry, UninstallerType
from bcu.scanners.base import BaseScanner
from bcu.utils.platform import IS_WINDOWS, RegistryHelper, normalize_path


_NON_APP_DIR_MARKERS = (
    "\\package cache\\",
    "\\windows\\installer",
    "\\windows\\system32",
    "\\windows\\syswow64",
    "\\windows\\sysarm32",
    "\\appdata\\local\\temp",
    "\\windows\\temp",
)


def _infer_install_location(uninstall_string: Optional[str], display_icon: Optional[str]) -> Optional[str]:
    """Safely infers an application's install directory from UninstallString or DisplayIcon when InstallLocation is missing."""
    candidates: List[str] = []
    if uninstall_string:
        exe = extract_executable_path(uninstall_string)
        if exe:
            candidates.append(exe)
    if display_icon:
        icon_clean = display_icon.strip()
        if "," in icon_clean:
            icon_clean = icon_clean.rsplit(",", 1)[0]
        exe = extract_executable_path(icon_clean)
        if exe:
            candidates.append(exe)

    for candidate in candidates:
        if not candidate or not os.path.isabs(candidate):
            continue
        parent = os.path.dirname(candidate)
        if not parent or not os.path.isdir(parent):
            continue
        norm = normalize_path(parent)
        if not norm or norm in PROHIBITED_DIRECTORIES:
            continue
        if any(norm == pref or norm.startswith(pref + "\\") for pref in PROHIBITED_SUBTREE_PREFIXES):
            continue
        if any(marker in norm + "\\" for marker in _NON_APP_DIR_MARKERS):
            continue
        return parent
    return None


class RegistryScanner(BaseScanner):
    """Discovers installed software from the Windows Registry."""

    REG_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    REG_PATH_WOW = r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

    @property
    def name(self) -> str:
        return "Registry"

    def is_available(self) -> bool:
        return IS_WINDOWS and RegistryHelper.HIVE_MAP.get("HKLM") is not None

    def scan(self) -> List[ApplicationEntry]:
        if not self.is_available():
            return []

        entries: List[ApplicationEntry] = []
        seen_ids = set()

        # Targets to scan: (hive_name, open_subpath, display_subpath, view_64, is_64_bit_app)
        # Note: Opening REG_PATH with KEY_WOW64_32KEY transparently redirects to Wow6432Node.
        targets = [
            ("HKLM", self.REG_PATH, self.REG_PATH, True, True),
            ("HKLM", self.REG_PATH, self.REG_PATH_WOW, False, False),
            ("HKCU", self.REG_PATH, self.REG_PATH, True, True),
        ]

        for hive_name, open_subpath, display_subpath, view_64, is_64_bit in targets:
            hive = RegistryHelper.HIVE_MAP.get(hive_name)
            if not hive:
                continue

            subkeys = RegistryHelper.enum_subkeys(hive, open_subpath, view_64=view_64)
            for subkey_name in subkeys:
                key_path = f"{open_subpath}\\{subkey_name}"
                values = RegistryHelper.read_key_values(hive, key_path, view_64=view_64)
                if not values:
                    continue

                display_name = str(values.get("DisplayName", "")).strip()
                if not display_name:
                    continue

                full_reg_path = f"{hive_name}\\{display_subpath}\\{subkey_name}"
                app_id = f"reg:{hive_name}:{subkey_name}".lower()

                if app_id in seen_ids:
                    if not is_64_bit:
                        app_id = f"reg:{hive_name}32:{subkey_name}".lower()
                    if app_id in seen_ids:
                        continue
                seen_ids.add(app_id)

                # Parse EstimatedSize (registry stores size in KB)
                raw_size = values.get("EstimatedSize")
                size_bytes: Optional[int] = None
                if raw_size is not None:
                    try:
                        parsed_kb = int(raw_size)
                        if parsed_kb >= 0:
                            size_bytes = parsed_kb * 1024
                    except (ValueError, TypeError):
                        pass

                # Parse SystemComponent
                system_comp_val = values.get("SystemComponent", 0)
                is_system = False
                try:
                    is_system = int(system_comp_val) != 0
                except (ValueError, TypeError):
                    pass

                # URL
                about_url = (
                    values.get("URLInfoAbout")
                    or values.get("HelpLink")
                    or values.get("URLUpdateInfo")
                )
                if about_url:
                    about_url = str(about_url).strip()

                uninstall_str = str(values.get("UninstallString", "")).strip() or None
                display_icon = str(values.get("DisplayIcon", "")).strip() or None
                install_loc = str(values.get("InstallLocation", "")).strip().strip('"') or None
                if not install_loc:
                    install_loc = _infer_install_location(uninstall_str, display_icon)

                entry = ApplicationEntry(
                    id=app_id,
                    display_name=display_name,
                    display_version=str(values.get("DisplayVersion", "")).strip() or None,
                    publisher=str(values.get("Publisher", "")).strip() or None,
                    install_location=install_loc,
                    uninstall_string=uninstall_str,
                    quiet_uninstall_string=str(values.get("QuietUninstallString", "")).strip() or None,
                    install_date=str(values.get("InstallDate", "")).strip() or None,
                    estimated_size_bytes=size_bytes,
                    uninstaller_type=UninstallerType.UNKNOWN,
                    is_system_component=is_system,
                    is_64_bit=is_64_bit,
                    registry_path=full_reg_path,
                    registry_key_name=subkey_name,
                    bundle_provider_key=str(values.get("BundleProviderKey", "")).strip() or None,
                    about_url=about_url,
                    install_source=str(values.get("InstallSource", "")).strip() or None,
                    display_icon=display_icon,
                    comments=str(values.get("Comments", "")).strip() or None,
                    source_scanner=self.name,
                    raw_metadata=values,
                )
                entries.append(entry)

        return entries
