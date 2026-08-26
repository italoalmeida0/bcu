"""
Windows Registry scanner for installed applications.
Reads both 64-bit and 32-bit uninstall keys across HKLM and HKCU.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional
from bcu.models import ApplicationEntry, UninstallerType
from bcu.scanners.base import BaseScanner
from bcu.utils.platform import IS_WINDOWS, RegistryHelper


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

        # Targets to scan: (hive_name, subpath, view_64, is_64_bit_app)
        targets = [
            ("HKLM", self.REG_PATH, True, True),
            ("HKLM", self.REG_PATH_WOW, False, False),
            ("HKCU", self.REG_PATH, True, True),
            ("HKCU", self.REG_PATH_WOW, False, False),
        ]

        for hive_name, subpath, view_64, is_64_bit in targets:
            hive = RegistryHelper.HIVE_MAP.get(hive_name)
            if not hive:
                continue

            subkeys = RegistryHelper.enum_subkeys(hive, subpath, view_64=view_64)
            for subkey_name in subkeys:
                key_path = f"{subpath}\\{subkey_name}"
                values = RegistryHelper.read_key_values(hive, key_path, view_64=view_64)
                if not values:
                    continue

                display_name = str(values.get("DisplayName", "")).strip()
                if not display_name:
                    continue

                full_reg_path = f"{hive_name}\\{key_path}"
                app_id = f"reg:{hive_name}:{subkey_name}".lower()

                if app_id in seen_ids:
                    continue
                seen_ids.add(app_id)

                # Parse EstimatedSize (registry stores size in KB)
                raw_size = values.get("EstimatedSize")
                size_bytes: Optional[int] = None
                if raw_size is not None:
                    try:
                        size_bytes = int(raw_size) * 1024
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

                entry = ApplicationEntry(
                    id=app_id,
                    display_name=display_name,
                    display_version=str(values.get("DisplayVersion", "")).strip() or None,
                    publisher=str(values.get("Publisher", "")).strip() or None,
                    install_location=str(values.get("InstallLocation", "")).strip() or None,
                    uninstall_string=str(values.get("UninstallString", "")).strip() or None,
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
                    display_icon=str(values.get("DisplayIcon", "")).strip() or None,
                    comments=str(values.get("Comments", "")).strip() or None,
                    source_scanner=self.name,
                    raw_metadata=values,
                )
                entries.append(entry)

        return entries
