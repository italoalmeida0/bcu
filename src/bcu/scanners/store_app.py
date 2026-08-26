"""
Windows Store Apps (UWP / AppX / MSIX) discovery scanner.
"""

from __future__ import annotations

import json
from typing import List
from bcu.models import ApplicationEntry, UninstallerType
from bcu.scanners.base import BaseScanner
from bcu.utils.platform import IS_WINDOWS, run_powershell_command


class StoreAppScanner(BaseScanner):
    """Discovers installed Windows Store (UWP / MSIX) applications."""

    @property
    def name(self) -> str:
        return "StoreApp"

    def is_available(self) -> bool:
        return IS_WINDOWS

    def scan(self) -> List[ApplicationEntry]:
        if not self.is_available():
            return []

        # Query Appx packages as JSON via PowerShell
        ps_cmd = (
            "Get-AppxPackage -AllUsers | "
            "Where-Object { -not $_.IsFramework -and -not $_.IsResourcePackage } | "
            "Select-Object Name, PackageFullName, Publisher, Version, InstallLocation, NonRemovable, SignatureKind | "
            "ConvertTo-Json -Compress"
        )

        code, stdout, _ = run_powershell_command(ps_cmd, timeout_sec=25)
        if code != 0 or not stdout:
            return []

        try:
            data = json.loads(stdout)
            if isinstance(data, dict):
                data = [data]
        except Exception:
            return []

        entries: List[ApplicationEntry] = []
        for pkg in data:
            name = pkg.get("Name")
            full_name = pkg.get("PackageFullName")
            if not name or not full_name:
                continue

            # Friendly clean name
            clean_name = name.replace("Microsoft.", "").replace(".", " ")
            version = pkg.get("Version")
            publisher = pkg.get("Publisher")
            install_loc = pkg.get("InstallLocation")
            is_protected = bool(pkg.get("NonRemovable", False))

            entry = ApplicationEntry(
                id=f"store:{full_name}".lower(),
                display_name=f"{clean_name} (Store App)",
                display_version=version,
                publisher=publisher,
                install_location=install_loc,
                uninstaller_type=UninstallerType.STORE_APP,
                is_system_component=is_protected,
                is_protected=is_protected,
                source_scanner=self.name,
                raw_metadata={
                    "IsStoreApp": True,
                    "PackageFullName": full_name,
                    "Name": name,
                    "SignatureKind": pkg.get("SignatureKind"),
                },
            )
            entries.append(entry)

        return entries
