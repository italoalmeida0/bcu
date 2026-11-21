"""
Windows Store Apps (UWP / AppX / MSIX) discovery scanner.
"""

from __future__ import annotations

import json
import re
from typing import List, Optional
from bcu.models import ApplicationEntry, UninstallerType
from bcu.scanners.base import BaseScanner
from bcu.utils.platform import IS_WINDOWS, is_admin, run_powershell_command


def _clean_x509_publisher(raw_pub: Optional[str]) -> Optional[str]:
    """Extracts a human-readable organization/common name from an AppX X.509 Publisher string."""
    if not raw_pub:
        return None
    s = raw_pub.strip()
    if "CN=" not in s and "O=" not in s:
        return s
    # Prefer O= (Organization) if present and readable, otherwise CN=
    o_match = re.search(r"(?:^|,\s*)O=([^,]+)", s)
    if o_match:
        org = o_match.group(1).strip().strip('"')
        if org:
            return org
    cn_match = re.search(r"(?:^|,\s*)CN=([^,]+)", s)
    if cn_match:
        cn = cn_match.group(1).strip().strip('"')
        if cn:
            return cn
    return s


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

        # -AllUsers requires elevated privileges; fall back to current user cleanly when non-admin
        all_users_flag = "-AllUsers" if is_admin() else ""
        ps_cmd = (
            f"Get-AppxPackage {all_users_flag} | "
            "Where-Object { -not $_.IsFramework -and -not $_.IsResourcePackage } | "
            "Select-Object Name, PackageFullName, Publisher, Version, InstallLocation, NonRemovable, SignatureKind | "
            "ConvertTo-Json -Compress"
        )

        code, stdout, _ = run_powershell_command(ps_cmd, timeout_sec=25)
        if (code != 0 or not stdout) and all_users_flag:
            # Retry current user only if -AllUsers failed unexpectedly
            ps_cmd_fallback = ps_cmd.replace("-AllUsers", "")
            code, stdout, _ = run_powershell_command(ps_cmd_fallback, timeout_sec=25)
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

            # Friendly clean name & publisher
            clean_name = name.replace("Microsoft.", "").replace(".", " ")
            version = pkg.get("Version")
            raw_publisher = pkg.get("Publisher")
            publisher = _clean_x509_publisher(raw_publisher)
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
                    "RawPublisher": raw_publisher,
                    "SignatureKind": pkg.get("SignatureKind"),
                },
            )
            entries.append(entry)

        return entries
