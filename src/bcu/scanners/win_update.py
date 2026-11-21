"""
Windows Update (KB / Hotfix) scanner.
Discovers installed Windows Updates and security patches.
"""

from __future__ import annotations

import json
from typing import List
from bcu.models import ApplicationEntry, UninstallerType
from bcu.scanners.base import BaseScanner
from bcu.utils.platform import IS_WINDOWS, run_powershell_command


class WindowsUpdateScanner(BaseScanner):
    """Discovers installed Windows Updates and Hotfixes."""

    @property
    def name(self) -> str:
        return "WindowsUpdate"

    def is_available(self) -> bool:
        return IS_WINDOWS

    def scan(self) -> List[ApplicationEntry]:
        if not self.is_available():
            return []

        entries: List[ApplicationEntry] = []
        ps_cmd = (
            "Get-CimInstance Win32_QuickFixEngineering | "
            "Select-Object HotFixID, Description, "
            "@{Name='InstalledOn';Expression={if($_.InstalledOn){$_.InstalledOn.ToString('yyyy-MM-dd')}else{''}}}, "
            "InstalledBy | "
            "ConvertTo-Json -Compress"
        )
        code, stdout, _ = run_powershell_command(ps_cmd, timeout_sec=20)
        if code != 0 or not stdout:
            return []

        try:
            data = json.loads(stdout)
            if isinstance(data, dict):
                data = [data]
        except Exception:
            return []

        for item in data:
            hotfix_id = item.get("HotFixID")
            if not hotfix_id:
                continue

            desc = item.get("Description") or "Update"
            raw_installed = item.get("InstalledOn")
            if isinstance(raw_installed, dict):
                installed_on = str(raw_installed.get("DateTime") or "")
            else:
                installed_on = str(raw_installed or "").strip()
            kb_number = hotfix_id.upper().replace("KB", "")

            entry = ApplicationEntry(
                id=f"update:{hotfix_id}".lower(),
                display_name=f"Update for Windows ({hotfix_id}) - {desc}",
                publisher="Microsoft Corporation",
                install_date=installed_on or None,
                uninstall_string=f"wusa.exe /uninstall /kb:{kb_number}",
                quiet_uninstall_string=f"wusa.exe /uninstall /kb:{kb_number} /quiet /norestart",
                uninstaller_type=UninstallerType.WINDOWS_UPDATE,
                is_system_component=True,
                is_protected=True,
                comments=f"Installed by: {item.get('InstalledBy') or 'System'}",
                source_scanner=self.name,
                raw_metadata={
                    "IsWindowsUpdate": True,
                    "HotFixID": hotfix_id,
                    "Description": desc,
                },
            )
            entries.append(entry)

        return entries
