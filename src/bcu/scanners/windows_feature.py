"""
Windows Optional Features scanner.
Discovers optional Windows features and capabilities enabled on the system.
"""

from __future__ import annotations

import json
from typing import List
from bcu.models import ApplicationEntry, UninstallerType
from bcu.scanners.base import BaseScanner
from bcu.utils.platform import IS_WINDOWS, run_powershell_command


class WindowsFeatureScanner(BaseScanner):
    """Discovers installed/enabled Windows Optional Features."""

    @property
    def name(self) -> str:
        return "WindowsFeature"

    def is_available(self) -> bool:
        return IS_WINDOWS

    def scan(self) -> List[ApplicationEntry]:
        if not self.is_available():
            return []

        entries: List[ApplicationEntry] = []
        ps_cmd = (
            "Get-WindowsOptionalFeature -Online | "
            "Where-Object { $_.State -eq 'Enabled' } | "
            "Select-Object FeatureName, State, Description | "
            "ConvertTo-Json -Compress"
        )
        code, stdout, _ = run_powershell_command(ps_cmd, timeout_sec=30)
        if code != 0 or not stdout:
            return []

        try:
            data = json.loads(stdout)
            if isinstance(data, dict):
                data = [data]
        except Exception:
            return []

        for item in data:
            feature_name = item.get("FeatureName")
            if not feature_name:
                continue

            desc = item.get("Description") or ""
            clean_display = feature_name.replace("-", " ").replace("_", " ")

            entry = ApplicationEntry(
                id=f"feature:{feature_name}".lower(),
                display_name=f"{clean_display} (Windows Feature)",
                publisher="Microsoft Windows",
                uninstall_string=f"dism.exe /Online /Disable-Feature /FeatureName:{feature_name}",
                quiet_uninstall_string=f"dism.exe /Online /Disable-Feature /FeatureName:{feature_name} /NoRestart",
                uninstaller_type=UninstallerType.WINDOWS_FEATURE,
                is_system_component=True,
                is_protected=True,
                comments=desc or None,
                source_scanner=self.name,
                raw_metadata={
                    "IsWindowsFeature": True,
                    "FeatureName": feature_name,
                    "State": item.get("State"),
                },
            )
            entries.append(entry)

        return entries
