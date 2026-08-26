"""
Detects uninstaller types and architectures based on uninstallation strings,
executables, and metadata (ported from BCU).
"""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import Optional

from bcu.models import ApplicationEntry, UninstallerType

INNO_FILENAME_PATTERN = re.compile(r"unins\d{3}\.exe", re.IGNORECASE)
GUID_PATTERN = re.compile(r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}")


def detect_uninstaller_type(
    uninstall_string: Optional[str] = None,
    install_location: Optional[str] = None,
    raw_metadata: Optional[dict] = None,
) -> UninstallerType:
    """
    Analyzes an uninstaller command string and metadata to determine the uninstaller type.
    """
    raw_metadata = raw_metadata or {}
    cmd = (uninstall_string or "").strip()

    if not cmd:
        if raw_metadata.get("IsStoreApp"):
            return UninstallerType.STORE_APP
        if raw_metadata.get("IsScoop"):
            return UninstallerType.SCOOP
        if raw_metadata.get("IsChoco"):
            return UninstallerType.CHOCOLATEY
        if raw_metadata.get("IsWinget"):
            return UninstallerType.WINGET
        if raw_metadata.get("IsSteam"):
            return UninstallerType.STEAM
        if install_location and os.path.exists(install_location):
            return UninstallerType.SIMPLE_DELETE
        return UninstallerType.UNKNOWN

    cmd_lower = cmd.lower()

    # 1. Check for MSI / Windows Installer
    if "msiexec" in cmd_lower or ("package cache\\{" in cmd_lower and ".exe" in cmd_lower):
        return UninstallerType.MSIEXEC
    if raw_metadata.get("WindowsInstaller") == 1 or raw_metadata.get("WindowsInstaller") == "1":
        return UninstallerType.MSIEXEC
    if GUID_PATTERN.search(cmd) and ("msi" in cmd_lower or "/x" in cmd_lower or "/i" in cmd_lower):
        return UninstallerType.MSIEXEC

    # 2. Check for StoreApp / UWP / MSIX
    if "remove-appxpackage" in cmd_lower or raw_metadata.get("IsStoreApp"):
        return UninstallerType.STORE_APP

    # 3. Check for Package Managers
    if "winget uninstall" in cmd_lower or "winget" in cmd_lower:
        return UninstallerType.WINGET
    if "choco uninstall" in cmd_lower or "chocolatey" in cmd_lower:
        return UninstallerType.CHOCOLATEY
    if "scoop uninstall" in cmd_lower or "scoop" in cmd_lower:
        return UninstallerType.SCOOP

    # 4. Check for Steam
    if "steam://uninstall" in cmd_lower or "steam.exe" in cmd_lower:
        return UninstallerType.STEAM

    # 5. Check for Oculus
    if "oculus" in cmd_lower and ("uninstall" in cmd_lower or "redistributable" in cmd_lower):
        return UninstallerType.OCULUS

    # 6. Check for InstallShield
    if "installshield" in cmd_lower or "isuninst.exe" in cmd_lower:
        return UninstallerType.INSTALL_SHIELD

    # 7. Check for SdbInst
    if "sdbinst" in cmd_lower and ".sdb" in cmd_lower:
        return UninstallerType.SDB_INST

    # 8. Check for PowerShell scripts
    if "powershell.exe" in cmd_lower or cmd_lower.endswith(".ps1"):
        return UninstallerType.POWER_SHELL

    # 9. Extract executable path and inspect file properties if available
    exe_path = extract_executable_path(cmd)
    if exe_path and os.path.isabs(exe_path) and os.path.exists(exe_path):
        exe_name = os.path.basename(exe_path)

        # Inno Setup heuristic: unins000.exe alongside unins000.dat
        if INNO_FILENAME_PATTERN.match(exe_name):
            dat_path = os.path.splitext(exe_path)[0] + ".dat"
            if os.path.exists(dat_path):
                return UninstallerType.INNO_SETUP
            return UninstallerType.INNO_SETUP

        # NSIS Nullsoft header inspection
        try:
            with open(exe_path, "rb") as f:
                header = f.read(65536)
                if b"NullsoftInst" in header or b"Nullsoft" in header:
                    return UninstallerType.NSIS
                if b"Inno Setup" in header:
                    return UninstallerType.INNO_SETUP
        except (OSError, PermissionError):
            pass

    # Generic filename heuristics
    if "unins00" in cmd_lower:
        return UninstallerType.INNO_SETUP
    if "uninstall.exe" in cmd_lower or "uninst.exe" in cmd_lower:
        return UninstallerType.NSIS

    return UninstallerType.CUSTOM


def extract_executable_path(cmd_str: str) -> Optional[str]:
    """Extracts the first executable path from a command string."""
    if not cmd_str:
        return None
    cmd_str = cmd_str.strip()

    if cmd_str.startswith('"'):
        end_idx = cmd_str.find('"', 1)
        if end_idx != -1:
            return cmd_str[1:end_idx]

    # Split by spaces if no leading quote
    parts = cmd_str.split()
    if parts:
        return parts[0]
    return None


def enrich_app_uninstaller_type(app: ApplicationEntry) -> None:
    """Enriches an ApplicationEntry with detected uninstaller type."""
    if app.uninstaller_type == UninstallerType.UNKNOWN:
        app.uninstaller_type = detect_uninstaller_type(
            uninstall_string=app.uninstall_string or app.quiet_uninstall_string,
            install_location=app.install_location,
            raw_metadata=app.raw_metadata,
        )
