"""
Generates silent and unattended uninstallation command strings based on uninstaller types.
Ported from BCU's quiet argument generators.
"""

from __future__ import annotations

import re
from typing import Optional
from bcu.models import ApplicationEntry, UninstallerType
from bcu.enrichers.detector import GUID_PATTERN, extract_executable_path


def generate_quiet_uninstall_string(app: ApplicationEntry) -> Optional[str]:
    """
    Synthesizes a quiet uninstallation command for the given ApplicationEntry
    if one is not already provided or if it can be constructed reliably.
    """
    if app.quiet_uninstall_string and app.quiet_uninstall_string.strip():
        return app.quiet_uninstall_string.strip()

    base_cmd = (app.uninstall_string or "").strip()
    u_type = app.uninstaller_type

    # 1. MSIEXEC
    if u_type == UninstallerType.MSIEXEC:
        guid_match = GUID_PATTERN.search(base_cmd) or (
            GUID_PATTERN.search(app.bundle_provider_key or "")
        )
        if guid_match:
            guid = guid_match.group(0)
            return f"msiexec.exe /X{guid} /qn /norestart"
        if base_cmd:
            # Replace /I or /i with /X and append /qn /norestart
            clean_cmd = re.sub(r"/[Ii]\b", "/X", base_cmd)
            if "/qn" not in clean_cmd and "/quiet" not in clean_cmd:
                clean_cmd += " /qn /norestart"
            return clean_cmd

    # 2. INNO SETUP
    if u_type == UninstallerType.INNO_SETUP:
        exe_path = extract_executable_path(base_cmd)
        if exe_path:
            return f'"{exe_path}" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
        if base_cmd:
            return f"{base_cmd} /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"

    # 3. NSIS
    if u_type == UninstallerType.NSIS:
        exe_path = extract_executable_path(base_cmd)
        if exe_path:
            return f'"{exe_path}" /S'
        if base_cmd:
            return f"{base_cmd} /S"

    # 4. INSTALLSHIELD
    if u_type == UninstallerType.INSTALL_SHIELD:
        if base_cmd:
            if "/s" not in base_cmd.lower():
                return f'{base_cmd} /s /v"/qn /norestart"'
            return base_cmd

    # 5. STORE APP (UWP)
    if u_type == UninstallerType.STORE_APP:
        pkg_full_name = app.raw_metadata.get("PackageFullName") or app.id
        return f"powershell.exe -NoProfile -NonInteractive -Command \"Remove-AppxPackage -Package '{pkg_full_name}'\""

    # 6. WINGET
    if u_type == UninstallerType.WINGET:
        winget_id = app.raw_metadata.get("WingetId") or app.id
        return f"winget uninstall --id {winget_id} --silent --accept-source-agreements"

    # 7. SCOOP
    if u_type == UninstallerType.SCOOP:
        scoop_name = app.raw_metadata.get("ScoopName") or app.display_name_trimmed
        return f"scoop uninstall {scoop_name}"

    # 8. CHOCOLATEY
    if u_type == UninstallerType.CHOCOLATEY:
        choco_name = app.raw_metadata.get("ChocoName") or app.display_name_trimmed
        return f"choco uninstall {choco_name} -y --remove-dependencies"

    # 9. STEAM
    if u_type == UninstallerType.STEAM:
        steam_id = app.raw_metadata.get("SteamAppId")
        if steam_id:
            return f"steam://uninstall/{steam_id}"

    # 10. POWERSHELL
    if u_type == UninstallerType.POWER_SHELL:
        if base_cmd:
            return f"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {base_cmd}"

    # 11. WINDOWS FEATURE
    if u_type == UninstallerType.WINDOWS_FEATURE:
        feature_name = app.raw_metadata.get("FeatureName")
        if feature_name:
            return f"dism.exe /Online /Disable-Feature /FeatureName:{feature_name} /NoRestart"

    # 12. WINDOWS UPDATE
    if u_type == UninstallerType.WINDOWS_UPDATE:
        hotfix_id = app.raw_metadata.get("HotFixID")
        if hotfix_id:
            kb_num = hotfix_id.upper().replace("KB", "")
            return f"wusa.exe /uninstall /kb:{kb_num} /quiet /norestart"

    return None


def enrich_app_quiet_string(app: ApplicationEntry) -> None:
    """Enriches an ApplicationEntry with a synthesized quiet uninstall string."""
    if not app.quiet_uninstall_string:
        app.quiet_uninstall_string = generate_quiet_uninstall_string(app)
