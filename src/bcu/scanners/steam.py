"""
Steam game library and appmanifest (.acf) scanner.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Set
from bcu.models import ApplicationEntry, UninstallerType
from bcu.scanners.base import BaseScanner
from bcu.utils.platform import IS_WINDOWS, RegistryHelper


def parse_vdf_simple(content: str) -> dict:
    """Simple parser for Valve KeyValues (.vdf / .acf) format."""
    result = {}
    pattern = re.compile(r'"([^"]+)"\s+"([^"]+)"')
    for match in pattern.finditer(content):
        result[match.group(1).lower()] = match.group(2)
    return result


class SteamScanner(BaseScanner):
    """Discovers installed Steam games and applications."""

    @property
    def name(self) -> str:
        return "Steam"

    def is_available(self) -> bool:
        return self._find_steam_path() is not None

    def _find_steam_path(self) -> Path | None:
        # Check Registry first
        if IS_WINDOWS:
            hive = RegistryHelper.HIVE_MAP.get("HKCU")
            if hive:
                vals = RegistryHelper.read_key_values(hive, r"Software\Valve\Steam", view_64=True)
                steam_path = vals.get("SteamPath")
                if steam_path and os.path.exists(steam_path):
                    return Path(steam_path)

        # Standard default locations
        defaults = [
            Path("C:/Program Files (x86)/Steam"),
            Path("C:/Program Files/Steam"),
            Path("D:/Steam"),
            Path("E:/Steam"),
        ]
        for p in defaults:
            if p.exists():
                return p
        return None

    def _find_library_folders(self, steam_root: Path) -> Set[Path]:
        folders = {steam_root}
        vdf_path = steam_root / "steamapps" / "libraryfolders.vdf"
        if vdf_path.exists():
            try:
                content = vdf_path.read_text(encoding="utf-8", errors="ignore")
                # Search for "path" "..." entries
                for match in re.finditer(r'"path"\s+"([^"]+)"', content, re.IGNORECASE):
                    p = Path(match.group(1).replace("\\\\", "\\"))
                    if p.exists():
                        folders.add(p)
            except Exception:
                pass
        return folders

    def scan(self) -> List[ApplicationEntry]:
        steam_root = self._find_steam_path()
        if not steam_root:
            return []

        entries: List[ApplicationEntry] = []
        library_folders = self._find_library_folders(steam_root)

        for lib_dir in library_folders:
            steamapps = lib_dir / "steamapps"
            if not steamapps.exists():
                continue

            for manifest in steamapps.glob("appmanifest_*.acf"):
                try:
                    content = manifest.read_text(encoding="utf-8", errors="ignore")
                    vdf_data = parse_vdf_simple(content)

                    app_id = vdf_data.get("appid")
                    app_name = vdf_data.get("name")
                    install_dir = vdf_data.get("installdir")
                    size_on_disk = vdf_data.get("sizeondisk")

                    # Skip Steamworks Common Redistributables or empty names
                    if not app_id or not app_name or app_id == "228980":
                        continue

                    full_install_path = str(steamapps / "common" / install_dir) if install_dir else None
                    size_bytes = int(size_on_disk) if size_on_disk and size_on_disk.isdigit() else None

                    entry = ApplicationEntry(
                        id=f"steam:{app_id}".lower(),
                        display_name=f"{app_name} (Steam)",
                        publisher="Steam",
                        install_location=full_install_path,
                        uninstall_string=f"steam://uninstall/{app_id}",
                        quiet_uninstall_string=f"steam://uninstall/{app_id}",
                        estimated_size_bytes=size_bytes,
                        uninstaller_type=UninstallerType.STEAM,
                        source_scanner=self.name,
                        raw_metadata={
                            "IsSteam": True,
                            "SteamAppId": app_id,
                            "ManifestPath": str(manifest),
                        },
                    )
                    entries.append(entry)
                except Exception:
                    continue

        return entries
