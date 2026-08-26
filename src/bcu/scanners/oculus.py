"""
Oculus VR application and game library scanner.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Set
from bcu.models import ApplicationEntry, UninstallerType
from bcu.scanners.base import BaseScanner
from bcu.utils.platform import IS_WINDOWS, RegistryHelper


class OculusScanner(BaseScanner):
    """Discovers installed Oculus VR games and software."""

    @property
    def name(self) -> str:
        return "Oculus"

    def is_available(self) -> bool:
        if not IS_WINDOWS:
            return False
        hive = RegistryHelper.HIVE_MAP.get("HKCU")
        if hive and RegistryHelper.key_exists(hive, r"Software\Oculus VR, LLC", view_64=True):
            return True
        oculus_prog = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Oculus"
        return oculus_prog.exists()

    def _find_library_locations(self) -> Set[Path]:
        locations: Set[Path] = set()
        prog_oculus = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Oculus" / "Software" / "Manifests"
        if prog_oculus.exists():
            locations.add(prog_oculus)

        # Check AppData Oculus paths
        local_app = os.environ.get("LOCALAPPDATA")
        if local_app:
            manifest_dir = Path(local_app) / "Oculus" / "Manifests"
            if manifest_dir.exists():
                locations.add(manifest_dir)

        return locations

    def scan(self) -> List[ApplicationEntry]:
        if not self.is_available():
            return []

        entries: List[ApplicationEntry] = []
        for manifest_dir in self._find_library_locations():
            try:
                for manifest_file in manifest_dir.glob("*.json"):
                    if manifest_file.name.endswith("_assets.json"):
                        continue
                    try:
                        content = manifest_file.read_text(encoding="utf-8", errors="ignore")
                        data = json.loads(content)
                        canonical_name = data.get("canonicalName") or manifest_file.stem
                        app_name = data.get("displayName") or canonical_name.replace("-", " ").title()
                        version = data.get("version")
                        install_dir = data.get("launchFile") or str(manifest_file.parent.parent / canonical_name)

                        entry = ApplicationEntry(
                            id=f"oculus:{canonical_name}".lower(),
                            display_name=f"{app_name} (Oculus)",
                            display_version=version,
                            publisher="Oculus VR",
                            install_location=install_dir if os.path.exists(install_dir) else None,
                            uninstaller_type=UninstallerType.OCULUS,
                            source_scanner=self.name,
                            raw_metadata={"IsOculus": True, "CanonicalName": canonical_name},
                        )
                        entries.append(entry)
                    except Exception:
                        continue
            except (PermissionError, OSError):
                continue

        return entries
