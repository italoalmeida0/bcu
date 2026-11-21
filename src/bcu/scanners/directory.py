"""
Directory scanner for detecting orphaned applications and standalone setup directories.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Set
from bcu.models import ApplicationEntry, UninstallerType
from bcu.scanners.base import BaseScanner
from bcu.enrichers.detector import INNO_FILENAME_PATTERN

UNINSTALLER_EXE_NAMES = {
    "uninstall.exe",
    "uninst.exe",
    "uninstaller.exe",
    "unins000.exe",
    "unins001.exe",
}


class DirectoryScanner(BaseScanner):
    """Discovers standalone applications by scanning common program folders."""

    @property
    def name(self) -> str:
        return "Directory"

    def is_available(self) -> bool:
        return True

    def _get_search_roots(self) -> List[Path]:
        roots = []
        for env_var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA", "APPDATA"]:
            val = os.environ.get(env_var)
            if val:
                p = Path(val)
                if env_var in ("LOCALAPPDATA", "APPDATA"):
                    p = p / "Programs"
                if p.exists():
                    roots.append(p)
        return roots

    def scan(self) -> List[ApplicationEntry]:
        # Fast directory scan
        entries: List[ApplicationEntry] = []
        seen_paths: Set[str] = set()
        seen_ids: Set[str] = set()

        for root in self._get_search_roots():
            try:
                for item in root.iterdir():
                    if not item.is_dir() or item.name.startswith((".", "$")):
                        continue

                    # Look for uninstaller executables in top level
                    found_uninstaller = None
                    try:
                        for child in item.iterdir():
                            if child.is_file() and (
                                child.name.lower() in UNINSTALLER_EXE_NAMES
                                or INNO_FILENAME_PATTERN.match(child.name)
                            ):
                                found_uninstaller = str(child)
                                break
                    except (PermissionError, OSError):
                        continue

                    norm_item = str(item).lower()
                    if found_uninstaller and norm_item not in seen_paths:
                        seen_paths.add(norm_item)
                        clean_name = item.name.replace("_", " ").title()
                        app_id = f"dir:{item.name}".lower()
                        if app_id in seen_ids:
                            app_id = f"dir:{root.name}:{item.name}".lower()
                        seen_ids.add(app_id)

                        entry = ApplicationEntry(
                            id=app_id,
                            display_name=f"{clean_name} (Directory)",
                            install_location=str(item),
                            uninstall_string=f'"{found_uninstaller}"',
                            uninstaller_type=UninstallerType.UNKNOWN,
                            source_scanner=self.name,
                        )
                        entries.append(entry)
            except (PermissionError, OSError):
                continue

        return entries
