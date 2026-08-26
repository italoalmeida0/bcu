"""
Package Manager Scanners: Winget, Scoop, and Chocolatey.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import List
from bcu.models import ApplicationEntry, UninstallerType
from bcu.scanners.base import BaseScanner


class ScoopScanner(BaseScanner):
    """Discovers applications installed via Scoop package manager."""

    @property
    def name(self) -> str:
        return "Scoop"

    def is_available(self) -> bool:
        scoop_dir = os.path.expanduser("~/scoop/apps")
        return os.path.exists(scoop_dir) or shutil.which("scoop") is not None

    def scan(self) -> List[ApplicationEntry]:
        entries: List[ApplicationEntry] = []
        scoop_apps_dir = Path(os.path.expanduser("~/scoop/apps"))
        if not scoop_apps_dir.exists():
            return entries

        for app_dir in scoop_apps_dir.iterdir():
            if not app_dir.is_dir() or app_dir.name.startswith("."):
                continue

            app_name = app_dir.name
            current_symlink = app_dir / "current"
            version = None

            if current_symlink.exists():
                try:
                    version = current_symlink.resolve().name
                except Exception:
                    pass

            if not version:
                # Find newest subfolder
                versions = [p.name for p in app_dir.iterdir() if p.is_dir() and p.name != "current"]
                if versions:
                    version = versions[-1]

            install_loc = str(current_symlink if current_symlink.exists() else app_dir)

            entry = ApplicationEntry(
                id=f"scoop:{app_name}".lower(),
                display_name=f"{app_name} (Scoop)",
                display_version=version,
                publisher="Scoop",
                install_location=install_loc,
                uninstaller_type=UninstallerType.SCOOP,
                source_scanner=self.name,
                raw_metadata={"IsScoop": True, "ScoopName": app_name},
            )
            entries.append(entry)

        return entries


class ChocolateyScanner(BaseScanner):
    """Discovers applications installed via Chocolatey package manager."""

    @property
    def name(self) -> str:
        return "Chocolatey"

    def is_available(self) -> bool:
        choco_lib = Path("C:/ProgramData/chocolatey/lib")
        return choco_lib.exists() or shutil.which("choco") is not None

    def scan(self) -> List[ApplicationEntry]:
        entries: List[ApplicationEntry] = []
        choco_lib = Path("C:/ProgramData/chocolatey/lib")
        if not choco_lib.exists():
            return entries

        for pkg_dir in choco_lib.iterdir():
            if not pkg_dir.is_dir() or pkg_dir.name.lower() in ("chocolatey", "chocolatey-core.extension"):
                continue

            pkg_name = pkg_dir.name

            # Look for .nuspec file
            version = None
            nuspec_files = list(pkg_dir.glob("*.nuspec"))
            if nuspec_files:
                try:
                    # Simple heuristic parse without heavy XML dependency
                    content = nuspec_files[0].read_text(encoding="utf-8", errors="ignore")
                    import re
                    ver_match = re.search(r"<version>([^<]+)</version>", content, re.IGNORECASE)
                    if ver_match:
                        version = ver_match.group(1)
                except Exception:
                    pass

            entry = ApplicationEntry(
                id=f"choco:{pkg_name}".lower(),
                display_name=f"{pkg_name} (Chocolatey)",
                display_version=version,
                publisher="Chocolatey",
                install_location=str(pkg_dir),
                uninstaller_type=UninstallerType.CHOCOLATEY,
                source_scanner=self.name,
                raw_metadata={"IsChoco": True, "ChocoName": pkg_name},
            )
            entries.append(entry)

        return entries


class WingetScanner(BaseScanner):
    """Discovers applications listed via Windows Package Manager (winget)."""

    @property
    def name(self) -> str:
        return "Winget"

    def is_available(self) -> bool:
        return shutil.which("winget") is not None

    def scan(self) -> List[ApplicationEntry]:
        if not self.is_available():
            return []

        entries: List[ApplicationEntry] = []
        try:
            cmd = ["winget", "list", "--accept-source-agreements"]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=25,
                encoding="utf-8",
                errors="replace",
            )
            if proc.returncode != 0 or not proc.stdout:
                return []

            lines = [line.rstrip() for line in proc.stdout.splitlines() if line.strip()]
            header_idx = -1
            sep_idx = -1

            for i, line in enumerate(lines):
                if "Name" in line and "Id" in line and "Version" in line:
                    header_idx = i
                elif header_idx != -1 and line.startswith("---") and " " in line:
                    sep_idx = i
                    break

            if header_idx == -1 or sep_idx == -1:
                return []

            sep_line = lines[sep_idx]
            # Calculate column boundaries based on separator line
            # e.g. "------------------- ------------ -----------"
            col_spans = []
            current_start = 0
            for part in sep_line.split(" "):
                if part:
                    col_spans.append((current_start, current_start + len(part)))
                    current_start += len(part) + 1
                else:
                    current_start += 1

            for line in lines[sep_idx + 1:]:
                if not line.strip() or line.startswith(("-", "<")):
                    continue

                def get_col(idx: int) -> str:
                    if idx < len(col_spans):
                        start, end = col_spans[idx]
                        return line[start:end].strip() if len(line) >= start else ""
                    return ""

                app_name = get_col(0)
                app_id = get_col(1)
                version = get_col(2)
                source = get_col(4) if len(col_spans) >= 5 else ""

                if not app_name or not app_id:
                    continue

                entry = ApplicationEntry(
                    id=f"winget:{app_id}".lower(),
                    display_name=f"{app_name} (Winget)",
                    display_version=version or None,
                    publisher=source or "Winget",
                    uninstall_string=f"winget uninstall --id {app_id}",
                    quiet_uninstall_string=f"winget uninstall --id {app_id} --silent --accept-source-agreements",
                    uninstaller_type=UninstallerType.WINGET,
                    source_scanner=self.name,
                    raw_metadata={
                        "IsWinget": True,
                        "WingetId": app_id,
                        "WingetSource": source,
                    },
                )
                entries.append(entry)
        except Exception:
            pass

        return entries
