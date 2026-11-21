"""
Package Manager Scanners: Winget, Scoop, and Chocolatey.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Set, Tuple
from bcu.models import ApplicationEntry, UninstallerType
from bcu.scanners.base import BaseScanner
from bcu.utils.platform import SUBPROCESS_NO_WINDOW_FLAGS


class ScoopScanner(BaseScanner):
    """Discovers applications installed via Scoop package manager."""

    @property
    def name(self) -> str:
        return "Scoop"

    def _get_scoop_dirs(self) -> List[Path]:
        dirs: List[Path] = []
        candidates = [
            Path(os.environ.get("SCOOP", os.path.expanduser("~/scoop"))) / "apps",
            Path(os.environ.get("SCOOP_GLOBAL", "C:/ProgramData/scoop")) / "apps",
        ]
        for c in candidates:
            if c.exists() and c not in dirs:
                dirs.append(c)
        return dirs

    def is_available(self) -> bool:
        return bool(self._get_scoop_dirs()) or shutil.which("scoop") is not None

    def scan(self) -> List[ApplicationEntry]:
        entries: List[ApplicationEntry] = []
        seen: Set[str] = set()
        for scoop_apps_dir in self._get_scoop_dirs():
            try:
                for app_dir in scoop_apps_dir.iterdir():
                    if not app_dir.is_dir() or app_dir.name.startswith("."):
                        continue

                    app_name = app_dir.name
                    app_id = f"scoop:{app_name}".lower()
                    if app_id in seen:
                        continue
                    seen.add(app_id)

                    current_symlink = app_dir / "current"
                    version = None

                    if current_symlink.exists():
                        try:
                            version = current_symlink.resolve().name
                        except Exception:
                            pass

                    if not version:
                        versions = sorted(
                            p.name for p in app_dir.iterdir() if p.is_dir() and p.name != "current"
                        )
                        if versions:
                            version = versions[-1]

                    install_loc = str(current_symlink if current_symlink.exists() else app_dir)

                    entry = ApplicationEntry(
                        id=app_id,
                        display_name=f"{app_name} (Scoop)",
                        display_version=version,
                        publisher="Scoop",
                        install_location=install_loc,
                        uninstall_string=f"scoop uninstall {app_name}",
                        quiet_uninstall_string=f"scoop uninstall {app_name}",
                        uninstaller_type=UninstallerType.SCOOP,
                        source_scanner=self.name,
                        raw_metadata={"IsScoop": True, "ScoopName": app_name},
                    )
                    entries.append(entry)
            except (PermissionError, OSError):
                continue

        return entries


class ChocolateyScanner(BaseScanner):
    """Discovers applications installed via Chocolatey package manager."""

    @property
    def name(self) -> str:
        return "Chocolatey"

    def _get_choco_lib(self) -> Path:
        base = os.environ.get("ChocolateyInstall", "C:/ProgramData/chocolatey")
        return Path(base) / "lib"

    def is_available(self) -> bool:
        return self._get_choco_lib().exists() or shutil.which("choco") is not None

    def scan(self) -> List[ApplicationEntry]:
        entries: List[ApplicationEntry] = []
        choco_lib = self._get_choco_lib()
        if not choco_lib.exists():
            return entries

        try:
            for pkg_dir in choco_lib.iterdir():
                if not pkg_dir.is_dir() or pkg_dir.name.lower() in ("chocolatey", "chocolatey-core.extension"):
                    continue

                pkg_name = pkg_dir.name

                # Look for .nuspec file
                version = None
                nuspec_files = list(pkg_dir.glob("*.nuspec"))
                if nuspec_files:
                    try:
                        content = nuspec_files[0].read_text(encoding="utf-8", errors="ignore")
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
                    uninstall_string=f"choco uninstall {pkg_name}",
                    quiet_uninstall_string=f"choco uninstall {pkg_name} -y --remove-dependencies",
                    uninstaller_type=UninstallerType.CHOCOLATEY,
                    source_scanner=self.name,
                    raw_metadata={"IsChoco": True, "ChocoName": pkg_name},
                )
                entries.append(entry)
        except (PermissionError, OSError):
            pass

        return entries


class WingetScanner(BaseScanner):
    """Discovers applications listed via Windows Package Manager (winget)."""

    @property
    def name(self) -> str:
        return "Winget"

    def is_available(self) -> bool:
        return shutil.which("winget") is not None

    @staticmethod
    def parse_winget_output(stdout: str, include_arp_msix: bool = False) -> List[ApplicationEntry]:
        """
        Parses fixed-width table output from `winget list`.
        Handles modern unbroken `----` separators, spinner `\\r` fragments, and localized column headers.
        """
        entries: List[ApplicationEntry] = []
        seen_ids: Set[str] = set()

        # Normalize progress spinner carriage returns by taking the last segment of each line
        cleaned_lines: List[str] = []
        for raw_line in stdout.splitlines():
            seg = raw_line.split("\r")[-1].rstrip()
            if seg.strip():
                cleaned_lines.append(seg)

        # Find the horizontal rule separator (at least 20 dashes) and the header line immediately above it
        header_idx = -1
        sep_idx = -1
        for i in range(1, len(cleaned_lines)):
            stripped = cleaned_lines[i].strip()
            if len(stripped) >= 20 and set(stripped) <= {"-", " "}:
                header_idx = i - 1
                sep_idx = i
                break

        if header_idx == -1 or sep_idx == -1:
            return entries

        header_line = cleaned_lines[header_idx]
        # Compute column start indices from the header tokens (works across English, Portuguese, German, etc.)
        col_starts = [m.start() for m in re.finditer(r"\S+", header_line)]
        if len(col_starts) < 3:
            return entries

        col_spans: List[Tuple[int, int | None]] = []
        for idx, start in enumerate(col_starts):
            end = col_starts[idx + 1] if idx + 1 < len(col_starts) else None
            col_spans.append((start, end))

        for line in cleaned_lines[sep_idx + 1:]:
            stripped = line.strip()
            if not stripped or stripped.startswith(("-", "<")):
                continue

            def get_col(idx: int) -> str:
                if idx >= len(col_spans):
                    return ""
                start, end = col_spans[idx]
                if len(line) <= start:
                    return ""
                return line[start:end].strip() if end is not None else line[start:].strip()

            app_name = get_col(0)
            app_id = get_col(1)
            version = get_col(2)
            # With 5 cols: [Name, Id, Version, Available, Source]; with 4 cols: [Name, Id, Version, Source]
            source = get_col(4) if len(col_spans) >= 5 else (get_col(3) if len(col_spans) == 4 else "")

            if not app_name or not app_id:
                continue

            # Skip synthetic ARP/MSIX mirror rows unless explicitly requested (already covered by Registry & StoreApp)
            if not include_arp_msix and app_id.upper().startswith(("ARP\\", "MSIX\\")):
                continue

            # Strip trailing ellipsis if winget truncated a super long ID
            entry_id = f"winget:{app_id}".lower()
            if entry_id in seen_ids:
                continue
            seen_ids.add(entry_id)

            entries.append(
                ApplicationEntry(
                    id=entry_id,
                    display_name=f"{app_name} (Winget)",
                    display_version=version or None,
                    publisher=source or "Winget",
                    uninstall_string=f'winget uninstall --id "{app_id}" --exact',
                    quiet_uninstall_string=f'winget uninstall --id "{app_id}" --exact --silent --accept-source-agreements',
                    uninstaller_type=UninstallerType.WINGET,
                    source_scanner="Winget",
                    raw_metadata={
                        "IsWinget": True,
                        "WingetId": app_id,
                        "WingetSource": source,
                    },
                )
            )

        return entries

    def scan(self) -> List[ApplicationEntry]:
        if not self.is_available():
            return []

        try:
            cmd = ["winget", "list", "--accept-source-agreements", "--disable-interactivity"]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=25,
                encoding="utf-8",
                errors="replace",
                creationflags=SUBPROCESS_NO_WINDOW_FLAGS,
            )
            if proc.returncode != 0 or not proc.stdout:
                return []

            return self.parse_winget_output(proc.stdout)
        except Exception:
            return []
