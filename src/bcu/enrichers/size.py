"""
Calculates file and directory disk space usage for installed applications.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from bcu.models import ApplicationEntry


def calculate_dir_size(dir_path: str, max_depth: int = 10) -> Optional[int]:
    """Calculates total size of a directory in bytes."""
    if not dir_path or not os.path.exists(dir_path):
        return None

    total_size = 0
    try:
        p = Path(dir_path)
        if p.is_file():
            return p.stat().st_size

        for root, _, files in os.walk(dir_path):
            # Check depth relative to start directory
            depth = len(Path(root).relative_to(p).parts)
            if depth > max_depth:
                continue

            for f in files:
                file_path = os.path.join(root, f)
                try:
                    total_size += os.path.getsize(file_path)
                except (OSError, PermissionError, FileNotFoundError):
                    continue
        return total_size
    except (OSError, PermissionError):
        return None


def enrich_app_size(app: ApplicationEntry) -> None:
    """Enriches an ApplicationEntry with estimated disk size if absent."""
    if app.estimated_size_bytes is None or app.estimated_size_bytes <= 0:
        if app.install_location and os.path.exists(app.install_location):
            size = calculate_dir_size(app.install_location)
            if size and size > 0:
                app.estimated_size_bytes = size
