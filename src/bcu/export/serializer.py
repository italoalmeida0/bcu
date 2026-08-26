"""
Export and import serializers for JSON, CSV, and BCUL uninstall lists.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import List, Union
from bcu.models import ApplicationEntry


class ApplicationSerializer:
    """Handles serialization and deserialization of application lists."""

    @classmethod
    def export_json(cls, apps: List[ApplicationEntry], target_path: Union[str, Path]) -> None:
        """Exports application entries to a JSON file."""
        data = [app.model_dump() for app in apps]
        Path(target_path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def export_csv(cls, apps: List[ApplicationEntry], target_path: Union[str, Path]) -> None:
        """Exports application entries to a CSV file."""
        fieldnames = [
            "id",
            "display_name",
            "display_version",
            "publisher",
            "install_location",
            "estimated_size_bytes",
            "uninstaller_type",
            "quiet_uninstall_possible",
            "uninstall_string",
            "quiet_uninstall_string",
            "install_date",
            "source_scanner",
        ]
        with open(target_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for app in apps:
                row = app.model_dump()
                row["quiet_uninstall_possible"] = app.quiet_uninstall_possible
                row["uninstaller_type"] = app.uninstaller_type.value
                writer.writerow(row)

    @classmethod
    def import_json(cls, source_path: Union[str, Path]) -> List[ApplicationEntry]:
        """Imports application entries from a JSON file."""
        content = Path(source_path).read_text(encoding="utf-8")
        data = json.loads(content)
        if isinstance(data, dict) and "apps" in data:
            data = data["apps"]
        return [ApplicationEntry.model_validate(item) for item in data]
