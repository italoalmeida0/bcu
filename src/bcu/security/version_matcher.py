"""
Loose semantic version comparison and range matching for Windows software versions.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple


def parse_version_tuple(version_str: Optional[str]) -> Optional[Tuple[int, ...]]:
    """
    Extracts numeric version segments from a version string.
    Handles formats like 'v6.23', '23.01', '8.5.7.1', '2.45.1.windows.1'.
    """
    if not version_str:
        return None

    # Strip prefixes like 'v', 'ver', 'version'
    clean = re.sub(r"^(?:v|ver|version)\s*", "", version_str.strip(), flags=re.IGNORECASE)
    # Extract consecutive number sequences
    numbers = re.findall(r"\d+", clean)
    if not numbers:
        return None

    return tuple(int(n) for n in numbers)


def compare_versions(v1_str: str, v2_str: str) -> int:
    """
    Compares two version strings.
    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    t1 = parse_version_tuple(v1_str)
    t2 = parse_version_tuple(v2_str)

    if t1 is None and t2 is None:
        return 0
    if t1 is None:
        return -1
    if t2 is None:
        return 1

    # Pad shorter tuple with zeros
    max_len = max(len(t1), len(t2))
    p1 = t1 + (0,) * (max_len - len(t1))
    p2 = t2 + (0,) * (max_len - len(t2))

    if p1 < p2:
        return -1
    elif p1 > p2:
        return 1
    return 0


def match_version_constraint(installed_version: str, constraint_str: str) -> bool:
    """
    Evaluates if installed_version satisfies a constraint condition.
    Supports single or comma-separated constraints like:
      - '< 6.23'
      - '<= 23.01'
      - '>= 1.0.0, < 1.4.2'
      - '== 3.0.0'
    """
    if not installed_version or not constraint_str:
        return False

    installed_tuple = parse_version_tuple(installed_version)
    if installed_tuple is None:
        return False

    parts = [p.strip() for p in constraint_str.split(",") if p.strip()]
    for part in parts:
        match = re.match(r"^([<>!=]=?)\s*(.+)$", part)
        if not match:
            # Assume exact match or prefix if operator is missing
            op = "=="
            target_ver = part
        else:
            op = match.group(1)
            target_ver = match.group(2).strip()

        cmp = compare_versions(installed_version, target_ver)

        if op == "<" and not (cmp < 0):
            return False
        elif op == "<=" and not (cmp <= 0):
            return False
        elif op in ("==", "=") and not (cmp == 0):
            return False
        elif op == ">=" and not (cmp >= 0):
            return False
        elif op == ">" and not (cmp > 0):
            return False
        elif op == "!=" and not (cmp != 0):
            return False

    return True
