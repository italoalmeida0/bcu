"""
Sift4 string distance algorithm for fast string similarity comparisons,
ported from BCU (Bulk Crap Uninstaller).
Original algorithm by Siderite.
"""

from __future__ import annotations
from typing import Optional


def sift4_simplest_distance(s1: Optional[str], s2: Optional[str], max_offset: int = 5) -> int:
    """
    Standard Sift4 distance algorithm using strings and taking max_offset.
    Returns the estimated edit distance between s1 and s2.
    0 means strings are identical.
    """
    if not s1:
        return len(s2) if s2 else 0
    if not s2:
        return len(s1)

    l1 = len(s1)
    l2 = len(s2)

    c1 = 0  # cursor for string 1
    c2 = 0  # cursor for string 2
    lcss = 0  # largest common subsequence
    local_cs = 0  # local common substring

    while c1 < l1 and c2 < l2:
        if s1[c1] == s2[c2]:
            local_cs += 1
        else:
            lcss += local_cs
            local_cs = 0
            if c1 != c2:
                c1 = c2 = max(c1, c2)

            for i in range(max_offset):
                if (c1 + i < l1) and (c2 + i < l2):
                    if (c1 + i < l1) and (s1[c1 + i] == s2[c2]):
                        c1 += i - 1
                        c2 -= 1
                        break
                    if (c2 + i < l2) and (s1[c1] == s2[c2 + i]):
                        c1 -= 1
                        c2 += i - 1
                        break

        c1 += 1
        c2 += 1

    lcss += local_cs
    return max(l1, l2) - lcss


def similarity_ratio(s1: Optional[str], s2: Optional[str]) -> float:
    """
    Calculates similarity ratio between 0.0 (completely different) and 1.0 (identical).
    """
    if not s1 and not s2:
        return 1.0
    if not s1 or not s2:
        return 0.0
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = sift4_simplest_distance(s1.lower(), s2.lower(), max_offset=5)
    return max(0.0, 1.0 - (dist / max_len))
