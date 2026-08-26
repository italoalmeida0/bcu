"""
Confidence calculation and scoring engine for remnant detection.
Ported from BCU's ConfidenceGenerators and ConfidenceRecords.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Tuple
from bcu.models import ApplicationEntry, ConfidenceLevel
from bcu.utils.sift4 import sift4_simplest_distance, similarity_ratio


import re

CLEAN_NAME_REGEX = re.compile(
    r"\s*(\([^)]*(?:64-bit|32-bit|x64|x86|arm64|store app)[^)]*\)|\[[^\]]*(?:64-bit|32-bit|x64|x86|arm64)[^\]]*\]|v?\d+(?:\.\d+)+)\s*",
    re.IGNORECASE,
)


class ConfidenceCalculator:
    """Calculates confidence scores and reasons for detected junk items."""

    @classmethod
    def clean_name(cls, name: str) -> str:
        """Strips architecture and version tags from application names."""
        cleaned = CLEAN_NAME_REGEX.sub(" ", name)
        return re.sub(r"\s+", " ", cleaned).strip().lower()

    @classmethod
    def match_string_to_product(cls, app: ApplicationEntry, candidate_name: str) -> int:
        """
        Calculates similarity metric matching candidate_name to app.display_name.
        Returns:
            -1 if no match
             0 if perfect match
             1..N depending on edit distance
        """
        product_name = app.display_name_trimmed.lower()
        clean_prod = cls.clean_name(product_name)
        candidate = candidate_name.replace("_", " ").strip().lower()
        clean_cand = cls.clean_name(candidate)

        min_len = min(len(clean_prod), len(clean_cand))
        if min_len <= 3:
            return -1

        # Direct exact match on raw or clean name
        if product_name == candidate or clean_prod == clean_cand:
            return 0

        # Direct containment of clean names
        if clean_prod == candidate or clean_cand == product_name:
            return 0

        # Check sift4 distance on clean names
        dist = sift4_simplest_distance(clean_prod, clean_cand, max_offset=2)
        if dist <= 1:
            return dist

        # If product name starts with or contains company name, strip it and test again
        publisher = (app.publisher or "").lower().strip()
        if len(publisher) > 3 and publisher in clean_prod:
            trimmed_prod = clean_prod.replace(publisher, "").strip()
            if len(trimmed_prod) > 3:
                trimmed_dist = sift4_simplest_distance(trimmed_prod, clean_cand, max_offset=2)
                if trimmed_dist <= 1:
                    return trimmed_dist
                if trimmed_prod == clean_cand:
                    return 0

        # Check substring inclusion
        if clean_cand in clean_prod or clean_prod in clean_cand:
            return 1

        # Cutoff if distance is small relative to string length
        if dist <= min_len / 3:
            return dist

        return -1

    @classmethod
    def evaluate_confidence(
        cls,
        app: ApplicationEntry,
        item_name: str,
        item_parent_path: Optional[str] = None,
        depth_level: int = 0,
        is_registry_key: bool = False,
        is_empty_dir: bool = False,
        has_executables: bool = False,
        is_still_used_by_other: bool = False,
    ) -> Tuple[ConfidenceLevel, int, List[str]]:
        """
        Evaluates the confidence score and reasons for a detected junk candidate.
        """
        score = 0
        reasons: List[str] = []

        # 1. Product Name Matching
        match_metric = cls.match_string_to_product(app, item_name)
        if match_metric == 0:
            score += 6
            reasons.append("Product name perfect match (+6)")
        elif match_metric == 1:
            score += 4
            reasons.append("Product name close match (+4)")
        elif match_metric >= 2:
            score -= 1
            reasons.append("Product name partial/dodgy match (-1)")
        else:
            # Check if candidate matches publisher exactly
            pub = (app.publisher or "").lower().strip()
            if pub and len(pub) > 3 and pub == item_name.lower().strip():
                score += 2
                reasons.append("Matches publisher name (+2)")
            else:
                return ConfidenceLevel.UNKNOWN, -10, ["No valid product name or publisher match"]

        # 2. Path Depth Level Penalty
        depth_penalty = abs(depth_level) * 2
        if depth_penalty > 0:
            score -= depth_penalty
            reasons.append(f"Deeper folder depth penalty (-{depth_penalty})")

        # 3. Publisher parent directory match (e.g. Adobe\Photoshop)
        if item_parent_path:
            parent_name = Path(item_parent_path).name.lower()
            pub = (app.publisher or "").lower()
            if pub and len(parent_name) > 3 and parent_name in pub:
                score += 4
                reasons.append("Parent folder matches company name (+4)")

        # 4. Registry Key Bonus
        if is_registry_key:
            score += 2
            reasons.append("Registry uninstaller/software subkey (+2)")

        # 5. Empty Directory Bonus
        if is_empty_dir:
            score += 3
            reasons.append("Directory is empty (+3)")

        # 6. Executables Present (might belong to other software)
        if has_executables:
            score -= 4
            reasons.append("Executables are present in folder (-4)")

        # 7. Similar named or active app collision penalty
        if is_still_used_by_other:
            score -= 6
            reasons.append("Folder name may be used by another installed app (-6)")

        # Map score to ConfidenceLevel
        level = cls.score_to_level(score)
        return level, score, reasons

    @staticmethod
    def score_to_level(score: int) -> ConfidenceLevel:
        """Maps integer score to discrete ConfidenceLevel."""
        if score < 0:
            return ConfidenceLevel.BAD
        elif score < 2:
            return ConfidenceLevel.QUESTIONABLE
        elif score < 5:
            return ConfidenceLevel.GOOD
        return ConfidenceLevel.VERY_GOOD
