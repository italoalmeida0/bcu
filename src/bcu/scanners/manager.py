"""
Scanner Manager orchestrates application discovery across all available scanners,
deduplicates results, and enriches discovered metadata.
"""

from __future__ import annotations

import concurrent.futures
import re
import threading
import time
from typing import Callable, List, Optional
from bcu.config import PROTECTED_PUBLISHERS
from bcu.enrichers.detector import enrich_app_uninstaller_type
from bcu.enrichers.quiet_args import enrich_app_quiet_string
from bcu.enrichers.size import enrich_app_size
from bcu.models import ApplicationEntry, FilterCriteria
from bcu.scanners.base import BaseScanner
from bcu.scanners.directory import DirectoryScanner
from bcu.scanners.oculus import OculusScanner
from bcu.scanners.package_mgr import ChocolateyScanner, ScoopScanner, WingetScanner
from bcu.scanners.registry import RegistryScanner
from bcu.scanners.steam import SteamScanner
from bcu.scanners.store_app import StoreAppScanner
from bcu.scanners.windows_feature import WindowsFeatureScanner
from bcu.scanners.win_update import WindowsUpdateScanner
from bcu.utils.platform import normalize_path


class ScannerManager:
    """Manages multi-source application scanning, deduplication, and enrichment."""

    _cached_default_apps: Optional[List[ApplicationEntry]] = None
    _cache_timestamp: float = 0.0
    _cache_lock = threading.Lock()
    DEFAULT_CACHE_TTL_SEC: float = 300.0  # 5 minutes cache TTL

    def __init__(self, scanners: Optional[List[BaseScanner]] = None):
        self._custom_scanners = scanners is not None
        self.scanners: List[BaseScanner] = scanners or [
            RegistryScanner(),
            StoreAppScanner(),
            SteamScanner(),
            WingetScanner(),
            ScoopScanner(),
            ChocolateyScanner(),
            OculusScanner(),
            WindowsFeatureScanner(),
            WindowsUpdateScanner(),
            DirectoryScanner(),
        ]

    @classmethod
    def invalidate_cache(cls) -> None:
        """Invalidates the in-memory scanned applications cache."""
        with cls._cache_lock:
            cls._cached_default_apps = None
            cls._cache_timestamp = 0.0

    def scan_all(
        self,
        progress_callback: Optional[Callable[[str], None]] = None,
        enrich_sizes: bool = False,
        force_refresh: bool = False,
    ) -> List[ApplicationEntry]:
        """Scans all sources concurrently, deduplicates, and enriches metadata with high-performance caching."""
        now = time.time()

        # If using default system scanners and cache is valid, return cached entries instantly
        if not self._custom_scanners and not force_refresh:
            with self.__class__._cache_lock:
                if self.__class__._cached_default_apps is not None:
                    if (now - self.__class__._cache_timestamp) < self.__class__.DEFAULT_CACHE_TTL_SEC:
                        return self.__class__._cached_default_apps

        all_entries: List[ApplicationEntry] = []
        available_scanners = [s for s in self.scanners if s.is_available()]

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(available_scanners) or 1) as executor:
            future_to_scanner = {
                executor.submit(s.scan): s for s in available_scanners
            }
            for future in concurrent.futures.as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                if progress_callback:
                    progress_callback(f"Scanning {scanner.name}...")
                try:
                    entries = future.result()
                    all_entries.extend(entries)
                except Exception:
                    pass

        # Deduplicate & enrich entries
        deduplicated = self._deduplicate_entries(all_entries)

        for entry in deduplicated:
            enrich_app_uninstaller_type(entry)
            enrich_app_quiet_string(entry)
            if enrich_sizes:
                enrich_app_size(entry)

            # Check if protected publisher
            pub_lower = (entry.publisher or "").lower()
            if any(p in pub_lower for p in PROTECTED_PUBLISHERS):
                if entry.is_system_component:
                    entry.is_protected = True

        if not self._custom_scanners:
            with self.__class__._cache_lock:
                self.__class__._cached_default_apps = deduplicated
                self.__class__._cache_timestamp = time.time()

        return deduplicated

    def _deduplicate_entries(self, entries: List[ApplicationEntry]) -> List[ApplicationEntry]:
        """Deduplicates entries prioritizing Registry > StoreApp > Steam/PackageMgr > Directory."""
        seen_names = set()
        seen_locations = set()
        unique: List[ApplicationEntry] = []

        # Sort so highest quality scanners come first
        priority_order = {
            "Registry": 0,
            "StoreApp": 1,
            "Steam": 2,
            "Winget": 3,
            "Scoop": 4,
            "Chocolatey": 5,
            "Oculus": 6,
            "WindowsFeature": 7,
            "WindowsUpdate": 8,
            "Directory": 9,
        }
        sorted_entries = sorted(entries, key=lambda e: priority_order.get(e.source_scanner, 10))

        for entry in sorted_entries:
            norm_name = entry.display_name_trimmed.lower()
            norm_loc = normalize_path(entry.install_location)

            if not norm_name:
                continue

            # Directory scanner items should not duplicate existing registry apps
            if entry.source_scanner == "Directory":
                if norm_name in seen_names or (norm_loc and norm_loc in seen_locations):
                    continue

            seen_names.add(norm_name)
            if norm_loc:
                seen_locations.add(norm_loc)
            unique.append(entry)

        return unique

    @staticmethod
    def filter_entries(entries: List[ApplicationEntry], criteria: FilterCriteria) -> List[ApplicationEntry]:
        """Applies FilterCriteria to a list of ApplicationEntry items."""
        results: List[ApplicationEntry] = []

        for entry in entries:
            # System component check
            if entry.is_system_component and not criteria.include_system:
                continue

            # Protected app check
            if entry.is_protected and not criteria.include_protected:
                continue

            # Quiet only check
            if criteria.has_quiet_only and not entry.quiet_uninstall_possible:
                continue

            # Source scanner check
            if criteria.source_scanner and entry.source_scanner.lower() != criteria.source_scanner.lower():
                continue

            # Uninstaller type check
            if criteria.uninstaller_type and entry.uninstaller_type != criteria.uninstaller_type:
                continue

            # Size checks
            if criteria.min_size_bytes is not None and (
                entry.estimated_size_bytes is None or entry.estimated_size_bytes < criteria.min_size_bytes
            ):
                continue
            if criteria.max_size_bytes is not None and (
                entry.estimated_size_bytes is not None and entry.estimated_size_bytes > criteria.max_size_bytes
            ):
                continue

            # Publisher check
            if criteria.publisher:
                pub = (entry.publisher or "").lower()
                if criteria.publisher.lower() not in pub:
                    continue

            # Query search (supports regex or fuzzy substring)
            if criteria.query:
                q = criteria.query.strip()
                if criteria.regex_match:
                    try:
                        pattern = re.compile(q, re.IGNORECASE)
                        if not (
                            pattern.search(entry.display_name)
                            or pattern.search(entry.id)
                            or pattern.search(entry.publisher or "")
                            or pattern.search(entry.install_location or "")
                        ):
                            continue
                    except re.error:
                        continue
                else:
                    q_lower = q.lower()
                    match_found = (
                        q_lower in entry.display_name.lower()
                        or q_lower in entry.id.lower()
                        or q_lower in (entry.publisher or "").lower()
                        or q_lower in (entry.install_location or "").lower()
                        or q_lower in (entry.uninstall_string or "").lower()
                    )
                    if not match_found:
                        continue

            results.append(entry)

        return results
