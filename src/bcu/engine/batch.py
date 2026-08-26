"""
Batch uninstallation queue manager with concurrency control and MSI lock serialization.
"""

from __future__ import annotations

import time
from typing import Callable, List, Optional
from bcu.engine.uninstaller import UninstallerExecutor
from bcu.models import (
    ApplicationEntry,
    ConfidenceLevel,
    UninstallResult,
    UninstallStatus,
    UninstallerType,
)
from bcu.utils.platform import create_system_restore_point


class BatchUninstallQueue:
    """Manages batch uninstallation execution across multiple applications."""

    def __init__(
        self,
        apps: List[ApplicationEntry],
        prefer_quiet: bool = True,
        dry_run: bool = False,
        clean_junk: bool = True,
        deep_junk: bool = True,
        kill_running: bool = False,
        backup_registry: bool = True,
        create_restore_point: bool = False,
        junk_min_confidence: ConfidenceLevel = ConfidenceLevel.GOOD,
        timeout_sec: int = 300,
    ):
        self.apps = apps
        self.prefer_quiet = prefer_quiet
        self.dry_run = dry_run
        self.clean_junk = clean_junk
        self.deep_junk = deep_junk
        self.kill_running = kill_running
        self.backup_registry = backup_registry
        self.create_restore_point = create_restore_point
        self.junk_min_confidence = junk_min_confidence
        self.timeout_sec = timeout_sec
        self.results: List[UninstallResult] = []

    def run(
        self,
        on_app_start: Optional[Callable[[ApplicationEntry, int, int], None]] = None,
        on_app_finish: Optional[Callable[[UninstallResult, int, int], None]] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> List[UninstallResult]:
        """Executes uninstallation for all queued apps in order."""
        total = len(self.apps)
        self.results.clear()

        # Optional: create System Restore Point before batch
        if self.create_restore_point and not self.dry_run and total > 0:
            if on_progress:
                on_progress("Creating Windows System Restore Point...")
            desc = f"BCU Uninstall: {self.apps[0].display_name}" if total == 1 else f"BCU Batch Uninstall ({total} apps)"
            success, msg = create_system_restore_point(desc)
            if on_progress:
                on_progress(f"Restore Point: {msg}")

        for index, app in enumerate(self.apps, 1):
            if on_app_start:
                on_app_start(app, index, total)

            result = UninstallerExecutor.execute_uninstall(
                app=app,
                prefer_quiet=self.prefer_quiet,
                dry_run=self.dry_run,
                clean_junk=self.clean_junk,
                deep_junk=self.deep_junk,
                kill_running=self.kill_running,
                backup_registry=self.backup_registry,
                junk_min_confidence=self.junk_min_confidence,
                timeout_sec=self.timeout_sec,
                progress_callback=on_progress,
            )

            self.results.append(result)

            if on_app_finish:
                on_app_finish(result, index, total)

            if not self.dry_run and index < total:
                time.sleep(1.0)

        return self.results
