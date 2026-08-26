"""
Uninstaller execution engine: process supervision, locking process termination,
timeout handling, and stall detection.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from typing import Callable, List, Optional, Tuple
import psutil

from bcu.config import (
    DEFAULT_PROCESS_TIMEOUT_SEC,
    DEFAULT_STALL_IDLE_TIMEOUT_SEC,
)
from bcu.junk.cleaner import JunkCleaner
from bcu.models import (
    ApplicationEntry,
    ConfidenceLevel,
    JunkItem,
    UninstallResult,
    UninstallStatus,
    UninstallerType,
)
from bcu.utils.platform import delete_path_safe, run_powershell_command


class UninstallerExecutor:
    """Executes uninstallation commands and manages process lifecycle."""

    @classmethod
    def terminate_locking_processes(
        cls,
        app: ApplicationEntry,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> List[str]:
        """Finds and terminates any running processes associated with the application."""
        killed_names = []
        loc = app.install_location.lower() if app.install_location else None
        app_name_clean = "".join(c for c in app.display_name_trimmed.lower() if c.isalnum())

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                p_exe = (proc.info.get("exe") or "").lower()
                p_name = (proc.info.get("name") or "").lower()
                p_name_clean = "".join(c for c in p_name if c.isalnum())

                # Check if executable resides inside application directory
                is_in_loc = bool(loc and loc in p_exe and len(loc) > 4)
                is_name_match = bool(
                    len(app_name_clean) > 4
                    and (app_name_clean in p_name_clean or p_name_clean in app_name_clean)
                    and p_name not in ("explorer.exe", "svchost.exe", "powershell.exe", "cmd.exe", "python.exe", "uv.exe")
                )

                if is_in_loc or is_name_match:
                    if progress_callback:
                        progress_callback(f"Terminating locking process: {proc.info['name']} (PID: {proc.info['pid']})...")
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except psutil.TimeoutExpired:
                        proc.kill()
                    killed_names.append(proc.info["name"])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return killed_names

    @classmethod
    def execute_uninstall(
        cls,
        app: ApplicationEntry,
        prefer_quiet: bool = True,
        dry_run: bool = False,
        clean_junk: bool = True,
        deep_junk: bool = True,
        backup_registry: bool = True,
        kill_running: bool = False,
        junk_min_confidence: ConfidenceLevel = ConfidenceLevel.GOOD,
        timeout_sec: int = DEFAULT_PROCESS_TIMEOUT_SEC,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> UninstallResult:
        """Executes uninstallation for a single ApplicationEntry."""
        start_time = time.time()

        if app.is_protected:
            return UninstallResult(
                app_id=app.id,
                app_name=app.display_name_trimmed,
                status=UninstallStatus.FAILED,
                error_message="Cannot uninstall protected system application",
                duration_sec=0.0,
            )

        # Optional: Kill locking processes before uninstall
        if kill_running and not dry_run:
            cls.terminate_locking_processes(app, progress_callback)

        # 1. Determine command string
        cmd = None
        if prefer_quiet:
            if not app.quiet_uninstall_string:
                from bcu.enrichers.quiet_args import enrich_app_quiet_string
                enrich_app_quiet_string(app)
            if app.quiet_uninstall_possible:
                cmd = app.quiet_uninstall_string
        
        if not cmd:
            if app.uninstall_string:
                cmd = app.uninstall_string
            elif app.uninstaller_type == UninstallerType.STORE_APP:
                cmd = app.quiet_uninstall_string
            elif app.uninstaller_type == UninstallerType.SIMPLE_DELETE and app.install_location:
                cmd = f"[DELETE] {app.install_location}"

        if not cmd:
            return UninstallResult(
                app_id=app.id,
                app_name=app.display_name_trimmed,
                status=UninstallStatus.INVALID,
                error_message="No valid uninstall string or uninstaller found",
                duration_sec=0.0,
            )

        # 2. DRY-RUN handling
        if dry_run:
            junk_items: List[JunkItem] = []
            if clean_junk:
                junk_items = JunkCleaner.scan_app_junk(
                    app,
                    min_confidence=junk_min_confidence,
                    deep_scan=deep_junk,
                )

            return UninstallResult(
                app_id=app.id,
                app_name=app.display_name_trimmed,
                status=UninstallStatus.COMPLETED,
                exit_code=0,
                command_executed=cmd,
                duration_sec=0.0,
                junk_cleaned_count=len(junk_items),
                cleaned_junk_items=junk_items,
            )

        # 3. SimpleDelete fallback
        if app.uninstaller_type == UninstallerType.SIMPLE_DELETE and app.install_location:
            if progress_callback:
                progress_callback(f"Deleting directory {app.install_location}...")
            success, msg = delete_path_safe(app.install_location)
            duration = time.time() - start_time
            if success:
                return UninstallResult(
                    app_id=app.id,
                    app_name=app.display_name_trimmed,
                    status=UninstallStatus.COMPLETED,
                    exit_code=0,
                    command_executed=cmd,
                    duration_sec=duration,
                )
            else:
                return UninstallResult(
                    app_id=app.id,
                    app_name=app.display_name_trimmed,
                    status=UninstallStatus.FAILED,
                    exit_code=1,
                    command_executed=cmd,
                    error_message=f"Directory deletion failed: {msg}",
                    duration_sec=duration,
                )

        # 4. Store App PowerShell execution
        if app.uninstaller_type == UninstallerType.STORE_APP:
            if progress_callback:
                progress_callback(f"Removing Store Package {app.display_name}...")
            pkg_full = app.raw_metadata.get("PackageFullName") or app.id.replace("store:", "")
            ps_cmd = f"Remove-AppxPackage -Package '{pkg_full}'"
            code, out, err = run_powershell_command(ps_cmd, timeout_sec=timeout_sec)
            duration = time.time() - start_time

            if code == 0:
                return UninstallResult(
                    app_id=app.id,
                    app_name=app.display_name_trimmed,
                    status=UninstallStatus.COMPLETED,
                    exit_code=0,
                    command_executed=ps_cmd,
                    duration_sec=duration,
                )
            else:
                return UninstallResult(
                    app_id=app.id,
                    app_name=app.display_name_trimmed,
                    status=UninstallStatus.FAILED,
                    exit_code=code,
                    command_executed=ps_cmd,
                    error_message=err or "Store app removal failed",
                    duration_sec=duration,
                )

        # 5. Process execution & monitoring
        if progress_callback:
            progress_callback(f"Executing: {cmd}")

        exit_code, error_msg = cls._run_and_monitor_process(cmd, timeout_sec, progress_callback)
        duration = time.time() - start_time

        # Check standard acceptable exit codes
        is_success = False
        if exit_code == 0:
            is_success = True
        elif app.uninstaller_type == UninstallerType.MSIEXEC and exit_code in (0, 3010):
            is_success = True
        elif app.uninstaller_type == UninstallerType.NSIS and exit_code in (0, 1627):
            is_success = True

        status = UninstallStatus.COMPLETED if is_success else UninstallStatus.FAILED

        # 6. Post-uninstall junk cleanup
        cleaned_items: List[JunkItem] = []
        if is_success and clean_junk:
            if progress_callback:
                progress_callback(f"Deep scanning leftover junk for {app.display_name}...")
            junk_list = JunkCleaner.scan_app_junk(
                app,
                min_confidence=junk_min_confidence,
                deep_scan=deep_junk,
            )
            if junk_list:
                if progress_callback:
                    progress_callback(f"Cleaning {len(junk_list)} leftover junk items...")
                clean_results = JunkCleaner.clean_junk(
                    junk_list,
                    dry_run=False,
                    backup_registry=backup_registry,
                )
                cleaned_items = [item for item, ok, _ in clean_results if ok]

        return UninstallResult(
            app_id=app.id,
            app_name=app.display_name_trimmed,
            status=status,
            exit_code=exit_code,
            duration_sec=duration,
            command_executed=cmd,
            error_message=error_msg if not is_success else None,
            junk_cleaned_count=len(cleaned_items),
            cleaned_junk_items=cleaned_items,
        )

    @classmethod
    def _run_and_monitor_process(
        cls,
        cmd: str,
        timeout_sec: int,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Tuple[int, Optional[str]]:
        """Spawns uninstaller process and monitors child processes and timeouts."""
        try:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception as e:
            return 1, f"Failed to launch process: {e}"

        start_time = time.time()
        parent_ps = None
        try:
            parent_ps = psutil.Process(proc.pid)
        except Exception:
            pass

        while proc.poll() is None:
            time_elapsed = time.time() - start_time
            if time_elapsed > timeout_sec:
                try:
                    if parent_ps:
                        for child in parent_ps.children(recursive=True):
                            try:
                                child.kill()
                            except Exception:
                                pass
                        parent_ps.kill()
                    proc.kill()
                except Exception:
                    pass
                return -1, f"Uninstaller timed out after {timeout_sec} seconds"

            time.sleep(0.5)

        if parent_ps:
            try:
                children = parent_ps.children(recursive=True)
                for child in children:
                    try:
                        child.wait(timeout=5)
                    except (psutil.TimeoutExpired, psutil.NoSuchProcess):
                        pass
            except Exception:
                pass

        exit_code = proc.returncode
        error_msg = None
        if exit_code != 0:
            _, stderr = proc.communicate()
            error_msg = stderr.strip() if stderr else f"Process exited with code {exit_code}"

        return exit_code, error_msg
