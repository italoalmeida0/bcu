"""
Uninstaller execution engine: process supervision, locking process termination,
timeout handling, and stall detection.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional, Set, Tuple
import psutil

from bcu.config import (
    DEFAULT_PROCESS_TIMEOUT_SEC,
    MSIEXEC_BUSY_RETRY_INTERVAL_SEC,
    MSIEXEC_MAX_RETRIES,
)
from bcu.junk.cleaner import JunkCleaner
from bcu.junk.confidence import ConfidenceCalculator
from bcu.junk.finders import _get_safe_install_location, _path_contains_location
from bcu.models import (
    ApplicationEntry,
    ConfidenceLevel,
    JunkItem,
    UninstallResult,
    UninstallStatus,
    UninstallerType,
)
from bcu.utils.platform import IS_WINDOWS, delete_path_safe, run_powershell_command

_PROTECTED_PROCESS_NAMES = {
    "system",
    "registry",
    "memory compression",
    "idle",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "explorer.exe",
    "conhost.exe",
    "windowsterminal.exe",
    "wt.exe",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "python.exe",
    "pythonw.exe",
    "uv.exe",
    "bcu.exe",
    "wudo.exe",
    "msiexec.exe",
    "trustedinstaller.exe",
    "msmpeng.exe",
}


def _protected_ancestor_pids() -> Set[int]:
    """Returns PIDs of the current process and all ancestor processes so BCU never kills itself or its host terminal."""
    pids: Set[int] = {os.getpid()}
    try:
        proc = psutil.Process(os.getpid())
        for parent in proc.parents():
            pids.add(parent.pid)
    except Exception:
        pass
    return pids


class UninstallerExecutor:
    """Executes uninstallation commands and manages process lifecycle."""

    @classmethod
    def terminate_locking_processes(
        cls,
        app: ApplicationEntry,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> List[str]:
        """Finds and safely terminates running processes belonging to the target application."""
        killed_names: List[str] = []
        safe_loc = _get_safe_install_location(app)
        clean_app = ConfidenceCalculator.clean_name(app.display_name_trimmed)
        app_name_clean = "".join(c for c in clean_app if c.isalnum())
        protected_pids = _protected_ancestor_pids()

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pid = proc.info.get("pid")
                if pid in protected_pids:
                    continue

                p_exe = proc.info.get("exe") or ""
                p_name = (proc.info.get("name") or "").lower()
                if not p_name or p_name in _PROTECTED_PROCESS_NAMES:
                    continue

                p_stem = Path(p_name).stem.lower()
                p_stem_clean = "".join(c for c in p_stem if c.isalnum())

                # 1. Exact path boundary match inside application's safe install directory
                is_in_loc = bool(safe_loc and p_exe and _path_contains_location(p_exe, safe_loc))

                # 2. Exact stem match against cleaned app name (never substring-match short system procs!)
                is_name_match = bool(
                    len(app_name_clean) >= 5
                    and len(p_stem_clean) >= 5
                    and (p_stem_clean == app_name_clean)
                )

                if is_in_loc or is_name_match:
                    if progress_callback:
                        progress_callback(f"Terminating locking process: {proc.info['name']} (PID: {pid})...")
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
    def _run_post_uninstall_junk_cleanup(
        cls,
        app: ApplicationEntry,
        all_apps: Optional[List[ApplicationEntry]],
        deep_junk: bool,
        backup_registry: bool,
        junk_min_confidence: ConfidenceLevel,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> List[JunkItem]:
        """Scans and cleans leftover remnants after a successful uninstall."""
        if progress_callback:
            progress_callback(f"Deep scanning leftover junk for {app.display_name}...")
        junk_list = JunkCleaner.scan_app_junk(
            app,
            all_apps=all_apps,
            min_confidence=junk_min_confidence,
            deep_scan=deep_junk,
        )
        if not junk_list:
            return []
        if progress_callback:
            progress_callback(f"Cleaning {len(junk_list)} leftover junk items...")
        clean_results = JunkCleaner.clean_junk(
            junk_list,
            dry_run=False,
            backup_registry=backup_registry,
        )
        return [item for item, ok, _ in clean_results if ok]

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
        all_apps: Optional[List[ApplicationEntry]] = None,
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
                from bcu.enrichers.quiet_args import enrich_app_quiet_string
                enrich_app_quiet_string(app)
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
                    all_apps=all_apps,
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
            cleaned_items: List[JunkItem] = []
            if success and clean_junk:
                cleaned_items = cls._run_post_uninstall_junk_cleanup(
                    app, all_apps, deep_junk, backup_registry, junk_min_confidence, progress_callback
                )
            duration = time.time() - start_time
            if success:
                return UninstallResult(
                    app_id=app.id,
                    app_name=app.display_name_trimmed,
                    status=UninstallStatus.COMPLETED,
                    exit_code=0,
                    command_executed=cmd,
                    duration_sec=duration,
                    junk_cleaned_count=len(cleaned_items),
                    cleaned_junk_items=cleaned_items,
                )
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
            pkg_full = str(app.raw_metadata.get("PackageFullName") or app.id.removeprefix("store:")).replace("'", "''")
            ps_cmd = f"Remove-AppxPackage -Package '{pkg_full}'"
            code, _out, err = run_powershell_command(ps_cmd, timeout_sec=timeout_sec)
            cleaned_items = []
            if code == 0 and clean_junk:
                cleaned_items = cls._run_post_uninstall_junk_cleanup(
                    app, all_apps, deep_junk, backup_registry, junk_min_confidence, progress_callback
                )
            duration = time.time() - start_time
            if code == 0:
                return UninstallResult(
                    app_id=app.id,
                    app_name=app.display_name_trimmed,
                    status=UninstallStatus.COMPLETED,
                    exit_code=0,
                    command_executed=ps_cmd,
                    duration_sec=duration,
                    junk_cleaned_count=len(cleaned_items),
                    cleaned_junk_items=cleaned_items,
                )
            return UninstallResult(
                app_id=app.id,
                app_name=app.display_name_trimmed,
                status=UninstallStatus.FAILED,
                exit_code=code,
                command_executed=ps_cmd,
                error_message=err or "Store app removal failed",
                duration_sec=duration,
            )

        # 5. Protocol URI handlers (e.g. steam://uninstall/<id>)
        if cmd.lower().startswith("steam://"):
            if progress_callback:
                progress_callback(f"Launching Steam URI: {cmd}")
            try:
                if IS_WINDOWS and hasattr(os, "startfile"):
                    os.startfile(cmd)  # type: ignore[attr-defined]
                    duration = time.time() - start_time
                    return UninstallResult(
                        app_id=app.id,
                        app_name=app.display_name_trimmed,
                        status=UninstallStatus.COMPLETED,
                        exit_code=0,
                        command_executed=cmd,
                        duration_sec=duration,
                    )
                return UninstallResult(
                    app_id=app.id,
                    app_name=app.display_name_trimmed,
                    status=UninstallStatus.FAILED,
                    exit_code=1,
                    command_executed=cmd,
                    error_message="Protocol URI launch is only supported on Windows",
                    duration_sec=time.time() - start_time,
                )
            except Exception as e:
                return UninstallResult(
                    app_id=app.id,
                    app_name=app.display_name_trimmed,
                    status=UninstallStatus.FAILED,
                    exit_code=1,
                    command_executed=cmd,
                    error_message=f"Failed to launch URI: {e}",
                    duration_sec=time.time() - start_time,
                )

        # 6. Process execution & monitoring (with MSIEXEC 1618 busy retry)
        if progress_callback:
            progress_callback(f"Executing: {cmd}")

        attempts = MSIEXEC_MAX_RETRIES if app.uninstaller_type == UninstallerType.MSIEXEC else 1
        exit_code = 1
        error_msg: Optional[str] = None
        for attempt in range(1, attempts + 1):
            exit_code, error_msg = cls._run_and_monitor_process(cmd, timeout_sec, progress_callback)
            if app.uninstaller_type == UninstallerType.MSIEXEC and exit_code == 1618 and attempt < attempts:
                if progress_callback:
                    progress_callback(
                        f"Windows Installer busy (exit 1618), retrying ({attempt}/{attempts})..."
                    )
                time.sleep(MSIEXEC_BUSY_RETRY_INTERVAL_SEC)
                continue
            break

        duration = time.time() - start_time

        # Check standard acceptable exit codes (3010 = reboot required, 1605 = already uninstalled)
        is_success = False
        if exit_code == 0:
            is_success = True
        elif app.uninstaller_type == UninstallerType.MSIEXEC and exit_code in (0, 3010, 1605):
            is_success = True
        elif app.uninstaller_type == UninstallerType.NSIS and exit_code in (0, 1627):
            is_success = True

        status = UninstallStatus.COMPLETED if is_success else UninstallStatus.FAILED

        # 7. Post-uninstall junk cleanup
        cleaned_items = []
        if is_success and clean_junk:
            cleaned_items = cls._run_post_uninstall_junk_cleanup(
                app, all_apps, deep_junk, backup_registry, junk_min_confidence, progress_callback
            )

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
        """Spawns uninstaller process, drains stdout/stderr safely (preventing pipe deadlocks), and enforces timeouts."""
        try:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except Exception as e:
            return 1, f"Failed to launch process: {e}"

        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []

        def _drain(stream, bucket: List[str]) -> None:
            if stream is None:
                return
            try:
                for line in iter(stream.readline, ""):
                    bucket.append(line)
            except Exception:
                pass
            finally:
                try:
                    stream.close()
                except Exception:
                    pass

        t_out = threading.Thread(target=_drain, args=(proc.stdout, stdout_chunks), daemon=True)
        t_err = threading.Thread(target=_drain, args=(proc.stderr, stderr_chunks), daemon=True)
        t_out.start()
        t_err.start()

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
                t_out.join(timeout=1.0)
                t_err.join(timeout=1.0)
                return -1, f"Uninstaller timed out after {timeout_sec} seconds"

            time.sleep(0.25)

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

        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)

        exit_code = proc.returncode if proc.returncode is not None else 1
        error_msg = None
        if exit_code != 0:
            stderr_text = "".join(stderr_chunks).strip()
            stdout_text = "".join(stdout_chunks).strip()
            detail = stderr_text or stdout_text
            error_msg = detail[:500] if detail else f"Process exited with code {exit_code}"

        return exit_code, error_msg
