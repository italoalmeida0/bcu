"""
Unit tests for batch uninstallation queue and dry-run execution.
"""

from bcu.engine.batch import BatchUninstallQueue
from bcu.engine.uninstaller import UninstallerExecutor
from bcu.models import ApplicationEntry, UninstallStatus, UninstallerType


def test_dry_run_uninstallation(sample_inno_app: ApplicationEntry):
    result = UninstallerExecutor.execute_uninstall(
        app=sample_inno_app,
        dry_run=True,
        prefer_quiet=True,
    )
    assert result.status == UninstallStatus.COMPLETED
    assert result.exit_code == 0
    assert result.command_executed is not None
    assert "/VERYSILENT" in result.command_executed


def test_protected_app_rejection(sample_msi_app: ApplicationEntry):
    result = UninstallerExecutor.execute_uninstall(
        app=sample_msi_app,
        dry_run=False,
    )
    assert result.status == UninstallStatus.FAILED
    assert "protected" in (result.error_message or "").lower()


def test_batch_queue_dry_run(sample_inno_app: ApplicationEntry):
    queue = BatchUninstallQueue(
        apps=[sample_inno_app],
        dry_run=True,
        prefer_quiet=True,
    )
    results = queue.run()
    assert len(results) == 1
    assert results[0].status == UninstallStatus.COMPLETED


def test_monitor_waits_for_detached_child_process():
    """Simulates NSIS/Inno behavior where parent spawns a child and exits immediately."""
    import sys
    import time

    # Parent spawns a child that sleeps 0.9s, then parent exits immediately with 0
    child_code = "import time; time.sleep(0.9)"
    parent_code = (
        f"import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        f"time.sleep(0.25)"
    )
    cmd = f'"{sys.executable}" -c "{parent_code}"'
    t0 = time.perf_counter()
    code, err = UninstallerExecutor._run_and_monitor_process(cmd, timeout_sec=10)
    elapsed = time.perf_counter() - t0
    assert code == 0
    assert err is None
    assert elapsed >= 0.85, f"Returned too early ({elapsed:.2f}s) before child process exited!"
