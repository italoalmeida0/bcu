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
