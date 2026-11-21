"""
Unit and responsive layout tests for the Textual TUI Application (BcuApp).
Verifies zero overlaps, unclipped controls, centered modals, keybinding isolation,
and Inspector synchronization across small (80x24) and standard (120x30) terminals.
"""

import pytest
from textual.widgets import DataTable, Input

from bcu.models import ApplicationEntry, UninstallerType
from bcu.tui.app import BcuApp
from bcu.tui.screens.audit_modal import AuditModal
from bcu.tui.screens.junk_modal import JunkModal
from bcu.tui.screens.uninstall_modal import UninstallModal
from bcu.tui.widgets.header_stats import HeaderStatsBanner
from bcu.tui.widgets.inspector import InspectorSidebar


@pytest.mark.asyncio
async def test_tui_app_composition(sample_inno_app: ApplicationEntry, sample_store_app: ApplicationEntry, monkeypatch):
    monkeypatch.setattr(BcuApp, "load_applications_async", lambda self, force_refresh=False: None)
    app = BcuApp()
    async with app.run_test(size=(120, 30)) as pilot:
        assert app.query_one(HeaderStatsBanner) is not None
        assert app.query_one(InspectorSidebar) is not None
        assert app.query_one(DataTable) is not None
        assert app.query_one("#search-input", Input) is not None

        app.all_apps = [sample_inno_app, sample_store_app]
        app.apply_filters_and_render()
        await pilot.pause()

        table = app.query_one(DataTable)
        assert table.row_count == 2

        # Row highlight must synchronize the InspectorSidebar
        table.focus()
        await pilot.press("down")
        await pilot.pause()
        insp_name = str(app.query_one("#insp-name").render())
        assert "MSN Weather" in insp_name

        # Search filtering
        search_input = app.query_one("#search-input", Input)
        search_input.value = "Notepad"
        await pilot.pause()
        assert table.row_count == 1

        # Toggle selection
        table.move_cursor(row=0)
        app.action_toggle_selection()
        await pilot.pause()
        assert sample_inno_app.id in app.selected_ids

        # Select all toggles off when all visible apps are selected
        app.action_toggle_select_all()
        await pilot.pause()
        assert len(app.selected_ids) == 0

        # Select all toggles on for visible apps
        app.action_toggle_select_all()
        await pilot.pause()
        assert len(app.selected_ids) == 1

        # Empty search clears inspector cleanly
        search_input.value = "DefinitelyNoSuchApp999"
        await pilot.pause()
        assert table.row_count == 0
        assert "No application selected" in str(app.query_one("#insp-name").render())


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(80, 24), (100, 30), (120, 30)])
async def test_tui_responsive_layout_and_modals(size, monkeypatch):
    monkeypatch.setattr(BcuApp, "load_applications_async", lambda self, force_refresh=False: None)
    apps = [
        ApplicationEntry(
            id=f"reg:hklm:app{i}",
            display_name=f"Sample [Beta] Application {i} (64-bit)",
            display_version="12.34.5678",
            publisher="Example Software Corporation",
            install_location=f"C:\\Program Files\\SampleApp{i}",
            uninstall_string=f'"C:\\Program Files\\SampleApp{i}\\unins000.exe"',
            quiet_uninstall_string=f'"C:\\Program Files\\SampleApp{i}\\unins000.exe" /VERYSILENT',
            estimated_size_bytes=120_000_000,
            uninstaller_type=UninstallerType.INNO_SETUP,
            is_64_bit=True,
        )
        for i in range(6)
    ]

    w_term, h_term = size
    app = BcuApp()
    async with app.run_test(size=size) as pilot:
        app.all_apps = apps
        app.apply_filters_and_render()
        await pilot.pause()

        # Stat card values are not clipped by borders
        stat_card = app.query_one("#stat-total")
        stat_val = app.query_one("#stat-total-val")
        assert stat_val.region.bottom <= stat_card.region.bottom

        # Type selector never wraps vertically
        assert app.query_one("#filter-type").region.height == 3

        # DataTable fits width without forced horizontal scrollbar overflow
        tbl = app.query_one("#app-table", DataTable)
        assert tbl.virtual_size.width <= tbl.region.width
        assert tbl.region.height >= 12

        # UninstallModal: centered, zero log/button overlap, keybinding isolation & Escape close
        um = UninstallModal(target_apps=apps[:3], all_apps=apps)
        app.push_screen(um)
        await pilot.pause()
        cont = um.query_one(".modal-container")
        log = um.query_one("#uninstall-log")
        btns = um.query_one(".modal-buttons")
        assert cont.region.x > 0 and cont.region.y > 0
        assert log.region.bottom <= btns.region.y
        assert btns.region.bottom <= cont.region.bottom <= h_term

        # Space on checkbox must toggle checkbox and NOT leak to main app selection
        cb = um.query_one("#opt-quiet")
        cb.focus()
        await pilot.pause()
        before_val = cb.value
        await pilot.press("space")
        await pilot.pause()
        assert cb.value is (not before_val)
        assert len(app.selected_ids) == 0

        # Pressing 'v' in modal must NOT stack AuditModal on top
        await pilot.press("v")
        await pilot.pause()
        assert len(app.screen_stack) == 2

        # Escape closes modal cleanly
        await pilot.press("escape")
        await pilot.pause()
        assert len(app.screen_stack) == 1

        # JunkModal (Orphaned Leftovers mode): geometry, zero overlap & installed-app block
        jm = JunkModal(all_apps=apps)
        jm.scan_junk_task = lambda: None
        app.push_screen(jm)
        await pilot.pause()
        assert jm.query_one(".junk-search-bar").region.bottom <= jm.query_one("#junk-table").region.y
        assert jm.query_one("#junk-table").region.bottom <= jm.query_one("#junk-log").region.y
        assert jm.query_one("#junk-log").region.bottom <= jm.query_one(".modal-buttons").region.y
        assert jm.query_one(".modal-buttons").region.bottom <= jm.query_one(".modal-container").region.bottom <= h_term

        # Trying to search an active installed app as "removed" must be blocked
        rem_input = jm.query_one("#junk-removed-input", Input)
        rem_input.value = "Sample [Beta] Application 0"
        jm._trigger_removed_app_scan()
        await pilot.pause()
        assert len(jm.junk_items) == 0

        await pilot.press("escape")
        await pilot.pause()

        am = AuditModal(apps=apps)
        am.run_audit_task = lambda online=False: None
        app.push_screen(am)
        await pilot.pause()
        assert am.query_one("#audit-table").region.bottom <= am.query_one(".modal-buttons").region.y
        await pilot.press("escape")
        await pilot.pause()
        assert len(app.screen_stack) == 1
