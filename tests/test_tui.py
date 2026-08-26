"""
Unit tests for the Textual TUI Application (BcuApp).
"""

import pytest
from bcu.models import ApplicationEntry, UninstallerType
from bcu.tui.app import BcuApp
from bcu.tui.widgets.header_stats import HeaderStatsBanner
from bcu.tui.widgets.inspector import InspectorSidebar
from textual.widgets import DataTable, Input


@pytest.mark.asyncio
async def test_tui_app_composition(sample_inno_app: ApplicationEntry, sample_store_app: ApplicationEntry, monkeypatch):
    monkeypatch.setattr(BcuApp, "load_applications_async", lambda self: None)
    app = BcuApp()
    async with app.run_test() as pilot:
        # Check that core widgets are mounted
        assert app.query_one(HeaderStatsBanner) is not None
        assert app.query_one(InspectorSidebar) is not None
        assert app.query_one(DataTable) is not None
        assert app.query_one("#search-input", Input) is not None

        # Inject sample apps and render
        app.all_apps = [sample_inno_app, sample_store_app]
        app.apply_filters_and_render()
        await pilot.pause()

        table = app.query_one(DataTable)
        assert table.row_count == 2

        # Test search filtering
        search_input = app.query_one("#search-input", Input)
        search_input.value = "Notepad"
        await pilot.pause()

        assert table.row_count == 1

        # Test toggle selection
        table.move_cursor(row=0)
        app.action_toggle_selection()
        await pilot.pause()

        assert sample_inno_app.id in app.selected_ids

        # Test select all toggle off when all are selected
        app.action_toggle_select_all()
        await pilot.pause()
        assert len(app.selected_ids) == 0

        # Test select all toggle on
        app.action_toggle_select_all()
        await pilot.pause()
        assert len(app.selected_ids) == 1
