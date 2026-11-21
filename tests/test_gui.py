"""Unit tests for the modern Tkinter Desktop GUI (sprites, icons, views, and controller)."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from unittest.mock import patch

import pytest
from PIL import Image

from bcu.gui.app import BcuGuiApp
from bcu.gui.icons import (
    AppIconCache,
    extract_app_pil_icon,
    make_app_logo_pil,
    make_monogram_pil,
    make_rounded_rect_pil,
    make_toggle_pil,
)
from bcu.gui.theme import configure_ttk_styles
from bcu.gui.views import UninstallDialog
from bcu.models import (
    ApplicationEntry,
    ConfidenceLevel,
    JunkItem,
    JunkType,
    SeverityLevel,
    UninstallerType,
    VulnerabilityFinding,
)


@pytest.fixture(scope="module")
def _shared_tk_root():
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Tk display unavailable in this environment")
    root.withdraw()
    configure_ttk_styles(root)
    yield root
    try:
        root.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def tk_root(_shared_tk_root):
    # Clean children between tests so a single Tcl interpreter is reused cleanly on Windows
    for child in list(_shared_tk_root.winfo_children()):
        try:
            child.destroy()
        except tk.TclError:
            pass
    yield _shared_tk_root
    for child in list(_shared_tk_root.winfo_children()):
        try:
            child.destroy()
        except tk.TclError:
            pass


def _sample_apps() -> list[ApplicationEntry]:
    return [
        ApplicationEntry(
            id="reg:hklm:vscode",
            display_name="Visual Studio Code",
            display_version="1.96.0",
            publisher="Microsoft Corporation",
            estimated_size_bytes=420 * 1024 * 1024,
            uninstaller_type=UninstallerType.INNO_SETUP,
            uninstall_string=r'"C:\Program Files\VSCode\unins000.exe"',
            quiet_uninstall_string=r'"C:\Program Files\VSCode\unins000.exe" /VERYSILENT /NORESTART',
            quiet_uninstall_possible=True,
            install_location=r"C:\Program Files\VSCode",
            registry_path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VSCode",
            source_scanner="Registry",
        ),
        ApplicationEntry(
            id="reg:hklm:7zip",
            display_name="7-Zip",
            display_version="24.08",
            publisher="Igor Pavlov",
            estimated_size_bytes=6 * 1024 * 1024,
            uninstaller_type=UninstallerType.NSIS,
            uninstall_string=r'"C:\Program Files\7-Zip\Uninstall.exe"',
            quiet_uninstall_string=r'"C:\Program Files\7-Zip\Uninstall.exe" /S',
            quiet_uninstall_possible=True,
            source_scanner="Registry",
        ),
        ApplicationEntry(
            id="win:syscomp",
            display_name="Windows Core Runtime",
            display_version="10.0.22631",
            publisher="Microsoft",
            estimated_size_bytes=50 * 1024 * 1024,
            uninstaller_type=UninstallerType.MSIEXEC,
            is_system_component=True,
            is_protected=True,
            source_scanner="Registry",
        ),
    ]


def test_pillow_sprites_render_cleanly():
    rect = make_rounded_rect_pil(120, 32, 8, "#3B82F6", border="#60A5FA", bg_matte="#0B0E14")
    assert rect.size == (120, 32)
    assert rect.mode == "RGBA"

    tog_on = make_toggle_pil(True, "#0B0E14", 38, 20)
    tog_off = make_toggle_pil(False, "#0B0E14", 38, 20)
    assert tog_on.size == (38, 20)
    assert tog_off.size == (38, 20)
    assert tog_on.tobytes() != tog_off.tobytes()

    logo = make_app_logo_pil(32)
    assert logo.size == (32, 32)
    assert logo.getchannel("A").getextrema()[1] == 255

    app = _sample_apps()[0]
    mono = make_monogram_pil(app, size=24)
    assert mono.size == (24, 24)
    assert mono.getchannel("A").getextrema()[1] == 255


def test_extract_app_pil_icon_handles_visible_blank_and_missing(tmp_path: Path):
    # Visible PNG icon
    valid_png = tmp_path / "app.png"
    Image.new("RGBA", (32, 32), (59, 130, 246, 255)).save(valid_png)
    app_ok = ApplicationEntry(id="a1", display_name="Demo", display_icon=str(valid_png))
    extracted = extract_app_pil_icon(app_ok, size=22)
    assert extracted is not None
    assert extracted.size == (22, 22)

    # Completely transparent dummy PNG must be rejected so monogram fallback applies
    blank_png = tmp_path / "blank.png"
    Image.new("RGBA", (32, 32), (0, 0, 0, 0)).save(blank_png)
    app_blank = ApplicationEntry(id="a2", display_name="BlankStore", display_icon=str(blank_png))
    assert extract_app_pil_icon(app_blank, size=22) is None

    # Non-existent icon path returns None cleanly
    app_missing = ApplicationEntry(id="a3", display_name="Missing", display_icon=str(tmp_path / "nope.ico"))
    assert extract_app_pil_icon(app_missing, size=22) is None


def test_icon_cache_records_hits_and_misses(tk_root, tmp_path: Path):
    cache = AppIconCache(tk_root)
    valid_png = tmp_path / "ok.png"
    Image.new("RGBA", (48, 48), (34, 197, 94, 255)).save(valid_png)
    app_ok = ApplicationEntry(id="hit1", display_name="HitApp", display_icon=str(valid_png))
    app_miss = ApplicationEntry(id="miss1", display_name="MissApp", display_icon=str(tmp_path / "missing.ico"))

    # Instant monogram returned before background extraction
    img_m = cache.get_instant_tk_icon(app_ok, size=22)
    assert img_m is not None

    # Background extract caches raw PIL and supports promoting to multiple sizes without re-extracting
    assert cache.extract_in_background(app_ok, size=22) is True
    tk22 = cache.promote_to_tk("hit1", size=22)
    tk48 = cache.promote_to_tk("hit1", size=48)
    assert tk22 is not None and tk48 is not None
    assert tk22.width() == 22 and tk48.width() == 48

    # Miss is recorded so subsequent checks return False without hitting disk again
    assert cache.extract_in_background(app_miss, size=22) is False
    assert "miss1" in cache._raw_cache
    assert cache._raw_cache["miss1"] is None


def test_gui_app_filtering_sorting_selection_and_inspector(tk_root):
    apps = _sample_apps()
    gui = BcuGuiApp(root=tk_root, auto_scan=False)
    gui.all_apps = apps
    gui.app_by_id = {a.id: a for a in apps}
    gui.apply_filters_and_render()
    tk_root.update_idletasks()

    # System component hidden by default -> 2 visible apps
    assert len(gui.filtered_apps) == 2
    assert len(gui.tree.get_children()) == 2

    # Enable System Apps toggle -> 3 visible apps
    gui._on_system_toggle(True)
    assert len(gui.filtered_apps) == 3

    # Filter by InnoSetup chip -> only VS Code
    gui._select_type_filter("InnoSetup")
    assert [a.id for a in gui.filtered_apps] == ["reg:hklm:vscode"]

    # Reset filter & sort by size descending
    gui._select_type_filter("ALL")
    gui._sort_by("size")
    assert gui.filtered_apps[0].id == "reg:hklm:vscode"

    # Toggle selection & verify metrics/button label
    gui._toggle_app_id("reg:hklm:vscode")
    assert "reg:hklm:vscode" in gui.selected_ids
    assert gui.btn_uninstall._text == "Uninstall (1)"

    # Select all visible & deselect all visible
    gui.toggle_select_all_visible()
    assert len(gui.selected_ids) == 3
    gui.toggle_select_all_visible()
    assert len(gui.selected_ids) == 0

    # Inspector sync
    gui._inspect_app(apps[0])
    assert gui.insp_name_lbl.cget("text") == "Visual Studio Code"
    assert gui.prop_ver.cget("text") == "1.96.0"
    assert "VERYSILENT" in gui.well_cmd.get("1.0", "end")

    # Toggle inspector drawer hide/show
    gui._toggle_inspector()
    assert gui._inspector_visible is False
    assert gui.btn_toggle_insp._text == "Show Inspector"
    gui._toggle_inspector()
    assert gui._inspector_visible is True


def test_orphans_view_blocks_active_installed_app_and_filters_items(tk_root, tmp_path: Path):
    apps = _sample_apps()
    apps[0].install_location = str(tmp_path)  # existing directory -> genuinely active install
    gui = BcuGuiApp(root=tk_root, auto_scan=False)
    gui.all_apps = apps
    gui._orphans_scanned_once = True
    gui._switch_view("orphans")

    # Typing an active installed app name must be blocked cleanly
    gui.orphans_view.removed_search._has_placeholder = False
    gui.orphans_view.removed_search.var.set("Visual Studio Code")
    gui.orphans_view._trigger_removed_scan()
    log_text = gui.orphans_view.log.get("1.0", "end")
    assert "BLOCKED" in log_text

    # Populate synthetic orphan items and test category filtering & checkboxes
    gui.orphans_view.all_items = [
        JunkItem(
            path=r"C:\Users\Demo\Desktop\OldApp.lnk",
            junk_type=JunkType.SHORTCUT,
            confidence_level=ConfidenceLevel.VERY_GOOD,
            app_id="orphan:shortcut:oldapp",
            app_name="OldApp",
            reasons=["Broken shortcut target missing"],
        ),
        JunkItem(
            path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\GhostApp",
            junk_type=JunkType.REGISTRY_KEY,
            confidence_level=ConfidenceLevel.VERY_GOOD,
            app_id="orphan:reg:ghostapp",
            app_name="GhostApp",
            reasons=["Install directory no longer exists"],
        ),
    ]
    gui.orphans_view.selected_indices = {0, 1}
    gui.orphans_view._render_tree()
    assert len(gui.orphans_view.tree.get_children()) == 2

    gui.orphans_view._select_category(JunkType.SHORTCUT.value)
    assert len(gui.orphans_view.tree.get_children()) == 1

    gui.orphans_view._toggle_iid("0")
    assert 0 not in gui.orphans_view.selected_indices


def test_audit_view_renders_and_filters_findings(tk_root):
    gui = BcuGuiApp(root=tk_root, auto_scan=False)
    gui._audit_ran_once = True
    gui._switch_view("audit")

    gui.audit_view.findings = [
        VulnerabilityFinding(
            id="CVE-2024-0001",
            app_id="reg:hklm:demo",
            app_name="DemoApp",
            installed_version="1.0.0",
            severity=SeverityLevel.CRITICAL,
            title="Critical RCE",
            description="Remote code execution in DemoApp",
            affected_range="< 1.1.0",
            fixed_version="1.1.0",
            references=["https://example.com/advisory"],
        ),
        VulnerabilityFinding(
            id="CVE-2024-0002",
            app_id="reg:hklm:other",
            app_name="OtherApp",
            installed_version="2.0.0",
            severity=SeverityLevel.LOW,
            title="Minor info leak",
            description="Minor disclosure in OtherApp",
            affected_range="< 2.1.0",
            fixed_version="2.1.0",
        ),
    ]
    gui.audit_view._render_findings()
    assert len(gui.audit_view.tree.get_children()) == 2

    gui.audit_view._select_sev(SeverityLevel.CRITICAL.value)
    assert len(gui.audit_view.tree.get_children()) == 1

    gui.audit_view.tree.selection_set("0")
    gui.audit_view._on_select_finding()
    assert "CVE-2024-0001" in gui.audit_view.det_title.cget("text")
    assert gui.audit_view._current_ref_url == "https://example.com/advisory"


def test_uninstall_dialog_initializes_with_footer_and_protected_badge(tk_root):
    apps = _sample_apps()
    dlg = UninstallDialog(tk_root, target_apps=[apps[0], apps[2]], all_apps=apps)
    tk_root.update_idletasks()
    assert dlg.tog_quiet.value is True
    assert dlg.tog_dryrun.value is False
    assert dlg.tog_junk.value is True
    assert dlg.btn_start._text == "Start Uninstall"
    assert dlg.btn_close._text == "Cancel"
    dlg.destroy()
