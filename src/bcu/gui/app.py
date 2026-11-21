"""
Main Modern Desktop GUI Application for Bulk Crap Uninstaller (BCU).
Apple / Linear-inspired 3-pane layout with native Windows app icons, seamless Win11 dark titlebar,
zero-lag virtualized Treeview, resizable Inspector drawer, and integrated Orphan/CVE views.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser
from typing import Dict, List, Optional, Set, Tuple
from PIL import ImageTk

from bcu import __version__
from bcu.export.serializer import ApplicationSerializer
from bcu.gui.icons import AppIconCache, make_app_logo_pil
from bcu.gui.theme import (
    Colors,
    Fonts,
    IS_WINDOWS,
    apply_windows_dark_titlebar,
    configure_ttk_styles,
    dp,
    enable_high_dpi,
    hide_dedicated_console_if_owned,
)
from bcu.gui.views import AuditView, OrphansView, UninstallDialog
from bcu.gui.widgets import (
    AppleToggle,
    EmptyStateOverlay,
    FilterChip,
    LoadingOverlay,
    ModernButton,
    ModernSearchBar,
    NavItem,
    ScanningBanner,
    SpinnerRing,
    ToastNotification,
)
from bcu.models import ApplicationEntry, FilterCriteria, UninstallerType
from bcu.scanners.manager import ScannerManager
from bcu.utils.formatting import format_size
from bcu.utils.platform import is_admin, verify_authenticode_signature


def _open_regedit_at_key(reg_path: str) -> Tuple[bool, str]:
    """Opens Windows Registry Editor directly at the given registry path via LastKey."""
    if not IS_WINDOWS or not reg_path:
        return False, "Registry path unavailable"
    try:
        import winreg

        full = reg_path.replace("/", "\\")
        prefixes = {
            "HKLM\\": "HKEY_LOCAL_MACHINE\\",
            "HKCU\\": "HKEY_CURRENT_USER\\",
            "HKCR\\": "HKEY_CLASSES_ROOT\\",
            "HKU\\": "HKEY_USERS\\",
        }
        for short, long_name in prefixes.items():
            if full.upper().startswith(short):
                full = long_name + full[len(short):]
                break

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit") as k:
            winreg.SetValueEx(k, "LastKey", 0, winreg.REG_SZ, f"Computer\\{full}")
        subprocess.Popen(["regedit.exe", "-m"])
        return True, f"Opened RegEdit at {reg_path}"
    except Exception as exc:
        return False, str(exc)


def _relaunch_as_admin() -> bool:
    """Relaunches the BCU GUI with UAC elevation on Windows."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        if getattr(sys, "frozen", False):
            exe = sys.executable
            params = "gui"
        else:
            exe = sys.executable
            params = "-m bcu gui"

        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return int(ret) > 32
    except Exception:
        return False


class BcuGuiApp:
    """Main BCU Desktop GUI Application Controller."""

    TYPE_FILTERS = [
        ("All", "ALL"),
        ("MSI", "Msiexec"),
        ("Inno", "InnoSetup"),
        ("NSIS", "Nsis"),
        ("Store", "StoreApp"),
        ("Winget", "Winget"),
        ("Pkg Mgr", "PackageMgr"),
        ("Steam", "Steam"),
        ("Custom", "Custom"),
    ]

    def __init__(self, root: Optional[tk.Tk] = None, auto_scan: bool = True) -> None:
        if root is None:
            enable_high_dpi()
            self.root = tk.Tk()
        else:
            self.root = root

        self.root.title(f"Bulk Crap Uninstaller  •  v{__version__}")
        self.root.configure(bg=Colors.BG_BASE)
        self.root.minsize(1040, 640)

        # Center window gracefully at 1360x820 (clamped to screen size)
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        w = min(1360, max(1040, int(sw * 0.84)))
        h = min(820, max(640, int(sh * 0.84)))
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

        configure_ttk_styles(self.root)
        apply_windows_dark_titlebar(self.root)

        self._list_icon_px = dp(22)
        self._hero_icon_px = dp(48)

        self._logo_photo = ImageTk.PhotoImage(make_app_logo_pil(dp(32)), master=self.root)
        try:
            self.root.iconphoto(True, self._logo_photo)
        except Exception:
            pass

        self.icon_cache = AppIconCache(self.root)
        self.all_apps: List[ApplicationEntry] = []
        self.filtered_apps: List[ApplicationEntry] = []
        self.app_by_id: Dict[str, ApplicationEntry] = {}
        self.selected_ids: Set[str] = set()
        self.active_type: str = "ALL"
        self.show_system: bool = False
        self.selected_only: bool = False
        self.quiet_only: bool = False
        self.sort_col: str = "name"
        self.sort_desc: bool = False
        self.focused_app: Optional[ApplicationEntry] = None
        self._hovered_iid: Optional[str] = None
        self._last_anchor_iid: Optional[str] = None
        self._is_scanning_apps: bool = False
        self._inspector_visible: bool = True
        self._icon_gen_token: int = 0
        self._orphans_scanned_once: bool = False
        self._audit_ran_once: bool = False
        self._sig_cache: Dict[str, Tuple[bool, Optional[str]]] = {}
        self._destroyed: bool = False
        self.root.bind("<Destroy>", self._on_root_destroy, add="+")

        self._type_chips: Dict[str, FilterChip] = {}
        self._nav_items: Dict[str, NavItem] = {}
        self._views: Dict[str, tk.Frame] = {}

        self._build_layout()
        self._bind_shortcuts()
        self._switch_view("apps")

        if auto_scan:
            self.load_applications_async(force_refresh=False)

    def _build_layout(self) -> None:
        # Outer horizontal shell: Left Nav Rail | Vertical Hairline | Active Main View
        shell = tk.Frame(self.root, bg=Colors.BG_BASE)
        shell.pack(fill="both", expand=True)

        self._build_sidebar(shell)
        tk.Frame(shell, width=1, bg=Colors.BORDER_SUBTLE).pack(side="left", fill="y")

        self.stage = tk.Frame(shell, bg=Colors.BG_BASE)
        self.stage.pack(side="left", fill="both", expand=True)

        # Build 3 main pages
        self.apps_view = self._build_apps_view(self.stage)
        self.orphans_view = OrphansView(
            self.stage,
            get_all_apps=lambda: self.all_apps,
            on_count_changed=lambda n: self._nav_items["orphans"].set_badge(str(n) if n > 0 else ""),
            on_toast=self.show_toast,
        )
        self.audit_view = AuditView(
            self.stage,
            get_all_apps=lambda: self.all_apps,
            on_count_changed=lambda n: self._nav_items["audit"].set_badge(str(n) if n > 0 else ""),
            on_toast=self.show_toast,
        )
        self._views = {
            "apps": self.apps_view,
            "orphans": self.orphans_view,
            "audit": self.audit_view,
        }

        # Floating non-blocking Toast notification
        self.toast = ToastNotification(self.root)

        # Bottom subtle status bar with live activity spinner
        tk.Frame(self.root, height=1, bg=Colors.BORDER_SUBTLE).pack(fill="x")
        status_bar = tk.Frame(self.root, bg=Colors.BG_SIDEBAR, height=28, padx=16)
        status_bar.pack(fill="x")
        status_bar.pack_propagate(False)

        self.status_spinner = SpinnerRing(status_bar, size=14, stroke=2, bg=Colors.BG_SIDEBAR, track_color=Colors.BG_ELEVATED)
        self.status_lbl = tk.Label(status_bar, text="Ready", bg=Colors.BG_SIDEBAR, fg=Colors.TEXT_SECONDARY, font=Fonts.small(), anchor="w")
        self.status_lbl.pack(side="left", fill="x", expand=True)

        tk.Label(
            status_bar,
            text="Ctrl+F Search  •  Ctrl/Shift+Click Multi-Select  •  Space Toggle  •  Ctrl+D Clear  •  F5 Refresh",
            bg=Colors.BG_SIDEBAR,
            fg=Colors.TEXT_MUTED,
            font=Fonts.micro(),
        ).pack(side="right")

    def _build_sidebar(self, parent: tk.Misc) -> None:
        rail = tk.Frame(parent, width=dp(216), bg=Colors.BG_SIDEBAR)
        rail.pack(side="left", fill="y")
        rail.pack_propagate(False)

        # Brand Header
        brand = tk.Frame(rail, bg=Colors.BG_SIDEBAR, padx=16, pady=16)
        brand.pack(fill="x")
        tk.Label(brand, image=self._logo_photo, bg=Colors.BG_SIDEBAR, bd=0).pack(side="left", padx=(0, 10))
        btxt = tk.Frame(brand, bg=Colors.BG_SIDEBAR)
        btxt.pack(side="left")
        tk.Label(btxt, text="BCU", bg=Colors.BG_SIDEBAR, fg=Colors.TEXT_PRIMARY, font=Fonts.hero(), anchor="w").pack(anchor="w")
        tk.Label(btxt, text=f"v{__version__} Desktop", bg=Colors.BG_SIDEBAR, fg=Colors.TEXT_MUTED, font=Fonts.micro(), anchor="w").pack(anchor="w")

        # Navigation Section
        tk.Label(rail, text="WORKSPACE", bg=Colors.BG_SIDEBAR, fg=Colors.TEXT_MUTED, font=Fonts.micro(), padx=16, anchor="w").pack(fill="x", pady=(6, 4))

        self._nav_items["apps"] = NavItem(rail, "⊞", "Applications", lambda: self._switch_view("apps"), badge_text="0")
        self._nav_items["apps"].pack(fill="x", padx=8, pady=2)

        self._nav_items["orphans"] = NavItem(rail, "✦", "Orphaned Junk", lambda: self._switch_view("orphans"))
        self._nav_items["orphans"].pack(fill="x", padx=8, pady=2)

        self._nav_items["audit"] = NavItem(rail, "🛡", "Security Audit", lambda: self._switch_view("audit"))
        self._nav_items["audit"].pack(fill="x", padx=8, pady=2)

        tk.Frame(rail, height=1, bg=Colors.BORDER_SUBTLE).pack(fill="x", padx=16, pady=14)

        # Export & Tools
        tk.Label(rail, text="TOOLS", bg=Colors.BG_SIDEBAR, fg=Colors.TEXT_MUTED, font=Fonts.micro(), padx=16, anchor="w").pack(fill="x", pady=(0, 6))
        tools_box = tk.Frame(rail, bg=Colors.BG_SIDEBAR, padx=14)
        tools_box.pack(fill="x")

        ModernButton(tools_box, "Export JSON", command=lambda: self._export_inventory("json"), variant="secondary", width=188, height=30, bg_matte=Colors.BG_SIDEBAR).pack(pady=(0, 6))
        ModernButton(tools_box, "Export CSV", command=lambda: self._export_inventory("csv"), variant="secondary", width=188, height=30, bg_matte=Colors.BG_SIDEBAR).pack(pady=(0, 6))

        # Bottom summary & privilege block
        bottom = tk.Frame(rail, bg=Colors.BG_SIDEBAR, padx=14, pady=14)
        bottom.pack(side="bottom", fill="x")

        stats_border = tk.Frame(bottom, bg=Colors.BORDER_SUBTLE, padx=1, pady=1)
        stats_border.pack(fill="x", pady=(0, 10))
        stats_card = tk.Frame(stats_border, bg=Colors.BG_SURFACE, padx=10, pady=8)
        stats_card.pack(fill="x")

        self.stat_apps_lbl = self._mini_stat(stats_card, "Installed", "0")
        self.stat_quiet_lbl = self._mini_stat(stats_card, "Quiet Ready", "0%")
        self.stat_size_lbl = self._mini_stat(stats_card, "Est. Size", "0 B")
        self.stat_sel_lbl = self._mini_stat(stats_card, "Selected", "0", accent=Colors.ACCENT_BLUE_HOVER)

        elevated = is_admin()
        pill_bg = Colors.TINT_GREEN if elevated else Colors.TINT_AMBER
        pill_fg = Colors.ACCENT_GREEN_HOVER if elevated else Colors.ACCENT_AMBER_HOVER
        pill_txt = "●  ADMIN ELEVATED" if elevated else "●  STANDARD USER"

        tk.Label(
            bottom,
            text=pill_txt,
            bg=pill_bg,
            fg=pill_fg,
            font=Fonts.micro(),
            pady=5,
        ).pack(fill="x")

        if not elevated and IS_WINDOWS:
            ModernButton(
                bottom,
                "⚡ Relaunch as Admin",
                command=self._elevate,
                variant="amber-soft",
                width=188,
                height=30,
                bg_matte=Colors.BG_SIDEBAR,
            ).pack(pady=(6, 0))

    def _mini_stat(self, parent: tk.Misc, label: str, value: str, accent: str = Colors.TEXT_PRIMARY) -> tk.Label:
        row = tk.Frame(parent, bg=Colors.BG_SURFACE)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=label, bg=Colors.BG_SURFACE, fg=Colors.TEXT_MUTED, font=Fonts.small()).pack(side="left")
        val_lbl = tk.Label(row, text=value, bg=Colors.BG_SURFACE, fg=accent, font=Fonts.small_bold())
        val_lbl.pack(side="right")
        return val_lbl

    def _build_apps_view(self, parent: tk.Misc) -> tk.Frame:
        frame = tk.Frame(parent, bg=Colors.BG_BASE)

        # Header + Search + Primary Actions
        top = tk.Frame(frame, bg=Colors.BG_BASE, padx=20, pady=14)
        top.pack(fill="x")

        self.search_bar = ModernSearchBar(
            top,
            placeholder="Search installed applications by name, publisher, ID, or path... (Ctrl+F)",
            on_change=lambda _q: self.apply_filters_and_render(),
            on_escape=lambda: self.tree.focus_set(),
        )
        self.search_bar.pack(side="left", fill="x", expand=True)

        self.btn_uninstall = ModernButton(
            top,
            "Uninstall",
            command=self.open_uninstall_dialog,
            variant="danger",
            width=136,
            height=34,
            bg_matte=Colors.BG_BASE,
        )
        self.btn_uninstall.pack(side="left", padx=(10, 0))

        self.btn_refresh = ModernButton(
            top,
            "↻ Refresh",
            command=lambda: self.load_applications_async(force_refresh=True),
            variant="secondary",
            width=96,
            height=34,
            bg_matte=Colors.BG_BASE,
        )
        self.btn_refresh.pack(side="left", padx=(8, 0))

        # Segmented Type Filter Chips + System Toggle + Inspector Toggle
        chips_row = tk.Frame(frame, bg=Colors.BG_BASE, padx=20)
        chips_row.pack(fill="x", pady=(0, 8))

        for label, val in self.TYPE_FILTERS:
            chip = FilterChip(chips_row, label, val, on_select=self._select_type_filter, active=(val == "ALL"))
            chip.pack(side="left", padx=(0, 5))
            self._type_chips[val] = chip

        self.btn_toggle_insp = ModernButton(
            chips_row,
            "Hide Inspector",
            command=self._toggle_inspector,
            variant="secondary",
            width=108,
            height=26,
            bg_matte=Colors.BG_BASE,
        )
        self.btn_toggle_insp.pack(side="right")

        self.tog_system = AppleToggle(
            chips_row,
            "System Apps",
            initial=False,
            on_change=self._on_system_toggle,
            bg=Colors.BG_BASE,
        )
        self.tog_system.pack(side="right", padx=(0, 12))

        # Selection & Quick-Filter Toolbar (Selected-only filter, Quiet-only filter, Select All, Clear Selection, Live Summary)
        sel_bar = tk.Frame(frame, bg=Colors.BG_BASE, padx=20)
        sel_bar.pack(fill="x", pady=(0, 10))

        self.chip_selected_only = FilterChip(
            sel_bar,
            "Selected (0)",
            "SELECTED",
            on_select=lambda _v: self._toggle_selected_only(),
            active=False,
        )
        self.chip_selected_only.pack(side="left", padx=(0, 6))

        self.chip_quiet_only = FilterChip(
            sel_bar,
            "Quiet Only",
            "QUIET",
            on_select=lambda _v: self._toggle_quiet_only(),
            active=False,
        )
        self.chip_quiet_only.pack(side="left", padx=(0, 10))

        self.btn_sel_all = ModernButton(
            sel_bar,
            "Select Visible",
            command=self.select_all_visible,
            variant="secondary",
            width=102,
            height=25,
            radius=6,
            bg_matte=Colors.BG_BASE,
        )
        self.btn_sel_all.pack(side="left", padx=(0, 6))

        self.btn_clear_sel = ModernButton(
            sel_bar,
            "Clear Selection",
            command=self.clear_selection,
            variant="secondary",
            width=110,
            height=25,
            radius=6,
            bg_matte=Colors.BG_BASE,
            disabled=True,
        )
        self.btn_clear_sel.pack(side="left")

        self.selection_summary_lbl = tk.Label(
            sel_bar,
            text="",
            bg=Colors.BG_BASE,
            fg=Colors.TEXT_MUTED,
            font=Fonts.small(),
            anchor="e",
        )
        self.selection_summary_lbl.pack(side="right")

        # Split PanedWindow: Left App Treeview | Right Inspector Drawer
        self.paned = ttk.PanedWindow(frame, orient="horizontal", style="Modern.TPanedwindow")
        self.paned.pack(fill="both", expand=True, padx=20, pady=(0, 14))

        # Table card with animated LoadingOverlay, ScanningBanner & EmptyStateOverlay
        tbl_border = tk.Frame(self.paned, bg=Colors.BORDER_SUBTLE, padx=1, pady=1)
        tbl_wrap = tk.Frame(tbl_border, bg=Colors.BG_SURFACE)
        tbl_wrap.pack(fill="both", expand=True)

        self.scan_banner = ScanningBanner(tbl_wrap)

        tree_host = tk.Frame(tbl_wrap, bg=Colors.BG_SURFACE)
        tree_host.pack(fill="both", expand=True)
        self._tree_host = tree_host

        cols = ("version", "publisher", "size", "type", "quiet")
        self.tree = ttk.Treeview(
            tree_host,
            columns=cols,
            show="tree headings",
            style="Modern.Treeview",
            selectmode="extended",
        )
        self.tree.heading("#0", text="APPLICATION ▴", anchor="w", command=lambda: self._sort_by("name"))
        self.tree.heading("version", text="VERSION", anchor="w", command=lambda: self._sort_by("version"))
        self.tree.heading("publisher", text="PUBLISHER", anchor="w", command=lambda: self._sort_by("publisher"))
        self.tree.heading("size", text="SIZE", anchor="e", command=lambda: self._sort_by("size"))
        self.tree.heading("type", text="TYPE", anchor="w", command=lambda: self._sort_by("type"))
        self.tree.heading("quiet", text="QUIET", anchor="center", command=lambda: self._sort_by("quiet"))

        self.tree.column("#0", width=dp(260), minwidth=dp(170), stretch=True, anchor="w")
        self.tree.column("version", width=dp(88), minwidth=dp(68), stretch=False, anchor="w")
        self.tree.column("publisher", width=dp(140), minwidth=dp(90), stretch=True, anchor="w")
        self.tree.column("size", width=dp(76), minwidth=dp(66), stretch=False, anchor="e")
        self.tree.column("type", width=dp(82), minwidth=dp(70), stretch=False, anchor="w")
        self.tree.column("quiet", width=dp(50), minwidth=dp(44), stretch=False, anchor="center")

        self.tree.tag_configure("odd", background=Colors.BG_ROW_ALT)
        self.tree.tag_configure("even", background=Colors.BG_SURFACE)
        self.tree.tag_configure("hover", background=Colors.BG_HOVER)
        self.tree.tag_configure("checked", foreground="#93C5FD")

        vsb = ttk.Scrollbar(tree_host, orient="vertical", style="Modern.TScrollbar", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.loading_overlay = LoadingOverlay(tree_host)
        self.empty_overlay = EmptyStateOverlay(tree_host)

        # Keep all 6 columns cleanly proportioned inside the visible table width (zero horizontal clipping)
        def _fit_tree_columns(event) -> None:
            avail = event.width - dp(4)
            if avail < dp(360):
                return
            w_ver = dp(88)
            w_size = dp(76)
            w_type = dp(82)
            w_quiet = dp(50)
            rem = max(dp(200), avail - (w_ver + w_size + w_type + w_quiet))
            if avail < dp(560):
                # Narrow viewport (e.g. 1040px with inspector open): maximize name clarity
                w_pub = max(dp(75), int(rem * 0.28))
            else:
                w_pub = max(dp(110), int(rem * 0.34))
            w_name = max(dp(140), rem - w_pub)
            self.tree.column("#0", width=w_name)
            self.tree.column("version", width=w_ver)
            self.tree.column("publisher", width=w_pub)
            self.tree.column("size", width=w_size)
            self.tree.column("type", width=w_type)
            self.tree.column("quiet", width=w_quiet)

        self.tree.bind("<Configure>", _fit_tree_columns)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Double-1>", lambda _e: self.toggle_focused_selection())
        self.tree.bind("<space>", lambda _e: self.toggle_focused_selection())
        self.tree.bind("<Button-3>", self._on_tree_right_click)
        self.tree.bind("<Motion>", self._on_tree_motion)
        self.tree.bind("<Leave>", self._on_tree_leave)

        # Inspector Drawer (weight=0 preserves steady Apple-style 344dp width during window resize while still sash-draggable)
        self.inspector_pane = self._build_inspector(self.paned)

        self.paned.add(tbl_border, weight=4)
        self.paned.add(self.inspector_pane, weight=0)

        # Dark Right-Click Context Menu
        self._build_context_menu()

        return frame

    def _build_inspector(self, parent: tk.Misc) -> tk.Frame:
        border = tk.Frame(parent, bg=Colors.BORDER_SUBTLE, padx=1, pady=1, width=dp(344))
        border.pack_propagate(False)
        container = tk.Frame(border, bg=Colors.BG_SURFACE)
        container.pack(fill="both", expand=True)

        # Scrollable canvas inside inspector so long commands/paths never clip
        canvas = tk.Canvas(container, bg=Colors.BG_SURFACE, highlightthickness=0, bd=0)
        sb = ttk.Scrollbar(container, orient="vertical", style="Modern.TScrollbar", command=canvas.yview)
        self.insp_inner = tk.Frame(canvas, bg=Colors.BG_SURFACE, padx=16, pady=16)

        win_id = canvas.create_window((0, 0), window=self.insp_inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self._insp_prop_labels: List[tk.Label] = []

        def _on_canvas_configure(event) -> None:
            canvas.itemconfigure(win_id, width=event.width)
            avail = max(160, event.width - dp(32))
            hero_wrap = max(130, avail - self._hero_icon_px - dp(16))
            prop_wrap = max(110, avail - dp(115))
            if hasattr(self, "insp_name_lbl"):
                self.insp_name_lbl.configure(wraplength=hero_wrap)
                self.insp_pub_lbl.configure(wraplength=hero_wrap)
            for lbl in self._insp_prop_labels:
                lbl.configure(wraplength=prop_wrap)

        self.insp_inner.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", _on_canvas_configure)

        # Smooth MouseWheel scrolling anywhere inside the inspector drawer
        def _on_wheel(event) -> None:
            if canvas.yview() != (0.0, 1.0):
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        self._insp_wheel_handler = _on_wheel
        canvas.bind("<MouseWheel>", _on_wheel)
        self.insp_inner.bind("<MouseWheel>", _on_wheel)

        # App Hero Header (48dp icon + title + publisher)
        hero = tk.Frame(self.insp_inner, bg=Colors.BG_SURFACE)
        hero.pack(fill="x", pady=(0, 12))

        self.insp_icon_lbl = tk.Label(hero, bg=Colors.BG_SURFACE, bd=0)
        self.insp_icon_lbl.pack(side="left", padx=(0, 12), anchor="n")

        htxt = tk.Frame(hero, bg=Colors.BG_SURFACE)
        htxt.pack(side="left", fill="x", expand=True)

        self.insp_name_lbl = tk.Label(
            htxt,
            text="Select an application",
            bg=Colors.BG_SURFACE,
            fg=Colors.TEXT_PRIMARY,
            font=Fonts.heading(),
            anchor="w",
            justify="left",
            wraplength=dp(230),
        )
        self.insp_name_lbl.pack(fill="x")

        self.insp_pub_lbl = tk.Label(
            htxt,
            text="Click any app in the list to inspect metadata, verify signatures, or open in Explorer / RegEdit.",
            bg=Colors.BG_SURFACE,
            fg=Colors.TEXT_SECONDARY,
            font=Fonts.small(),
            anchor="w",
            justify="left",
            wraplength=dp(230),
        )
        self.insp_pub_lbl.pack(fill="x", pady=(2, 0))

        self.insp_url_lbl = tk.Label(
            htxt,
            text="",
            bg=Colors.BG_SURFACE,
            fg=Colors.ACCENT_BLUE_HOVER,
            font=Fonts.small(),
            anchor="w",
            cursor="hand2",
        )
        self.insp_url_lbl.bind("<Button-1>", self._open_focused_url)

        # Quick Actions Grid (2 sleek rows that fit cleanly even at 980px minsize)
        qa = tk.Frame(self.insp_inner, bg=Colors.BG_SURFACE)
        qa.pack(fill="x", pady=(0, 14))
        qa_r1 = tk.Frame(qa, bg=Colors.BG_SURFACE)
        qa_r1.pack(fill="x", pady=(0, 6))
        qa_r2 = tk.Frame(qa, bg=Colors.BG_SURFACE)
        qa_r2.pack(fill="x")

        self.btn_qa_folder = ModernButton(qa_r1, "Folder", command=self._open_focused_folder, variant="secondary", width=88, height=28, bg_matte=Colors.BG_SURFACE, disabled=True)
        self.btn_qa_folder.pack(side="left", padx=(0, 6))
        self.btn_qa_reg = ModernButton(qa_r1, "RegEdit", command=self._open_focused_regedit, variant="secondary", width=88, height=28, bg_matte=Colors.BG_SURFACE, disabled=True)
        self.btn_qa_reg.pack(side="left", padx=(0, 6))
        self.btn_qa_sig = ModernButton(qa_r1, "Verify Sig", command=self._verify_focused_signature, variant="blue-soft", width=98, height=28, bg_matte=Colors.BG_SURFACE, disabled=True)
        self.btn_qa_sig.pack(side="left")

        self.btn_qa_copy = ModernButton(qa_r2, "Copy Cmd", command=self._copy_focused_cmd, variant="secondary", width=136, height=28, bg_matte=Colors.BG_SURFACE, disabled=True)
        self.btn_qa_copy.pack(side="left", padx=(0, 6))
        self.btn_qa_uninst = ModernButton(qa_r2, "Uninstall App", command=self._uninstall_focused_only, variant="danger-soft", width=144, height=28, bg_matte=Colors.BG_SURFACE, disabled=True)
        self.btn_qa_uninst.pack(side="left")

        # Properties Section
        tk.Label(self.insp_inner, text="PROPERTIES", bg=Colors.BG_SURFACE, fg=Colors.TEXT_MUTED, font=Fonts.micro(), anchor="w").pack(fill="x", pady=(0, 6))
        prop_border = tk.Frame(self.insp_inner, bg=Colors.BORDER_SUBTLE, padx=1, pady=1)
        prop_border.pack(fill="x", pady=(0, 14))
        prop_card = tk.Frame(prop_border, bg=Colors.BG_ELEVATED, padx=12, pady=8)
        prop_card.pack(fill="x")

        self.prop_ver = self._prop_row(prop_card, "Version")
        self.prop_size = self._prop_row(prop_card, "Disk Size")
        self.prop_type = self._prop_row(prop_card, "Uninstaller")
        self.prop_quiet = self._prop_row(prop_card, "Quiet Mode")
        self.prop_arch = self._prop_row(prop_card, "Architecture")
        self.prop_sig = self._prop_row(prop_card, "Signature")
        self.prop_flags = self._prop_row(prop_card, "Flags")

        # Copyable Code Wells with 1-click Copy pills
        self.well_cmd = self._code_well(self.insp_inner, "UNINSTALL COMMAND", self._copy_focused_cmd)
        self.well_loc = self._code_well(self.insp_inner, "INSTALL DIRECTORY", self._copy_focused_path)
        self.well_reg = self._code_well(self.insp_inner, "REGISTRY PATH", self._copy_focused_reg)

        # Bind mousewheel recursively across all inspector children
        self._bind_wheel_recursive(self.insp_inner, _on_wheel)

        return border

    def _bind_wheel_recursive(self, widget: tk.Misc, handler) -> None:
        widget.bind("<MouseWheel>", handler, add="+")
        for child in widget.winfo_children():
            self._bind_wheel_recursive(child, handler)

    def _prop_row(self, parent: tk.Misc, key: str) -> tk.Label:
        row = tk.Frame(parent, bg=Colors.BG_ELEVATED)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=key, bg=Colors.BG_ELEVATED, fg=Colors.TEXT_MUTED, font=Fonts.small(), width=11, anchor="w").pack(side="left")
        val = tk.Label(row, text="-", bg=Colors.BG_ELEVATED, fg=Colors.TEXT_PRIMARY, font=Fonts.small_bold(), anchor="e", justify="right", wraplength=dp(190))
        val.pack(side="right", fill="x", expand=True)
        self._insp_prop_labels.append(val)
        return val

    def _code_well(self, parent: tk.Misc, title: str, on_copy=None) -> tk.Text:
        hdr = tk.Frame(parent, bg=Colors.BG_SURFACE)
        hdr.pack(fill="x", pady=(0, 4))
        tk.Label(hdr, text=title, bg=Colors.BG_SURFACE, fg=Colors.TEXT_MUTED, font=Fonts.micro(), anchor="w").pack(side="left")
        if on_copy is not None:
            copy_lbl = tk.Label(
                hdr,
                text="Copy",
                bg=Colors.BG_SURFACE,
                fg=Colors.ACCENT_BLUE_HOVER,
                font=Fonts.micro(),
                cursor="hand2",
                padx=4,
            )
            copy_lbl.pack(side="right")
            copy_lbl.bind("<Button-1>", lambda _e: on_copy())
            copy_lbl.bind("<Enter>", lambda _e: copy_lbl.configure(fg="#FFFFFF"))
            copy_lbl.bind("<Leave>", lambda _e: copy_lbl.configure(fg=Colors.ACCENT_BLUE_HOVER))

        border = tk.Frame(parent, bg=Colors.BORDER_SUBTLE, padx=1, pady=1)
        border.pack(fill="x", pady=(0, 12))
        txt = tk.Text(
            border,
            height=3,
            bg=Colors.BG_CODE,
            fg="#7EE787",
            font=Fonts.mono_small(),
            relief="flat",
            bd=0,
            padx=8,
            pady=6,
            wrap="char",
            state="disabled",
        )
        txt.pack(fill="x")
        return txt

    @staticmethod
    def _set_well(widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        lines = max(2, min(4, (len(value) // 38) + 1))
        widget.configure(height=lines, state="disabled")

    def _build_context_menu(self) -> None:
        self.ctx_menu = tk.Menu(
            self.root,
            tearoff=0,
            bg=Colors.BG_ELEVATED,
            fg=Colors.TEXT_PRIMARY,
            activebackground=Colors.BG_SELECTED,
            activeforeground="#FFFFFF",
            bd=1,
            relief="flat",
            font=Fonts.small(),
        )

    def _populate_context_menu(self, highlighted_ids: List[str]) -> None:
        self.ctx_menu.delete(0, "end")
        n_hi = len(highlighted_ids)
        if n_hi > 1:
            self.ctx_menu.add_command(label=f"Check {n_hi} Highlighted", command=lambda: self._set_highlighted_checked(True))
            self.ctx_menu.add_command(label=f"Uncheck {n_hi} Highlighted", command=lambda: self._set_highlighted_checked(False))
            self.ctx_menu.add_command(label=f"Uninstall {n_hi} Highlighted...", command=self._uninstall_highlighted)
            self.ctx_menu.add_separator()
        else:
            self.ctx_menu.add_command(label="Toggle Selection  (Space)", command=self.toggle_focused_selection)
            self.ctx_menu.add_command(label="Uninstall Application...", command=self._uninstall_focused_only)
            self.ctx_menu.add_separator()
        if self.selected_ids:
            self.ctx_menu.add_command(label=f"Uninstall {len(self.selected_ids)} Checked...", command=self.open_uninstall_dialog)
            self.ctx_menu.add_command(label="Clear All Checked  (Ctrl+D)", command=self.clear_selection)
            self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Open Install Folder", command=self._open_focused_folder)
        self.ctx_menu.add_command(label="Open in Registry Editor", command=self._open_focused_regedit)
        self.ctx_menu.add_command(label="Verify Digital Signature", command=self._verify_focused_signature)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Copy Uninstall Command", command=self._copy_focused_cmd)
        self.ctx_menu.add_command(label="Copy Application ID", command=self._copy_focused_id)
        self.ctx_menu.add_command(label="Copy Install Path", command=self._copy_focused_path)
        self.ctx_menu.add_command(label="Copy Registry Path", command=self._copy_focused_reg)

    def _bind_shortcuts(self) -> None:
        self.root.bind("<Control-f>", lambda _e: (self._switch_view("apps"), self.search_bar.focus_input()))
        self.root.bind("<Control-a>", self._on_ctrl_a)
        self.root.bind("<Control-d>", self._on_ctrl_d)
        self.root.bind("<Control-Key-1>", lambda _e: self._switch_view("apps"))
        self.root.bind("<Control-Key-2>", lambda _e: self._switch_view("orphans"))
        self.root.bind("<Control-Key-3>", lambda _e: self._switch_view("audit"))
        self.root.bind("<F5>", lambda _e: self.load_applications_async(force_refresh=True))
        self.root.bind("<Delete>", lambda _e: self.open_uninstall_dialog() if self._active_view_name == "apps" else None)

    def _on_ctrl_a(self, event) -> Optional[str]:
        if isinstance(event.widget, (tk.Entry, tk.Text)):
            return None
        if self._active_view_name == "apps":
            self.toggle_select_all_visible()
            return "break"
        if self._active_view_name == "orphans":
            self.orphans_view._select_visible()
            return "break"
        return None

    def _on_ctrl_d(self, event) -> Optional[str]:
        if isinstance(event.widget, (tk.Entry, tk.Text)):
            return None
        if self._active_view_name == "apps":
            self.clear_selection()
            return "break"
        if self._active_view_name == "orphans":
            self.orphans_view._deselect_all()
            return "break"
        return None

    def _switch_view(self, name: str) -> None:
        self._active_view_name = name
        for k, nav in self._nav_items.items():
            nav.set_active(k == name)
        for k, view in self._views.items():
            if k == name:
                view.pack(fill="both", expand=True)
            else:
                view.pack_forget()

        if name == "orphans" and not self._orphans_scanned_once:
            self._orphans_scanned_once = True
            self.orphans_view.scan_system_orphans()
        elif name == "audit" and not self._audit_ran_once and self.all_apps:
            self._audit_ran_once = True
            self.audit_view.run_audit()

    def _set_status(self, msg: str) -> None:
        self.status_lbl.configure(text=msg)

    def _set_status_spinner(self, active: bool) -> None:
        if active:
            if not self.status_spinner.winfo_ismapped():
                self.status_spinner.pack(side="left", padx=(0, 8), before=self.status_lbl)
            self.status_spinner.start()
        else:
            self.status_spinner.stop()
            self.status_spinner.pack_forget()

    def show_toast(self, message: str, tone: str = "info") -> None:
        if not self._destroyed:
            self.toast.show(message, tone=tone)

    def load_applications_async(self, force_refresh: bool = False) -> None:
        if self._is_scanning_apps:
            return
        self._is_scanning_apps = True
        self.btn_refresh.set_disabled(True)
        self.empty_overlay.hide()
        self._set_status_spinner(True)
        self._set_status("Scanning installed applications across Windows sources...")

        had_apps = bool(self.all_apps)
        if had_apps:
            self.scan_banner.show("Refreshing installed applications across Windows sources...", before=self._tree_host)
        else:
            self.loading_overlay.show(
                "Scanning Installed Applications...",
                "Discovering Windows Registry, Store Apps, Winget, Steam, Scoop & more...",
            )

        def _worker() -> None:
            def _prog(msg: str) -> None:
                def _u() -> None:
                    self._set_status(msg)
                    if self.loading_overlay.is_visible:
                        self.loading_overlay.update_subtitle(msg)
                    if self.scan_banner.is_visible:
                        self.scan_banner.update_message(msg)

                self._safe_after(_u)

            try:
                mgr = ScannerManager()
                apps = mgr.scan_all(progress_callback=_prog, force_refresh=force_refresh)
            except Exception as exc:
                def _err(e=str(exc)) -> None:
                    self._is_scanning_apps = False
                    self.loading_overlay.hide()
                    self.scan_banner.hide()
                    self._set_status_spinner(False)
                    self.btn_refresh.set_disabled(False)
                    self._set_status(f"Scan error: {e}")
                    self.show_toast(f"Scan failed: {e}", "err")

                self._safe_after(_err)
                return

            def _done() -> None:
                self._is_scanning_apps = False
                self.all_apps = apps
                self.app_by_id = {a.id: a for a in apps}
                # Prune any checked IDs that were uninstalled
                self.selected_ids.intersection_update(self.app_by_id.keys())
                self.loading_overlay.hide()
                self.scan_banner.hide()
                self._set_status_spinner(False)
                self.btn_refresh.set_disabled(False)
                self.apply_filters_and_render()
                self._set_status(f"Loaded {len(apps)} applications across Windows sources.")
                if had_apps:
                    self.show_toast(f"Refreshed {len(apps)} applications", "ok")
                self._start_lazy_icon_loader()

            self._safe_after(_done)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_root_destroy(self, event) -> None:
        if event.widget is self.root:
            self._destroyed = True
            self._icon_gen_token += 1

    def _safe_after(self, callback) -> None:
        if self._destroyed:
            return
        try:
            self.root.after(0, callback)
        except tk.TclError:
            pass

    def _start_lazy_icon_loader(self) -> None:
        """Extracts native Windows icons on a background thread without ever blocking the UI."""
        if self._destroyed:
            return
        self._icon_gen_token += 1
        token = self._icon_gen_token
        apps_snapshot = list(self.filtered_apps)

        def _worker() -> None:
            batch: List[str] = []

            def _flush(ids: List[str]) -> None:
                if self._destroyed or token != self._icon_gen_token:
                    return
                for app_id in ids:
                    if self.tree.exists(app_id):
                        tk_img = self.icon_cache.promote_to_tk(app_id, size=self._list_icon_px)
                        if tk_img is not None:
                            self.tree.item(app_id, image=tk_img)

            for app in apps_snapshot:
                if self._destroyed or token != self._icon_gen_token:
                    return
                if self.icon_cache.extract_in_background(app, size=self._list_icon_px):
                    batch.append(app.id)
                    if len(batch) >= 12:
                        flush_ids = list(batch)
                        batch.clear()
                        self._safe_after(lambda ids=flush_ids: _flush(ids))
            if batch and not self._destroyed:
                flush_ids = list(batch)
                self._safe_after(lambda ids=flush_ids: _flush(ids))

        threading.Thread(target=_worker, daemon=True).start()

    def _select_type_filter(self, val: str) -> None:
        self.active_type = val
        for k, chip in self._type_chips.items():
            chip.set_active(k == val)
        self.apply_filters_and_render()

    def _on_system_toggle(self, val: bool) -> None:
        self.show_system = val
        self.apply_filters_and_render()

    def _toggle_selected_only(self) -> None:
        self.selected_only = not self.selected_only
        self.chip_selected_only.set_active(self.selected_only)
        self.apply_filters_and_render()

    def _toggle_quiet_only(self) -> None:
        self.quiet_only = not self.quiet_only
        self.chip_quiet_only.set_active(self.quiet_only)
        self.apply_filters_and_render()

    def _reset_all_filters(self) -> None:
        self.search_bar.reset_silently()
        self.active_type = "ALL"
        for k, chip in self._type_chips.items():
            chip.set_active(k == "ALL")
        self.selected_only = False
        self.chip_selected_only.set_active(False)
        self.quiet_only = False
        self.chip_quiet_only.set_active(False)
        self.apply_filters_and_render()

    def _toggle_inspector(self) -> None:
        if self._inspector_visible:
            self.paned.forget(self.inspector_pane)
            self._inspector_visible = False
            self.btn_toggle_insp.set_text("Show Inspector")
        else:
            self.paned.add(self.inspector_pane, weight=0)
            self._inspector_visible = True
            self.btn_toggle_insp.set_text("Hide Inspector")

    def _sort_by(self, col: str) -> None:
        if self.sort_col == col:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_col = col
            self.sort_desc = col == "size"
        self._update_sort_headers()
        self.apply_filters_and_render()

    def _update_sort_headers(self) -> None:
        arrow = " ▾" if self.sort_desc else " ▴"
        labels = {
            "name": ("#0", "APPLICATION"),
            "version": ("version", "VERSION"),
            "publisher": ("publisher", "PUBLISHER"),
            "size": ("size", "SIZE"),
            "type": ("type", "TYPE"),
            "quiet": ("quiet", "QUIET"),
        }
        for key, (col_id, base) in labels.items():
            self.tree.heading(col_id, text=base + (arrow if key == self.sort_col else ""))

    def apply_filters_and_render(self) -> None:
        query = self.search_bar.get_query()
        # When "Selected Only" filter is active, show ALL checked apps regardless of System Apps toggle
        inc_sys = True if self.selected_only else self.show_system
        criteria = FilterCriteria(
            query=query if query else None,
            include_system=inc_sys,
            include_protected=inc_sys,
            has_quiet_only=self.quiet_only,
        )
        if self.active_type == "PackageMgr":
            pool = [
                a
                for a in self.all_apps
                if a.uninstaller_type in (UninstallerType.CHOCOLATEY, UninstallerType.SCOOP, UninstallerType.WINGET)
            ]
        elif self.active_type != "ALL":
            try:
                criteria.uninstaller_type = UninstallerType(self.active_type)
            except ValueError:
                pass
            pool = self.all_apps
        else:
            pool = self.all_apps

        if self.selected_only:
            pool = [a for a in pool if a.id in self.selected_ids]

        filtered = ScannerManager.filter_entries(pool, criteria)

        key_funcs = {
            "name": lambda a: a.display_name_trimmed.lower(),
            "version": lambda a: (a.display_version or "").lower(),
            "publisher": lambda a: a.publisher_trimmed.lower(),
            "size": lambda a: a.estimated_size_bytes or -1,
            "type": lambda a: a.uninstaller_type.value.lower(),
            "quiet": lambda a: 1 if a.quiet_uninstall_possible else 0,
        }
        filtered.sort(key=key_funcs.get(self.sort_col, key_funcs["name"]), reverse=self.sort_desc)
        self.filtered_apps = filtered

        self.tree.delete(*self.tree.get_children())
        self._hovered_iid = None

        for idx, app in enumerate(self.filtered_apps):
            is_sel = app.id in self.selected_ids
            chk = "☑" if is_sel else "☐"
            icon = self.icon_cache.get_instant_tk_icon(app, size=self._list_icon_px)
            tags = ["odd" if idx % 2 else "even"]
            if is_sel:
                tags.append("checked")
            self.tree.insert(
                "",
                "end",
                iid=app.id,
                text=f"  {chk}  {app.display_name_trimmed}",
                image=icon,
                values=(
                    app.display_version or "—",
                    app.publisher_trimmed or "—",
                    format_size(app.estimated_size_bytes),
                    app.uninstaller_type.value,
                    "✓" if app.quiet_uninstall_possible else "—",
                ),
                tags=tuple(tags),
            )

        self._update_metrics()

        if self._is_scanning_apps and not self.all_apps:
            self.empty_overlay.hide()
        elif not self.filtered_apps and self.all_apps:
            if self.selected_only and not self.selected_ids:
                self.empty_overlay.show(
                    "No Applications Selected",
                    "Check applications with click, Ctrl+Click, Shift+Click, or Space — or disable the Selected filter.",
                    icon="☐",
                    icon_color=Colors.TEXT_MUTED,
                    action_text="Show All Apps",
                    action_cmd=self._reset_all_filters,
                )
            else:
                q_msg = f"No applications match '{query}'." if query else "No applications match the active filters."
                self.empty_overlay.show(
                    "No Matching Applications",
                    q_msg,
                    icon="⌕",
                    icon_color=Colors.TEXT_MUTED,
                    action_text="Reset Filters",
                    action_cmd=self._reset_all_filters,
                )
        else:
            self.empty_overlay.hide()

        if self.filtered_apps:
            target = self.focused_app if (self.focused_app and self.tree.exists(self.focused_app.id)) else self.filtered_apps[0]
            self.tree.selection_set(target.id)
            self._inspect_app(target)
        else:
            self._inspect_app(None)

        self._start_lazy_icon_loader()

    def _update_metrics(self) -> None:
        total = len(self.all_apps)
        quiet = sum(1 for a in self.all_apps if a.quiet_uninstall_possible)
        size_b = sum(a.estimated_size_bytes or 0 for a in self.all_apps)
        sel = len(self.selected_ids)
        sel_size = sum((self.app_by_id[i].estimated_size_bytes or 0) for i in self.selected_ids if i in self.app_by_id)
        pct = f"{(quiet / total * 100):.0f}%" if total > 0 else "0%"

        self.stat_apps_lbl.configure(text=f"{len(self.filtered_apps)}/{total}" if len(self.filtered_apps) != total else str(total))
        self.stat_quiet_lbl.configure(text=f"{quiet} ({pct})")
        self.stat_size_lbl.configure(text=format_size(size_b))
        self.stat_sel_lbl.configure(text=str(sel))
        self._nav_items["apps"].set_badge(str(len(self.filtered_apps)))
        self.btn_uninstall.set_text(f"Uninstall ({sel})" if sel > 0 else "Uninstall")
        self.chip_selected_only.set_text(f"Selected ({sel})")
        self.btn_clear_sel.set_disabled(sel == 0)
        self.btn_sel_all.set_disabled(not bool(self.filtered_apps))

        if sel > 0:
            sz_str = f"  •  ~{format_size(sel_size)}" if sel_size > 0 else ""
            self.selection_summary_lbl.configure(
                text=f"{sel} selected{sz_str}",
                fg=Colors.ACCENT_BLUE_HOVER,
                font=Fonts.small_bold(),
            )
        elif total > 0:
            self.selection_summary_lbl.configure(
                text=f"Showing {len(self.filtered_apps)} of {total} apps  •  {format_size(size_b)}",
                fg=Colors.TEXT_MUTED,
                font=Fonts.small(),
            )
        else:
            self.selection_summary_lbl.configure(text="", fg=Colors.TEXT_MUTED)

    def _on_tree_select(self, _e=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        app = self.app_by_id.get(sel[-1])
        if app:
            self._inspect_app(app)

    def _refresh_row_check_visual(self, app_id: str) -> None:
        app = self.app_by_id.get(app_id)
        if not app or not self.tree.exists(app_id):
            return
        is_sel = app_id in self.selected_ids
        chk = "☑" if is_sel else "☐"
        tags = [t for t in self.tree.item(app_id, "tags") if t != "checked"]
        if is_sel:
            tags.append("checked")
        self.tree.item(app_id, text=f"  {chk}  {app.display_name_trimmed}", tags=tuple(tags))

    def _on_tree_click(self, event) -> Optional[str]:
        col = self.tree.identify_column(event.x)
        row_iid = self.tree.identify_row(event.y)
        if not row_iid:
            return None

        shift_held = bool(event.state & 0x0001)
        ctrl_held = bool(event.state & 0x0004)

        # Shift+Click: check & highlight the entire contiguous range from anchor to clicked row
        if shift_held and self._last_anchor_iid and self.tree.exists(self._last_anchor_iid):
            children = list(self.tree.get_children())
            if self._last_anchor_iid in children and row_iid in children:
                i1 = children.index(self._last_anchor_iid)
                i2 = children.index(row_iid)
                lo, hi = min(i1, i2), max(i1, i2)
                range_iids = children[lo : hi + 1]
                for rid in range_iids:
                    self.selected_ids.add(rid)
                    self._refresh_row_check_visual(rid)
                self.tree.selection_set(range_iids)
                app = self.app_by_id.get(row_iid)
                if app:
                    self._inspect_app(app)
                self._update_metrics()
                return "break"

        # Ctrl+Click anywhere on a row toggles its checkbox while preserving multi-selection
        if ctrl_held:
            self._toggle_app_id(row_iid)
            self._last_anchor_iid = row_iid
            return None

        # Plain click inside checkbox zone of column #0 toggles that row's checkbox
        if col == "#0" and event.x <= dp(58):
            self._toggle_app_id(row_iid)
            self._last_anchor_iid = row_iid
            return None

        self._last_anchor_iid = row_iid
        return None

    def _on_tree_right_click(self, event) -> None:
        row_iid = self.tree.identify_row(event.y)
        if row_iid:
            current_sel = list(self.tree.selection())
            if row_iid not in current_sel:
                self.tree.selection_set(row_iid)
                current_sel = [row_iid]
            app = self.app_by_id.get(row_iid)
            if app:
                self._inspect_app(app)
            self._populate_context_menu(current_sel)
            try:
                self.ctx_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.ctx_menu.grab_release()

    def _on_tree_motion(self, event) -> None:
        row_iid = self.tree.identify_row(event.y)
        if row_iid == self._hovered_iid:
            return
        self._clear_hover()
        if row_iid and self.tree.exists(row_iid):
            tags = list(self.tree.item(row_iid, "tags"))
            if "hover" not in tags:
                tags.append("hover")
                self.tree.item(row_iid, tags=tuple(tags))
            self._hovered_iid = row_iid

    def _on_tree_leave(self, _e=None) -> None:
        self._clear_hover()

    def _clear_hover(self) -> None:
        if self._hovered_iid and self.tree.exists(self._hovered_iid):
            tags = [t for t in self.tree.item(self._hovered_iid, "tags") if t != "hover"]
            self.tree.item(self._hovered_iid, tags=tuple(tags))
        self._hovered_iid = None

    def toggle_focused_selection(self) -> None:
        sel = list(self.tree.selection())
        if not sel:
            return
        if len(sel) == 1:
            self._toggle_app_id(sel[0])
            return
        all_checked = all(app_id in self.selected_ids for app_id in sel)
        self._set_highlighted_checked(not all_checked)

    def _set_highlighted_checked(self, checked: bool) -> None:
        for app_id in self.tree.selection():
            if app_id not in self.app_by_id:
                continue
            if checked:
                self.selected_ids.add(app_id)
            else:
                self.selected_ids.discard(app_id)
            self._refresh_row_check_visual(app_id)
        if self.selected_only and not checked:
            self.apply_filters_and_render()
        else:
            self._update_metrics()

    def _toggle_app_id(self, app_id: str) -> None:
        app = self.app_by_id.get(app_id)
        if not app:
            return
        if app_id in self.selected_ids:
            self.selected_ids.remove(app_id)
        else:
            self.selected_ids.add(app_id)
        self._refresh_row_check_visual(app_id)
        if self.selected_only and app_id not in self.selected_ids:
            self.apply_filters_and_render()
        else:
            self._update_metrics()

    def select_all_visible(self) -> None:
        if not self.filtered_apps:
            return
        for a in self.filtered_apps:
            self.selected_ids.add(a.id)
            self._refresh_row_check_visual(a.id)
        self._update_metrics()

    def clear_selection(self) -> None:
        if not self.selected_ids:
            return
        prev = list(self.selected_ids)
        self.selected_ids.clear()
        if self.selected_only:
            self.selected_only = False
            self.chip_selected_only.set_active(False)
            self.apply_filters_and_render()
        else:
            for app_id in prev:
                self._refresh_row_check_visual(app_id)
            self._update_metrics()

    def toggle_select_all_visible(self) -> None:
        if not self.filtered_apps:
            return
        vis_ids = {a.id for a in self.filtered_apps}
        if vis_ids.issubset(self.selected_ids):
            self.selected_ids.difference_update(vis_ids)
        else:
            self.selected_ids.update(vis_ids)
        self.apply_filters_and_render()

    def _inspect_app(self, app: Optional[ApplicationEntry]) -> None:
        self.focused_app = app
        if not app:
            self.insp_icon_lbl.configure(image="")
            self.insp_name_lbl.configure(text="No application selected")
            self.insp_pub_lbl.configure(text="")
            self.insp_url_lbl.pack_forget()
            for lbl in (self.prop_ver, self.prop_size, self.prop_type, self.prop_quiet, self.prop_arch, self.prop_sig, self.prop_flags):
                lbl.configure(text="-", fg=Colors.TEXT_PRIMARY)
            self._set_well(self.well_cmd, "-")
            self._set_well(self.well_loc, "-")
            self._set_well(self.well_reg, "-")
            for b in (self.btn_qa_folder, self.btn_qa_reg, self.btn_qa_sig, self.btn_qa_copy, self.btn_qa_uninst):
                b.set_disabled(True)
            return

        # Instant 48dp icon + background high-res extraction
        hero_icon = self.icon_cache.get_instant_tk_icon(app, size=self._hero_icon_px)
        self.insp_icon_lbl.configure(image=hero_icon)
        self._load_hero_icon_async(app)

        self.insp_name_lbl.configure(text=app.display_name_trimmed)
        self.insp_pub_lbl.configure(text=app.publisher_trimmed or "Unknown publisher")

        if app.about_url and app.about_url.startswith(("http://", "https://")):
            self.insp_url_lbl.configure(text="Website ↗")
            if not self.insp_url_lbl.winfo_ismapped():
                self.insp_url_lbl.pack(anchor="w", pady=(3, 0))
        else:
            self.insp_url_lbl.pack_forget()

        self.prop_ver.configure(text=app.display_version or "N/A")
        self.prop_size.configure(text=format_size(app.estimated_size_bytes))
        self.prop_type.configure(text=f"{app.uninstaller_type.value} ({app.source_scanner})")
        self.prop_quiet.configure(
            text="Supported" if app.quiet_uninstall_possible else "Loud Only",
            fg=Colors.ACCENT_GREEN_HOVER if app.quiet_uninstall_possible else Colors.ACCENT_AMBER_HOVER,
        )
        self.prop_arch.configure(text="64-bit Native" if app.is_64_bit else "32-bit / Universal")

        cached_sig = self._sig_cache.get(app.id)
        if cached_sig is not None:
            ok_s, signer = cached_sig
            short_signer = (signer.split(",")[0].replace("CN=", "") if signer else "Unsigned")
            self.prop_sig.configure(
                text=f"✓ {short_signer}" if ok_s else "Unverified",
                fg=Colors.ACCENT_GREEN_HOVER if ok_s else Colors.ACCENT_AMBER_HOVER,
            )
        else:
            self.prop_sig.configure(text="Click 'Verify Sig'", fg=Colors.TEXT_MUTED)

        flags = []
        if app.is_system_component:
            flags.append("System")
        if app.is_protected:
            flags.append("Protected")
        if app.raw_metadata.get("WingetId"):
            flags.append("Winget")
        self.prop_flags.configure(
            text=", ".join(flags) if flags else "Standard",
            fg=Colors.ACCENT_RED_HOVER if app.is_protected else Colors.TEXT_PRIMARY,
        )

        cmd_txt = app.quiet_uninstall_string or app.uninstall_string or "No uninstaller command"
        self._set_well(self.well_cmd, cmd_txt)
        self._set_well(self.well_loc, app.install_location or "Not specified")
        self._set_well(self.well_reg, app.registry_path or "N/A")

        self.btn_qa_folder.set_disabled(not bool(app.install_location and os.path.exists(app.install_location)))
        self.btn_qa_reg.set_disabled(not bool(app.registry_path))
        self.btn_qa_sig.set_disabled(False)
        self.btn_qa_copy.set_disabled(not bool(app.quiet_uninstall_string or app.uninstall_string))
        self.btn_qa_uninst.set_disabled(app.is_protected)

    def _load_hero_icon_async(self, app: ApplicationEntry) -> None:
        if self._destroyed:
            return
        target_id = app.id
        hero_px = self._hero_icon_px

        def _worker() -> None:
            if self._destroyed:
                return
            if self.icon_cache.extract_in_background(app, size=hero_px):
                def _apply() -> None:
                    if not self._destroyed and self.focused_app and self.focused_app.id == target_id:
                        img = self.icon_cache.promote_to_tk(target_id, size=hero_px)
                        if img is not None:
                            self.insp_icon_lbl.configure(image=img)

                self._safe_after(_apply)

        threading.Thread(target=_worker, daemon=True).start()

    def _open_focused_url(self, _e=None) -> None:
        if self.focused_app and self.focused_app.about_url:
            webbrowser.open(self.focused_app.about_url)

    def _open_focused_folder(self) -> None:
        if not self.focused_app or not self.focused_app.install_location:
            return
        loc = self.focused_app.install_location
        if os.path.exists(loc) and IS_WINDOWS:
            os.startfile(loc)  # type: ignore[attr-defined]
            self._set_status(f"Opened folder: {loc}")

    def _open_focused_regedit(self) -> None:
        if not self.focused_app or not self.focused_app.registry_path:
            return
        ok, msg = _open_regedit_at_key(self.focused_app.registry_path)
        self._set_status(msg)

    def _verify_focused_signature(self) -> None:
        app = self.focused_app
        if not app:
            return
        from bcu.enrichers.detector import extract_executable_path

        exe = None
        if app.uninstall_string:
            cand = extract_executable_path(os.path.expandvars(app.uninstall_string))
            if cand and os.path.exists(cand):
                exe = cand
        if not exe and app.install_location and os.path.isdir(app.install_location):
            for f in os.listdir(app.install_location):
                if f.lower().endswith(".exe"):
                    exe = os.path.join(app.install_location, f)
                    break
        if not exe:
            self.prop_sig.configure(text="No binary found", fg=Colors.TEXT_MUTED)
            self._set_status("Could not locate an executable to verify signature.")
            return

        self.prop_sig.configure(text="Verifying...", fg=Colors.ACCENT_BLUE_HOVER)
        self._set_status_spinner(True)
        self._set_status(f"Verifying Authenticode signature of {os.path.basename(exe)}...")
        app_id = app.id

        def _worker() -> None:
            ok_s, signer = verify_authenticode_signature(exe)
            self._sig_cache[app_id] = (ok_s, signer)

            def _done() -> None:
                if not self._is_scanning_apps:
                    self._set_status_spinner(False)
                short_signer = (signer.split(",")[0].replace("CN=", "") if signer else "Unsigned")
                if self.focused_app and self.focused_app.id == app_id:
                    self.prop_sig.configure(
                        text=f"✓ {short_signer}" if ok_s else "Unverified",
                        fg=Colors.ACCENT_GREEN_HOVER if ok_s else Colors.ACCENT_AMBER_HOVER,
                    )
                self._set_status(f"Signature check ({os.path.basename(exe)}): {'Valid - ' + str(signer) if ok_s else 'Not validly signed'}")
                self.show_toast(
                    f"Valid signature: {short_signer}" if ok_s else f"Not validly signed ({os.path.basename(exe)})",
                    "ok" if ok_s else "warn",
                )

            self._safe_after(_done)

        threading.Thread(target=_worker, daemon=True).start()

    def _copy_to_clipboard(self, text: str, label: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._set_status(f"Copied {label} to clipboard.")
        self.show_toast(f"Copied {label}", "info")

    def _copy_focused_cmd(self) -> None:
        if not self.focused_app:
            return
        cmd = self.focused_app.quiet_uninstall_string or self.focused_app.uninstall_string
        if cmd:
            self._copy_to_clipboard(cmd, "uninstall command")

    def _copy_focused_id(self) -> None:
        if self.focused_app:
            self._copy_to_clipboard(self.focused_app.id, "application ID")

    def _copy_focused_path(self) -> None:
        if self.focused_app and self.focused_app.install_location:
            self._copy_to_clipboard(self.focused_app.install_location, "install directory")

    def _copy_focused_reg(self) -> None:
        if self.focused_app and self.focused_app.registry_path:
            self._copy_to_clipboard(self.focused_app.registry_path, "registry path")

    def _uninstall_focused_only(self) -> None:
        if not self.focused_app:
            return
        self._open_uninstall_for([self.focused_app])

    def _uninstall_highlighted(self) -> None:
        targets = [self.app_by_id[i] for i in self.tree.selection() if i in self.app_by_id]
        if targets:
            self._open_uninstall_for(targets)

    def open_uninstall_dialog(self) -> None:
        targets = [a for a in self.all_apps if a.id in self.selected_ids]
        if not targets and self.focused_app:
            targets = [self.focused_app]
        if not targets:
            self._set_status("Select one or more applications first.")
            return
        self._open_uninstall_for(targets)

    def _open_uninstall_for(self, targets: List[ApplicationEntry]) -> None:
        def _after(completed: bool) -> None:
            if completed:
                self.selected_ids.clear()
                self.load_applications_async(force_refresh=True)

        UninstallDialog(self.root, target_apps=targets, all_apps=self.all_apps, on_completed=_after)

    def _export_inventory(self, fmt: str) -> None:
        if not self.all_apps:
            self._set_status("Wait for application scan to finish before exporting.")
            return
        ext = ".json" if fmt == "json" else ".csv"
        filetypes = [("JSON Files", "*.json")] if fmt == "json" else [("CSV Files", "*.csv")]
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title=f"Export Application Inventory ({fmt.upper()})",
            defaultextension=ext,
            initialfile=f"bcu_apps{ext}",
            filetypes=filetypes,
        )
        if not path:
            return
        try:
            if fmt == "csv":
                ApplicationSerializer.export_csv(self.filtered_apps or self.all_apps, path)
            else:
                ApplicationSerializer.export_json(self.filtered_apps or self.all_apps, path)
            self._set_status(f"Exported {len(self.filtered_apps or self.all_apps)} apps to {path}")
            self.show_toast(f"Exported {len(self.filtered_apps or self.all_apps)} apps ({fmt.upper()})", "ok")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc), parent=self.root)

    def _elevate(self) -> None:
        if _relaunch_as_admin():
            self.root.destroy()
        else:
            self._set_status("Elevation cancelled or failed.")

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    """Entrypoint launching the modern Tkinter Desktop GUI."""
    hide_dedicated_console_if_owned()
    app = BcuGuiApp()
    app.run()


if __name__ == "__main__":
    main()
