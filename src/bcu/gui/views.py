"""
First-class Desktop GUI views and dialogs for BCU:
  - UninstallDialog: bulk uninstaller with Apple toggles, animated spinner, progress bar & colored log
  - OrphansView: Revo/BCU-style verified orphaned leftovers cleaner with loading overlay, multi-select,
                 selected-only filter, category counts, instant removal + auto-rescan, and active-app guard
  - AuditView: CVE security audit page with animated loading overlay, severity counts & clickable advisories
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk
import webbrowser
from typing import Callable, Dict, List, Optional, Set

from bcu.engine.batch import BatchUninstallQueue
from bcu.gui.theme import Colors, Fonts, apply_windows_dark_titlebar
from bcu.gui.widgets import (
    AppleToggle,
    EmptyStateOverlay,
    FilterChip,
    LoadingOverlay,
    ModernButton,
    ModernSearchBar,
    ScanningBanner,
    SpinnerRing,
)
from bcu.junk.cleaner import JunkCleaner
from bcu.models import (
    ApplicationEntry,
    ConfidenceLevel,
    JunkItem,
    JunkType,
    SeverityLevel,
    UninstallResult,
    VulnerabilityFinding,
    VulnerabilityReport,
)
from bcu.security.auditor import VulnerabilityAuditor
from bcu.utils.formatting import format_size
from bcu.utils.platform import is_admin


def _configure_log_tags(text_widget: tk.Text) -> None:
    text_widget.tag_configure("info", foreground=Colors.ACCENT_BLUE_HOVER)
    text_widget.tag_configure("ok", foreground=Colors.ACCENT_GREEN_HOVER)
    text_widget.tag_configure("err", foreground=Colors.ACCENT_RED_HOVER)
    text_widget.tag_configure("warn", foreground=Colors.ACCENT_AMBER_HOVER)
    text_widget.tag_configure("dim", foreground=Colors.TEXT_MUTED)
    text_widget.tag_configure("bold", foreground=Colors.TEXT_PRIMARY, font=Fonts.mono())


def _append_log(text_widget: tk.Text, message: str, tag: str = "") -> None:
    text_widget.configure(state="normal")
    if tag:
        text_widget.insert("end", message + "\n", tag)
    else:
        text_widget.insert("end", message + "\n")
    text_widget.see("end")
    text_widget.configure(state="disabled")


class UninstallDialog(tk.Toplevel):
    """Sleek centered modal dialog for confirming and executing bulk uninstalls."""

    def __init__(
        self,
        parent: tk.Misc,
        target_apps: List[ApplicationEntry],
        all_apps: List[ApplicationEntry],
        on_completed: Optional[Callable[[bool], None]] = None,
    ) -> None:
        super().__init__(parent)
        self.target_apps = target_apps
        self.all_apps = all_apps
        self.on_completed = on_completed
        self.results: List[UninstallResult] = []
        self._is_running = False

        self.title("Bulk Uninstallation Manager")
        self.configure(bg=Colors.BG_BASE)
        self.transient(parent)
        self.grab_set()
        self.minsize(700, 580)

        w, h = 760, 630
        parent.update_idletasks()
        px = parent.winfo_rootx() + max(0, (parent.winfo_width() - w) // 2)
        py = parent.winfo_rooty() + max(0, (parent.winfo_height() - h) // 2)
        self.geometry(f"{w}x{h}+{px}+{py}")
        apply_windows_dark_titlebar(self)

        self.protocol("WM_DELETE_WINDOW", self._close)
        self.bind("<Escape>", lambda _e: self._close())

        self._build_ui()

    def _build_ui(self) -> None:
        outer = tk.Frame(self, bg=Colors.BG_BASE, padx=22, pady=18)
        outer.pack(fill="both", expand=True)

        total_bytes = sum(a.estimated_size_bytes or 0 for a in self.target_apps)
        size_suffix = f"  •  ~{format_size(total_bytes)}" if total_bytes > 0 else ""

        tk.Label(
            outer,
            text=f"Uninstall {len(self.target_apps)} Application{'s' if len(self.target_apps) != 1 else ''}{size_suffix}",
            bg=Colors.BG_BASE,
            fg=Colors.TEXT_PRIMARY,
            font=Fonts.hero(),
            anchor="w",
        ).pack(fill="x")
        tk.Label(
            outer,
            text="Review targets and safety options before executing. Post-uninstall cleanup runs only after uninstall succeeds.",
            bg=Colors.BG_BASE,
            fg=Colors.TEXT_SECONDARY,
            font=Fonts.small(),
            anchor="w",
        ).pack(fill="x", pady=(2, 12))

        list_border = tk.Frame(outer, bg=Colors.BORDER, padx=1, pady=1)
        list_border.pack(fill="x", pady=(0, 12))
        list_box = tk.Frame(list_border, bg=Colors.BG_SURFACE)
        list_box.pack(fill="both", expand=True)

        app_text = tk.Text(
            list_box,
            height=min(5, max(2, len(self.target_apps))),
            bg=Colors.BG_SURFACE,
            fg=Colors.TEXT_PRIMARY,
            font=Fonts.small(),
            relief="flat",
            bd=0,
            padx=10,
            pady=6,
            wrap="none",
        )
        app_text.tag_configure("name", foreground=Colors.TEXT_PRIMARY, font=Fonts.small_bold())
        app_text.tag_configure("meta", foreground=Colors.TEXT_MUTED, font=Fonts.small())
        app_text.tag_configure("prot", foreground=Colors.ACCENT_RED_HOVER, font=Fonts.micro())
        for app in self.target_apps:
            app_text.insert("end", f"•  {app.display_name_trimmed}  ", "name")
            app_text.insert("end", f"({app.uninstaller_type.value})", "meta")
            if app.is_protected:
                app_text.insert("end", "   [PROTECTED - WILL SKIP]", "prot")
            app_text.insert("end", "\n")
        app_text.configure(state="disabled")
        app_text.pack(fill="x")

        opts_border = tk.Frame(outer, bg=Colors.BORDER_SUBTLE, padx=1, pady=1)
        opts_border.pack(fill="x", pady=(0, 12))
        opts = tk.Frame(opts_border, bg=Colors.BG_SURFACE, padx=14, pady=12)
        opts.pack(fill="both", expand=True)
        opts.columnconfigure(0, weight=1)
        opts.columnconfigure(1, weight=1)

        self.tog_quiet = AppleToggle(opts, "Prefer Quiet / Silent Mode", initial=True, subtitle="Run unattended switches when supported", bg=Colors.BG_SURFACE)
        self.tog_dryrun = AppleToggle(opts, "Dry-Run Simulation Only", initial=False, subtitle="Preview actions & remnants with no changes", bg=Colors.BG_SURFACE)
        self.tog_junk = AppleToggle(opts, "Clean Post-Uninstall Leftovers", initial=True, subtitle="Clean leftover folders, keys & services after", bg=Colors.BG_SURFACE)
        self.tog_kill = AppleToggle(opts, "Terminate Locking Processes", initial=True, subtitle="Close app processes to prevent file locks", bg=Colors.BG_SURFACE)
        self.tog_backup = AppleToggle(opts, "Auto .reg Registry Backup", initial=True, subtitle="Export rollback .reg files before cleanup", bg=Colors.BG_SURFACE)
        self.tog_restore = AppleToggle(opts, "Create Restore Point (Admin)", initial=False, subtitle="Windows System Restore point before batch", bg=Colors.BG_SURFACE)

        self.tog_quiet.grid(row=0, column=0, sticky="w", pady=(0, 8), padx=(0, 14))
        self.tog_dryrun.grid(row=0, column=1, sticky="w", pady=(0, 8))
        self.tog_junk.grid(row=1, column=0, sticky="w", pady=(0, 8), padx=(0, 14))
        self.tog_kill.grid(row=1, column=1, sticky="w", pady=(0, 8))
        self.tog_backup.grid(row=2, column=0, sticky="w", padx=(0, 14))
        self.tog_restore.grid(row=2, column=1, sticky="w")

        # Footer buttons packed side="bottom" FIRST so expanding log never pushes them off-screen
        footer = tk.Frame(outer, bg=Colors.BG_BASE)
        footer.pack(side="bottom", fill="x", pady=(12, 0))

        self._run_spinner = SpinnerRing(footer, size=18, stroke=2, bg=Colors.BG_BASE)
        self._run_status = tk.Label(footer, text="", bg=Colors.BG_BASE, fg=Colors.ACCENT_BLUE_HOVER, font=Fonts.small_bold())

        self.btn_close = ModernButton(footer, "Cancel", command=self._close, variant="secondary", width=110, height=34, bg_matte=Colors.BG_BASE)
        self.btn_close.pack(side="right")

        self.btn_start = ModernButton(
            footer,
            "Start Uninstall",
            command=self._start,
            variant="danger",
            width=150,
            height=34,
            bg_matte=Colors.BG_BASE,
        )
        self.btn_start.pack(side="right", padx=(0, 10))

        # Progress bar
        self.progress = ttk.Progressbar(
            outer,
            style="Modern.Horizontal.TProgressbar",
            mode="determinate",
            maximum=max(1, len(self.target_apps)),
        )
        self.progress.pack(fill="x", pady=(0, 10))

        # Live execution log console
        log_border = tk.Frame(outer, bg=Colors.BORDER, padx=1, pady=1)
        log_border.pack(fill="both", expand=True)
        log_frame = tk.Frame(log_border, bg=Colors.BG_CODE)
        log_frame.pack(fill="both", expand=True)

        self.log = tk.Text(
            log_frame,
            height=8,
            bg=Colors.BG_CODE,
            fg=Colors.TEXT_SECONDARY,
            font=Fonts.mono(),
            relief="flat",
            bd=0,
            padx=10,
            pady=8,
            wrap="word",
            state="disabled",
        )
        _configure_log_tags(self.log)
        sb = ttk.Scrollbar(log_frame, orient="vertical", style="Modern.TScrollbar", command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        self.log.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        _append_log(self.log, f"Ready to process {len(self.target_apps)} application(s).", "dim")

    def _close(self) -> None:
        if self._is_running:
            return
        completed = bool(self.results)
        self.destroy()
        if self.on_completed:
            self.on_completed(completed)

    def _start(self) -> None:
        if self._is_running:
            return
        self._is_running = True
        self.btn_start.set_disabled(True)
        self.btn_close.set_disabled(True)
        self.progress["value"] = 0
        self._run_spinner.pack(side="left", padx=(0, 8))
        self._run_spinner.start()
        self._run_status.configure(text="Running uninstallation batch...")
        self._run_status.pack(side="left")

        opts = {
            "prefer_quiet": self.tog_quiet.value,
            "dry_run": self.tog_dryrun.value,
            "clean_junk": self.tog_junk.value,
            "deep_junk": self.tog_junk.value,
            "kill_running": self.tog_kill.value,
            "backup_registry": self.tog_backup.value,
            "create_restore_point": self.tog_restore.value,
        }
        threading.Thread(target=self._worker, kwargs=opts, daemon=True).start()

    def _worker(self, **opts) -> None:
        if opts["dry_run"]:
            self.after(0, lambda: _append_log(self.log, ">>> DRY-RUN SIMULATION ACTIVE — NO CHANGES WILL BE MADE <<<", "warn"))
        else:
            self.after(0, lambda: _append_log(self.log, "Starting uninstallation batch...", "info"))

        queue = BatchUninstallQueue(
            apps=self.target_apps,
            junk_min_confidence=ConfidenceLevel.GOOD,
            all_apps=self.all_apps,
            **opts,
        )

        def on_start(app: ApplicationEntry, idx: int, total: int) -> None:
            def _u() -> None:
                self._run_status.configure(text=f"[{idx}/{total}] Uninstalling {app.display_name_trimmed}...")
                _append_log(self.log, f"\n[{idx}/{total}] Processing {app.display_name_trimmed}...", "info")

            self.after(0, _u)

        def on_prog(msg: str) -> None:
            self.after(0, lambda m=msg: _append_log(self.log, f"  -> {m}", "dim"))

        def on_finish(res: UninstallResult, idx: int, total: int) -> None:
            def _ui() -> None:
                self.progress["value"] = idx
                if res.status.value == "Completed":
                    _append_log(
                        self.log,
                        f"✓ Completed: {res.app_name} ({res.duration_sec:.1f}s, {res.junk_cleaned_count} remnants)",
                        "ok",
                    )
                else:
                    _append_log(self.log, f"✗ Failed: {res.app_name} — {res.error_message or 'Unknown error'}", "err")

            self.after(0, _ui)

        try:
            self.results = queue.run(on_app_start=on_start, on_app_finish=on_finish, on_progress=on_prog)
        except Exception as exc:
            self.after(0, lambda e=str(exc): _append_log(self.log, f"Unexpected error: {e}", "err"))

        def _done() -> None:
            self._is_running = False
            self._run_spinner.stop()
            self._run_spinner.pack_forget()
            ok_cnt = sum(1 for r in self.results if r.status.value == "Completed")
            self._run_status.configure(text=f"Done: {ok_cnt}/{len(self.results)} succeeded", fg=Colors.ACCENT_GREEN_HOVER)
            _append_log(self.log, f"\nBatch complete: {ok_cnt}/{len(self.results)} succeeded.", "ok")
            self.btn_close.set_text("Close")
            self.btn_close.set_disabled(False)

        self.after(0, _done)


class OrphansView(tk.Frame):
    """
    Revo / BCU-style Orphaned Leftovers Cleaner integrated as a main window page.
    Only scans verified broken remnants from already-removed apps; blocks active installed apps.
    Supports Ctrl/Shift multi-select, selected-only filtering, live loading spinner, and auto-rescan after clean.
    """

    CATEGORY_FILTERS = [
        ("All", "ALL"),
        ("Ghost Keys", JunkType.REGISTRY_KEY.value),
        ("Shortcuts", JunkType.SHORTCUT.value),
        ("Startup", JunkType.STARTUP_ENTRY.value),
        ("Services", JunkType.SERVICE.value),
        ("App Paths", JunkType.APP_PATH.value),
        ("Firewall", JunkType.FIREWALL_RULE.value),
        ("COM", JunkType.COM_CLSID.value),
        ("AppCompat", JunkType.APP_COMPAT.value),
        ("Dumps", JunkType.CRASH_DUMP.value),
    ]

    def __init__(
        self,
        parent: tk.Misc,
        get_all_apps: Callable[[], List[ApplicationEntry]],
        on_count_changed: Optional[Callable[[int], None]] = None,
        on_toast: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        super().__init__(parent, bg=Colors.BG_BASE)
        self._get_all_apps = get_all_apps
        self._on_count_changed = on_count_changed
        self._on_toast = on_toast
        self.all_items: List[JunkItem] = []
        self.visible_indices: List[int] = []
        self.selected_indices: Set[int] = set()
        self.active_category: str = "ALL"
        self.selected_only: bool = False
        self._is_busy = False
        self._has_scanned = False
        self._last_scan_mode: str = "system"
        self._last_removed_query: str = ""
        self._last_anchor_iid: Optional[str] = None
        self._chips: Dict[str, FilterChip] = {}

        self._build_ui()

    def _toast(self, msg: str, tone: str = "info") -> None:
        if self._on_toast:
            self._on_toast(msg, tone)

    def _build_ui(self) -> None:
        hdr = tk.Frame(self, bg=Colors.BG_BASE, padx=20, pady=14)
        hdr.pack(fill="x")

        title_col = tk.Frame(hdr, bg=Colors.BG_BASE)
        title_col.pack(side="left", fill="x", expand=True)
        tk.Label(title_col, text="Orphaned Leftovers Cleaner", bg=Colors.BG_BASE, fg=Colors.TEXT_PRIMARY, font=Fonts.hero(), anchor="w").pack(fill="x")
        tk.Label(
            title_col,
            text="Scans broken remnants from already-removed apps only. Active installed apps are strictly protected.",
            bg=Colors.BG_BASE,
            fg=Colors.TEXT_SECONDARY,
            font=Fonts.small(),
            anchor="w",
        ).pack(fill="x", pady=(2, 0))

        self.btn_scan_orphans = ModernButton(
            hdr,
            "Scan System Orphans",
            command=self.scan_system_orphans,
            variant="primary",
            width=165,
            height=34,
            bg_matte=Colors.BG_BASE,
        )
        self.btn_scan_orphans.pack(side="right")

        # Removed-App Manual Search Bar
        search_row = tk.Frame(self, bg=Colors.BG_BASE, padx=20)
        search_row.pack(fill="x", pady=(0, 10))

        self.removed_search = ModernSearchBar(
            search_row,
            placeholder="Or search remnants of a previously REMOVED app (e.g. Spotify, McAfee)...",
            on_submit=lambda _q: self._trigger_removed_scan(),
            on_escape=lambda: self.tree.focus_set(),
        )
        self.removed_search.pack(side="left", fill="x", expand=True)

        self.btn_find_removed = ModernButton(
            search_row,
            "Find Removed App",
            command=self._trigger_removed_scan,
            variant="secondary",
            width=145,
            height=34,
            bg_matte=Colors.BG_BASE,
        )
        self.btn_find_removed.pack(side="left", padx=(10, 0))

        # Category Filter Chips
        chips_bar = tk.Frame(self, bg=Colors.BG_BASE, padx=20)
        chips_bar.pack(fill="x", pady=(0, 8))
        for label, val in self.CATEGORY_FILTERS:
            chip = FilterChip(chips_bar, label, val, on_select=self._select_category, active=(val == "ALL"))
            chip.pack(side="left", padx=(0, 5))
            self._chips[val] = chip

        # Table Container with animated overlays
        tbl_border = tk.Frame(self, bg=Colors.BORDER_SUBTLE, padx=1, pady=1)
        tbl_border.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        self.tbl_frame = tk.Frame(tbl_border, bg=Colors.BG_SURFACE)
        self.tbl_frame.pack(fill="both", expand=True)

        self.scan_banner = ScanningBanner(self.tbl_frame)

        tree_host = tk.Frame(self.tbl_frame, bg=Colors.BG_SURFACE)
        tree_host.pack(fill="both", expand=True)
        self._tree_host = tree_host

        cols = ("chk", "type", "conf", "app", "path", "reason")
        self.tree = ttk.Treeview(tree_host, columns=cols, show="headings", style="Compact.Treeview", selectmode="extended")
        self.tree.heading("chk", text="✓")
        self.tree.heading("type", text="TYPE")
        self.tree.heading("conf", text="CONFIDENCE")
        self.tree.heading("app", text="SOURCE / APP")
        self.tree.heading("path", text="TARGET PATH / KEY")
        self.tree.heading("reason", text="WHY ORPHANED")

        self.tree.column("chk", width=36, minwidth=36, stretch=False, anchor="center")
        self.tree.column("type", width=110, minwidth=95, stretch=False, anchor="w")
        self.tree.column("conf", width=90, minwidth=80, stretch=False, anchor="center")
        self.tree.column("app", width=160, minwidth=120, stretch=False, anchor="w")
        self.tree.column("path", width=320, minwidth=180, stretch=True, anchor="w")
        self.tree.column("reason", width=290, minwidth=180, stretch=True, anchor="w")

        self.tree.tag_configure("odd", background=Colors.BG_ROW_ALT)
        self.tree.tag_configure("even", background=Colors.BG_SURFACE)
        self.tree.tag_configure("hover", background=Colors.BG_HOVER)
        self.tree.tag_configure("checked", foreground="#93C5FD")
        self._hovered_iid: Optional[str] = None

        vsb = ttk.Scrollbar(tree_host, orient="vertical", style="Modern.TScrollbar", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.loading_overlay = LoadingOverlay(tree_host)
        self.empty_overlay = EmptyStateOverlay(tree_host)

        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Double-1>", lambda _e: self._toggle_focused_rows())
        self.tree.bind("<space>", lambda _e: self._toggle_focused_rows())
        self.tree.bind("<Button-3>", self._on_tree_right_click)
        self.tree.bind("<Motion>", self._on_tree_motion)
        self.tree.bind("<Leave>", self._on_tree_leave)

        self.ctx_menu = tk.Menu(
            self,
            tearoff=0,
            bg=Colors.BG_ELEVATED,
            fg=Colors.TEXT_PRIMARY,
            activebackground=Colors.BG_SELECTED,
            activeforeground="#FFFFFF",
            bd=1,
            relief="flat",
            font=Fonts.small(),
        )
        self.ctx_menu.add_command(label="Toggle Highlighted  (Space)", command=self._toggle_focused_rows)
        self.ctx_menu.add_command(label="Check Highlighted", command=lambda: self._set_highlighted_checked(True))
        self.ctx_menu.add_command(label="Uncheck Highlighted", command=lambda: self._set_highlighted_checked(False))
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Copy Path / Registry Key", command=self._copy_focused_path)

        # Controls Bar
        ctrl = tk.Frame(self, bg=Colors.BG_BASE, padx=20)
        ctrl.pack(fill="x", pady=(0, 8))

        self.chip_selected_only = FilterChip(
            ctrl,
            "Selected (0)",
            "SELECTED",
            on_select=lambda _v: self._toggle_selected_only(),
            active=False,
        )
        self.chip_selected_only.pack(side="left", padx=(0, 8))

        self.btn_sel_all = ModernButton(ctrl, "Select Visible", command=self._select_visible, variant="secondary", width=102, height=28, bg_matte=Colors.BG_BASE)
        self.btn_sel_all.pack(side="left", padx=(0, 6))
        self.btn_sel_none = ModernButton(ctrl, "Clear Selection", command=self._deselect_all, variant="secondary", width=108, height=28, bg_matte=Colors.BG_BASE, disabled=True)
        self.btn_sel_none.pack(side="left", padx=(0, 14))

        self.tog_dryrun = AppleToggle(
            ctrl,
            "Dry-Run Preview",
            initial=False,
            on_change=lambda _v: self._update_clean_button(),
            bg=Colors.BG_BASE,
        )
        self.tog_dryrun.pack(side="left", padx=(0, 14))
        self.tog_backup = AppleToggle(ctrl, "Auto .reg Backup", initial=True, bg=Colors.BG_BASE)
        self.tog_backup.pack(side="left")

        self.btn_clean = ModernButton(
            ctrl,
            "Delete Selected (0)",
            command=self._start_clean,
            variant="danger",
            width=172,
            height=32,
            bg_matte=Colors.BG_BASE,
            disabled=True,
        )
        self.btn_clean.pack(side="right")

        # Slim Output Log
        log_border = tk.Frame(self, bg=Colors.BORDER_SUBTLE, padx=1, pady=1)
        log_border.pack(fill="x", padx=20, pady=(0, 14))
        log_wrap = tk.Frame(log_border, bg=Colors.BG_CODE)
        log_wrap.pack(fill="x")

        self.log = tk.Text(
            log_wrap,
            height=5,
            bg=Colors.BG_CODE,
            fg=Colors.TEXT_SECONDARY,
            font=Fonts.mono_small(),
            relief="flat",
            bd=0,
            padx=10,
            pady=6,
            wrap="word",
            state="disabled",
        )
        _configure_log_tags(self.log)
        lsb = ttk.Scrollbar(log_wrap, orient="vertical", style="Modern.TScrollbar", command=self.log.yview)
        self.log.configure(yscrollcommand=lsb.set)
        self.log.pack(side="left", fill="x", expand=True)
        lsb.pack(side="right", fill="y")

        _append_log(self.log, "Click 'Scan System Orphans' to discover broken remnants left behind by removed apps.", "dim")
        if not is_admin():
            _append_log(self.log, "Tip: Running as standard user. Elevate to Admin to clean HKLM, Services, and Firewall orphans.", "dim")

    def _select_category(self, val: str) -> None:
        self.active_category = val
        for k, chip in self._chips.items():
            chip.set_active(k == val)
        self._render_tree()

    def _toggle_selected_only(self) -> None:
        self.selected_only = not self.selected_only
        self.chip_selected_only.set_active(self.selected_only)
        self._render_tree()

    def _update_category_chip_counts(self) -> None:
        counts: Dict[str, int] = {}
        for item in self.all_items:
            t = item.junk_type.value
            counts[t] = counts.get(t, 0) + 1
        for label, val in self.CATEGORY_FILTERS:
            if val == "ALL":
                txt = f"All ({len(self.all_items)})" if self._has_scanned else "All"
            else:
                n = counts.get(val, 0)
                txt = f"{label} ({n})" if n > 0 else label
            self._chips[val].set_text(txt)

    def _render_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.visible_indices.clear()
        self._hovered_iid = None

        for idx, item in enumerate(self.all_items):
            if self.active_category != "ALL" and item.junk_type.value != self.active_category:
                continue
            if self.selected_only and idx not in self.selected_indices:
                continue
            self.visible_indices.append(idx)
            is_sel = idx in self.selected_indices
            chk = "☑" if is_sel else "☐"
            reason = item.reasons[0] if item.reasons else ""
            tags = ["odd" if len(self.visible_indices) % 2 else "even"]
            if is_sel:
                tags.append("checked")
            self.tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(chk, item.junk_type.value, item.confidence_level.value, item.app_name, item.path, reason),
                tags=tuple(tags),
            )

        self._update_category_chip_counts()
        self._update_clean_button()

        if self._is_busy:
            self.empty_overlay.hide()
        elif not self.visible_indices:
            if not self._has_scanned:
                self.empty_overlay.show(
                    "Scan for Orphaned Leftovers",
                    "Discover ghost uninstall keys, broken shortcuts, dead startup entries, services, and firewall rules left behind by removed apps.",
                    icon="✦",
                    icon_color=Colors.ACCENT_BLUE_HOVER,
                    action_text="Scan System Orphans",
                    action_cmd=self.scan_system_orphans,
                )
            elif not self.all_items:
                self.empty_overlay.show(
                    "System is Clean",
                    "No verified orphaned leftovers were detected.",
                    icon="✓",
                    icon_color=Colors.ACCENT_GREEN_HOVER,
                    action_text="Rescan Now",
                    action_cmd=self.scan_system_orphans,
                )
            else:
                self.empty_overlay.show(
                    "No Items Match Active Filter",
                    "Try switching back to All categories or disabling the Selected-only filter.",
                    icon="○",
                    icon_color=Colors.TEXT_MUTED,
                    action_text="Show All Orphans",
                    action_cmd=self._reset_filters,
                )
        else:
            self.empty_overlay.hide()

    def _reset_filters(self) -> None:
        self.active_category = "ALL"
        self.selected_only = False
        self.chip_selected_only.set_active(False)
        for k, chip in self._chips.items():
            chip.set_active(k == "ALL")
        self._render_tree()

    def _update_clean_button(self) -> None:
        cnt = len(self.selected_indices)
        self.chip_selected_only.set_text(f"Selected ({cnt})")
        self.btn_sel_none.set_disabled(self._is_busy or cnt == 0)
        if self.tog_dryrun.value:
            self.btn_clean.set_variant("blue-soft")
            self.btn_clean.set_text(f"Simulate Dry-Run ({cnt})")
        else:
            self.btn_clean.set_variant("danger")
            self.btn_clean.set_text(f"Delete Selected ({cnt})")
        self.btn_clean.set_disabled(self._is_busy or cnt == 0)

    def _refresh_row_visual(self, iid: str, idx: int) -> None:
        if not self.tree.exists(iid):
            return
        is_sel = idx in self.selected_indices
        vals = list(self.tree.item(iid, "values"))
        if vals:
            vals[0] = "☑" if is_sel else "☐"
            tags = [t for t in self.tree.item(iid, "tags") if t != "checked"]
            if is_sel:
                tags.append("checked")
            self.tree.item(iid, values=vals, tags=tuple(tags))

    def _on_tree_click(self, event) -> Optional[str]:
        if self._is_busy:
            return None
        col = self.tree.identify_column(event.x)
        row_iid = self.tree.identify_row(event.y)
        if not row_iid:
            return None

        shift_held = bool(event.state & 0x0001)
        ctrl_held = bool(event.state & 0x0004)

        if shift_held and self._last_anchor_iid and self.tree.exists(self._last_anchor_iid):
            children = list(self.tree.get_children())
            if self._last_anchor_iid in children and row_iid in children:
                i1 = children.index(self._last_anchor_iid)
                i2 = children.index(row_iid)
                lo, hi = min(i1, i2), max(i1, i2)
                anchor_idx = int(self._last_anchor_iid)
                target_checked = anchor_idx in self.selected_indices or True
                range_iids = children[lo : hi + 1]
                for r_iid in range_iids:
                    r_idx = int(r_iid)
                    if target_checked:
                        self.selected_indices.add(r_idx)
                    else:
                        self.selected_indices.discard(r_idx)
                    self._refresh_row_visual(r_iid, r_idx)
                self.tree.selection_set(range_iids)
                self._update_clean_button()
                return "break"

        if ctrl_held:
            self._toggle_iid(row_iid)
            self._last_anchor_iid = row_iid
            return None

        if col == "#1":
            self._toggle_iid(row_iid)
            self._last_anchor_iid = row_iid
            return None

        self._last_anchor_iid = row_iid
        return None

    def _on_tree_right_click(self, event) -> None:
        row_iid = self.tree.identify_row(event.y)
        if row_iid:
            if row_iid not in self.tree.selection():
                self.tree.selection_set(row_iid)
            try:
                self.ctx_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.ctx_menu.grab_release()

    def _copy_focused_path(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        try:
            idx = int(sel[0])
            if 0 <= idx < len(self.all_items):
                self.clipboard_clear()
                self.clipboard_append(self.all_items[idx].path)
                _append_log(self.log, f"Copied to clipboard: {self.all_items[idx].path}", "dim")
                self._toast("Copied path to clipboard", "info")
        except ValueError:
            pass

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

    def _toggle_focused_rows(self) -> None:
        if self._is_busy:
            return
        sel = list(self.tree.selection())
        if not sel:
            return
        if len(sel) == 1:
            self._toggle_iid(sel[0])
            return
        idxs = [int(i) for i in sel if i.isdigit()]
        all_checked = all(idx in self.selected_indices for idx in idxs)
        self._set_highlighted_checked(not all_checked)

    def _set_highlighted_checked(self, checked: bool) -> None:
        if self._is_busy:
            return
        for iid in self.tree.selection():
            if not iid.isdigit():
                continue
            idx = int(iid)
            if checked:
                self.selected_indices.add(idx)
            else:
                self.selected_indices.discard(idx)
            self._refresh_row_visual(iid, idx)
        if self.selected_only and not checked:
            self._render_tree()
        else:
            self._update_clean_button()

    def _toggle_iid(self, iid: str) -> None:
        if self._is_busy:
            return
        try:
            idx = int(iid)
        except ValueError:
            return
        if idx in self.selected_indices:
            self.selected_indices.remove(idx)
        else:
            self.selected_indices.add(idx)
        self._refresh_row_visual(iid, idx)
        if self.selected_only and idx not in self.selected_indices:
            self._render_tree()
        else:
            self._update_clean_button()

    def _select_visible(self) -> None:
        if self._is_busy:
            return
        self.selected_indices.update(self.visible_indices)
        self._render_tree()

    def _deselect_all(self) -> None:
        if self._is_busy:
            return
        self.selected_indices.clear()
        if self.selected_only:
            self.selected_only = False
            self.chip_selected_only.set_active(False)
        self._render_tree()

    def _set_busy(self, busy: bool) -> None:
        self._is_busy = busy
        self.btn_scan_orphans.set_disabled(busy)
        self.btn_find_removed.set_disabled(busy)
        self.btn_sel_all.set_disabled(busy)
        self._update_clean_button()

    def scan_system_orphans(self, use_banner: bool = False) -> None:
        if self._is_busy:
            return
        self._last_scan_mode = "system"
        self._last_removed_query = ""
        self._set_busy(True)
        self.empty_overlay.hide()
        if use_banner and self.all_items:
            self.scan_banner.show("Rescanning system for remaining orphaned leftovers...", before=self._tree_host)
        else:
            self.loading_overlay.show(
                "Scanning System for Orphaned Leftovers...",
                "Checking Ghost Uninstall Keys, Broken Shortcuts, Startup, Services, Firewall & COM...",
            )
        _append_log(self.log, "Scanning system for verified orphaned leftovers...", "info")
        all_apps = self._get_all_apps()

        def _worker() -> None:
            items = JunkCleaner.scan_system_orphans(all_apps=all_apps, min_confidence=ConfidenceLevel.GOOD, deep_scan=True)

            def _done() -> None:
                self._has_scanned = True
                self.all_items = items
                self.selected_indices = set(range(len(items)))
                self.loading_overlay.hide()
                self.scan_banner.hide()
                self._set_busy(False)
                self._render_tree()
                _append_log(self.log, f"✓ Found {len(items)} verified orphaned leftover(s). Uncheck any items you want to keep.", "ok")
                if self._on_count_changed:
                    self._on_count_changed(len(items))

            self.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()

    def _trigger_removed_scan(self, query_override: Optional[str] = None, use_banner: bool = False) -> None:
        if self._is_busy:
            return
        query = (query_override if query_override is not None else self.removed_search.get_query()).strip()
        if not query:
            _append_log(self.log, "Enter the name of an already-removed app, or click 'Scan System Orphans'.", "warn")
            return

        all_apps = self._get_all_apps()
        active = JunkCleaner.find_active_installed_matches(query, all_apps)
        if active:
            names = ", ".join(a.display_name_trimmed for a in active[:3])
            _append_log(
                self.log,
                f"⛔ BLOCKED: '{query}' matches currently installed app(s): {names}. "
                f"Use the Applications view to Uninstall it safely instead of deleting active files.",
                "err",
            )
            self._toast(f"Blocked: '{query}' is currently installed", "err")
            return

        self._last_scan_mode = "removed"
        self._last_removed_query = query
        self._set_busy(True)
        self.empty_overlay.hide()
        if use_banner and self.all_items:
            self.scan_banner.show(f"Rescanning leftovers for '{query}'...", before=self._tree_host)
        else:
            self.loading_overlay.show(
                f"Scanning Remnants for '{query}'...",
                "Inspecting AppData, Registry, Services, Tasks, Startup, Firewall & Crash Dumps...",
            )
        _append_log(self.log, f"Scanning leftovers for removed app '{query}'...", "info")

        def _worker() -> None:
            ghost = ApplicationEntry(id=f"removed:{query.lower()}", display_name=query)
            items = JunkCleaner.scan_app_junk(ghost, all_apps=all_apps, min_confidence=ConfidenceLevel.GOOD, deep_scan=True)

            def _done() -> None:
                self._has_scanned = True
                self.all_items = items
                self.selected_indices = set(range(len(items)))
                self.active_category = "ALL"
                self.selected_only = False
                self.chip_selected_only.set_active(False)
                for k, chip in self._chips.items():
                    chip.set_active(k == "ALL")
                self.loading_overlay.hide()
                self.scan_banner.hide()
                self._set_busy(False)
                self._render_tree()
                _append_log(self.log, f"✓ Found {len(items)} leftover item(s) for removed app '{query}'.", "ok")
                if self._on_count_changed:
                    self._on_count_changed(len(items))

            self.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()

    def _start_clean(self) -> None:
        if self._is_busy or not self.selected_indices:
            return
        selected_sorted = sorted(i for i in self.selected_indices if i < len(self.all_items))
        chosen = [self.all_items[i] for i in selected_sorted]
        if not chosen:
            return

        is_dryrun = self.tog_dryrun.value
        backup_reg = self.tog_backup.value

        if not is_dryrun:
            ok_confirm = messagebox.askyesno(
                "Confirm Orphaned Leftovers Cleanup",
                f"Delete {len(chosen)} selected orphaned item(s)?\n\n"
                f"• Registry keys are backed up (.reg) automatically before deletion: {'Yes' if backup_reg else 'No'}\n"
                f"• Files/folders are sent safely to the Windows Recycle Bin.",
                parent=self.winfo_toplevel(),
            )
            if not ok_confirm:
                return

        self._set_busy(True)
        prefix = "[DRY-RUN] " if is_dryrun else ""
        self.scan_banner.show(
            f"{prefix}Cleaning {len(chosen)} selected orphaned leftover(s)...",
            before=self._tree_host,
        )
        _append_log(self.log, f"\n{prefix}Cleaning {len(chosen)} selected orphaned item(s)...", "warn")

        def _worker() -> None:
            results = JunkCleaner.clean_junk(chosen, dry_run=is_dryrun, backup_registry=backup_reg)

            def _done() -> None:
                self.scan_banner.hide()
                ok_cnt = 0
                deleted_indices: Set[int] = set()
                for orig_idx, (item, ok, msg) in zip(selected_sorted, results):
                    if ok:
                        ok_cnt += 1
                        if not is_dryrun:
                            deleted_indices.add(orig_idx)
                    else:
                        _append_log(self.log, f"  ✗ {item.junk_type.value}: {item.path} ({msg})", "err")

                if is_dryrun:
                    _append_log(
                        self.log,
                        f"✓ [DRY-RUN] Simulated {ok_cnt}/{len(results)} item(s). Turn off 'Dry-Run Preview' to delete permanently.",
                        "info",
                    )
                    self._toast(f"Dry-run simulated {ok_cnt}/{len(results)} items (no changes)", "info")
                    self._set_busy(False)
                    return

                # Real deletion: immediately prune deleted items from UI state, then rescan live system
                if deleted_indices:
                    new_items: List[JunkItem] = []
                    new_selected: Set[int] = set()
                    for old_idx, item in enumerate(self.all_items):
                        if old_idx in deleted_indices:
                            continue
                        new_idx = len(new_items)
                        new_items.append(item)
                        if old_idx in self.selected_indices:
                            new_selected.add(new_idx)
                    self.all_items = new_items
                    self.selected_indices = new_selected

                _append_log(
                    self.log,
                    f"✓ Cleaned {ok_cnt}/{len(results)} orphaned item(s). Rescanning system to verify...",
                    "ok",
                )
                self._toast(f"Cleaned {ok_cnt}/{len(results)} orphaned item(s)", "ok")
                if self._on_count_changed:
                    self._on_count_changed(len(self.all_items))
                self._set_busy(False)
                self._render_tree()

                # Automatic post-clean rescan so table reflects 100% real system truth
                if ok_cnt > 0:
                    self._rescan_after_clean()

            self.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()

    def _rescan_after_clean(self) -> None:
        if self._last_scan_mode == "removed" and self._last_removed_query:
            self._trigger_removed_scan(query_override=self._last_removed_query, use_banner=True)
        else:
            self.scan_system_orphans(use_banner=True)


class AuditView(tk.Frame):
    """First-class Software Vulnerability & CVE Audit view with animated loading overlay."""

    SEVERITY_FILTERS = [
        ("All", "ALL"),
        ("Critical", SeverityLevel.CRITICAL.value),
        ("High", SeverityLevel.HIGH.value),
        ("Medium", SeverityLevel.MEDIUM.value),
        ("Low", SeverityLevel.LOW.value),
    ]

    def __init__(
        self,
        parent: tk.Misc,
        get_all_apps: Callable[[], List[ApplicationEntry]],
        on_count_changed: Optional[Callable[[int], None]] = None,
        on_toast: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        super().__init__(parent, bg=Colors.BG_BASE)
        self._get_all_apps = get_all_apps
        self._on_count_changed = on_count_changed
        self._on_toast = on_toast
        self.findings: List[VulnerabilityFinding] = []
        self.active_sev: str = "ALL"
        self._chips: Dict[str, FilterChip] = {}
        self._is_running = False
        self._has_run = False
        self._current_ref_url: Optional[str] = None
        self._hovered_iid: Optional[str] = None

        self._build_ui()

    def _build_ui(self) -> None:
        hdr = tk.Frame(self, bg=Colors.BG_BASE, padx=20, pady=14)
        hdr.pack(fill="x")

        title_col = tk.Frame(hdr, bg=Colors.BG_BASE)
        title_col.pack(side="left", fill="x", expand=True)
        tk.Label(title_col, text="Software Vulnerability & CVE Audit", bg=Colors.BG_BASE, fg=Colors.TEXT_PRIMARY, font=Fonts.hero(), anchor="w").pack(fill="x")
        self.summary_lbl = tk.Label(
            title_col,
            text="Cross-reference installed applications against curated offline CVEs and optional live OSV.dev feeds.",
            bg=Colors.BG_BASE,
            fg=Colors.TEXT_SECONDARY,
            font=Fonts.small(),
            anchor="w",
        )
        self.summary_lbl.pack(fill="x", pady=(2, 0))

        right_ctrl = tk.Frame(hdr, bg=Colors.BG_BASE)
        right_ctrl.pack(side="right")

        self.tog_online = AppleToggle(right_ctrl, "Live OSV.dev", initial=False, bg=Colors.BG_BASE)
        self.tog_online.pack(side="left", padx=(0, 14))

        self.btn_run = ModernButton(
            right_ctrl,
            "Run Security Audit",
            command=self.run_audit,
            variant="primary",
            width=155,
            height=34,
            bg_matte=Colors.BG_BASE,
        )
        self.btn_run.pack(side="left")

        # Severity chips
        chips_bar = tk.Frame(self, bg=Colors.BG_BASE, padx=20)
        chips_bar.pack(fill="x", pady=(0, 10))
        for label, val in self.SEVERITY_FILTERS:
            chip = FilterChip(chips_bar, label, val, on_select=self._select_sev, active=(val == "ALL"))
            chip.pack(side="left", padx=(0, 6))
            self._chips[val] = chip

        # Findings Table
        tbl_border = tk.Frame(self, bg=Colors.BORDER_SUBTLE, padx=1, pady=1)
        tbl_border.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        tbl_frame = tk.Frame(tbl_border, bg=Colors.BG_SURFACE)
        tbl_frame.pack(fill="both", expand=True)

        cols = ("sev", "cve", "app", "installed", "affected", "fixed", "title")
        self.tree = ttk.Treeview(tbl_frame, columns=cols, show="headings", style="Compact.Treeview", selectmode="browse")
        self.tree.heading("sev", text="SEVERITY")
        self.tree.heading("cve", text="CVE / ID")
        self.tree.heading("app", text="APPLICATION")
        self.tree.heading("installed", text="INSTALLED")
        self.tree.heading("affected", text="AFFECTED")
        self.tree.heading("fixed", text="FIXED IN")
        self.tree.heading("title", text="ADVISORY")

        self.tree.column("sev", width=90, minwidth=80, stretch=False, anchor="center")
        self.tree.column("cve", width=135, minwidth=120, stretch=False, anchor="w")
        self.tree.column("app", width=200, minwidth=140, stretch=False, anchor="w")
        self.tree.column("installed", width=105, minwidth=85, stretch=False, anchor="w")
        self.tree.column("affected", width=110, minwidth=85, stretch=False, anchor="w")
        self.tree.column("fixed", width=95, minwidth=80, stretch=False, anchor="w")
        self.tree.column("title", width=300, minwidth=180, stretch=True, anchor="w")

        self.tree.tag_configure("Critical", foreground=Colors.ACCENT_RED_HOVER)
        self.tree.tag_configure("High", foreground="#FB923C")
        self.tree.tag_configure("Medium", foreground=Colors.ACCENT_AMBER_HOVER)
        self.tree.tag_configure("Low", foreground=Colors.ACCENT_CYAN)
        self.tree.tag_configure("hover", background=Colors.BG_HOVER)

        vsb = ttk.Scrollbar(tbl_frame, orient="vertical", style="Modern.TScrollbar", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.loading_overlay = LoadingOverlay(tbl_frame)
        self.empty_overlay = EmptyStateOverlay(tbl_frame)

        self.tree.bind("<<TreeviewSelect>>", self._on_select_finding)
        self.tree.bind("<Motion>", self._on_tree_motion)
        self.tree.bind("<Leave>", self._on_tree_leave)

        # Detail card
        det_border = tk.Frame(self, bg=Colors.BORDER_SUBTLE, padx=1, pady=1)
        det_border.pack(fill="x", padx=20, pady=(0, 14))
        det = tk.Frame(det_border, bg=Colors.BG_SURFACE, padx=14, pady=10)
        det.pack(fill="x")

        det_top = tk.Frame(det, bg=Colors.BG_SURFACE)
        det_top.pack(fill="x")
        self.det_title = tk.Label(det_top, text="Select a finding to inspect details", bg=Colors.BG_SURFACE, fg=Colors.TEXT_PRIMARY, font=Fonts.body_bold(), anchor="w")
        self.det_title.pack(side="left", fill="x", expand=True)

        self.btn_open_ref = ModernButton(det_top, "Open Advisory ↗", command=self._open_ref, variant="blue-soft", width=130, height=26, bg_matte=Colors.BG_SURFACE, disabled=True)
        self.btn_open_ref.pack(side="right")

        self.det_desc = tk.Label(det, text="", bg=Colors.BG_SURFACE, fg=Colors.TEXT_SECONDARY, font=Fonts.small(), anchor="w", justify="left", wraplength=700)
        self.det_desc.pack(fill="x", pady=(6, 0))
        det.bind("<Configure>", lambda e: self.det_desc.configure(wraplength=max(220, e.width - 28)))

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

    def _select_sev(self, val: str) -> None:
        self.active_sev = val
        for k, chip in self._chips.items():
            chip.set_active(k == val)
        self._render_findings()

    def _update_sev_chip_counts(self) -> None:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        for label, val in self.SEVERITY_FILTERS:
            if val == "ALL":
                txt = f"All ({len(self.findings)})" if self._has_run else "All"
            else:
                n = counts.get(val, 0)
                txt = f"{label} ({n})" if n > 0 else label
            self._chips[val].set_text(txt)

    def _render_findings(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._hovered_iid = None
        visible = 0
        for idx, f in enumerate(self.findings):
            if self.active_sev != "ALL" and f.severity.value != self.active_sev:
                continue
            visible += 1
            self.tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(
                    f.severity.value.upper(),
                    f.id,
                    f.app_name,
                    f.installed_version,
                    f.affected_range,
                    f.fixed_version or "-",
                    f.title,
                ),
                tags=(f.severity.value,),
            )

        self._update_sev_chip_counts()

        if self._is_running:
            self.empty_overlay.hide()
        elif visible == 0:
            if not self._has_run:
                self.empty_overlay.show(
                    "Ready to Audit Installed Software",
                    "Click 'Run Security Audit' to cross-reference your applications against known CVEs.",
                    icon="🛡",
                    icon_color=Colors.ACCENT_BLUE_HOVER,
                    action_text="Run Security Audit",
                    action_cmd=self.run_audit,
                )
            elif not self.findings:
                self.empty_overlay.show(
                    "No Known Vulnerabilities Found",
                    "All scanned applications passed the security check.",
                    icon="✓",
                    icon_color=Colors.ACCENT_GREEN_HOVER,
                )
            else:
                self.empty_overlay.show(
                    f"No {self.active_sev} Findings",
                    "Switch back to All severities to view all detected advisories.",
                    icon="○",
                    icon_color=Colors.TEXT_MUTED,
                    action_text="Show All",
                    action_cmd=lambda: self._select_sev("ALL"),
                )
        else:
            self.empty_overlay.hide()

    def _on_select_finding(self, _e=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if 0 <= idx < len(self.findings):
            f = self.findings[idx]
            self.det_title.configure(text=f"{f.id} — {f.app_name} ({f.severity.value})")
            self.det_desc.configure(text=f.description or f.title)
            self._current_ref_url = f.references[0] if f.references else None
            self.btn_open_ref.set_disabled(not bool(self._current_ref_url))

    def _open_ref(self) -> None:
        if self._current_ref_url:
            webbrowser.open(self._current_ref_url)

    def run_audit(self) -> None:
        if self._is_running:
            return
        self._is_running = True
        self.btn_run.set_disabled(True)
        self.empty_overlay.hide()
        online = self.tog_online.value
        apps = self._get_all_apps()
        mode = "curated offline DB + live OSV.dev" if online else "curated offline CVE DB"
        self.summary_lbl.configure(text=f"Scanning {len(apps)} applications against {mode}...", fg=Colors.ACCENT_BLUE_HOVER)
        self.loading_overlay.show(
            "Running Security & CVE Audit...",
            f"Checking {len(apps)} installed application(s) against {mode}...",
        )

        def _worker() -> None:
            report: VulnerabilityReport = VulnerabilityAuditor.audit_all(apps, min_severity=SeverityLevel.LOW, online=online)

            def _done() -> None:
                self._is_running = False
                self._has_run = True
                self.btn_run.set_disabled(False)
                self.loading_overlay.hide()
                self.findings = report.findings
                self._render_findings()
                if not report.findings:
                    self.summary_lbl.configure(
                        text=f"✓ Security Audit Passed! No known vulnerabilities across {report.total_scanned} scanned applications.",
                        fg=Colors.ACCENT_GREEN_HOVER,
                    )
                    if self._on_toast:
                        self._on_toast(f"Security audit passed ({report.total_scanned} apps clean)", "ok")
                else:
                    b = report.severity_breakdown
                    self.summary_lbl.configure(
                        text=(
                            f"Found {report.total_vulnerabilities} issue(s) across {report.vulnerable_apps_count} app(s)  •  "
                            f"Critical: {b.get('Critical', 0)}  High: {b.get('High', 0)}  "
                            f"Medium: {b.get('Medium', 0)}  Low: {b.get('Low', 0)}"
                        ),
                        fg=Colors.ACCENT_RED_HOVER,
                    )
                    if self._on_toast:
                        self._on_toast(f"Found {report.total_vulnerabilities} CVE finding(s)", "warn")
                if self._on_count_changed:
                    self._on_count_changed(report.total_vulnerabilities)

            self.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()
