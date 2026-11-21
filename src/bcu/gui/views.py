"""
First-class Desktop GUI views and dialogs for BCU:
  - UninstallDialog: bulk uninstaller with Apple toggles, progress bar & live colored log
  - OrphansView: Revo/BCU-style verified orphaned leftovers cleaner with category chips & active-app guard
  - AuditView: CVE security audit page with severity chips & clickable advisories
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk
import webbrowser
from typing import Callable, Dict, List, Optional, Set

from bcu.engine.batch import BatchUninstallQueue
from bcu.gui.theme import Colors, Fonts, apply_windows_dark_titlebar
from bcu.gui.widgets import AppleToggle, FilterChip, ModernButton, ModernSearchBar
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

        # Center over parent window
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

        # Header
        tk.Label(
            outer,
            text=f"Uninstall {len(self.target_apps)} Application{'s' if len(self.target_apps) != 1 else ''}",
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

        # Selected apps list box
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

        # Apple-style options card (2-column grid)
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
            self.after(0, lambda: _append_log(self.log, f"\n[{idx}/{total}] Processing {app.display_name_trimmed}...", "info"))

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
            ok_cnt = sum(1 for r in self.results if r.status.value == "Completed")
            _append_log(self.log, f"\nBatch complete: {ok_cnt}/{len(self.results)} succeeded.", "ok")
            self.btn_close.set_text("Close")
            self.btn_close.set_disabled(False)

        self.after(0, _done)


class OrphansView(tk.Frame):
    """
    Revo / BCU-style Orphaned Leftovers Cleaner integrated as a main window page.
    Only scans verified broken remnants from already-removed apps; blocks active installed apps.
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

    def __init__(self, parent: tk.Misc, get_all_apps: Callable[[], List[ApplicationEntry]], on_count_changed: Optional[Callable[[int], None]] = None) -> None:
        super().__init__(parent, bg=Colors.BG_BASE)
        self._get_all_apps = get_all_apps
        self._on_count_changed = on_count_changed
        self.all_items: List[JunkItem] = []
        self.visible_indices: List[int] = []
        self.selected_indices: Set[int] = set()
        self.active_category: str = "ALL"
        self._is_busy = False
        self._chips: Dict[str, FilterChip] = {}

        self._build_ui()

    def _build_ui(self) -> None:
        # Top Header
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
        chips_bar.pack(fill="x", pady=(0, 10))
        for label, val in self.CATEGORY_FILTERS:
            chip = FilterChip(chips_bar, label, val, on_select=self._select_category, active=(val == "ALL"))
            chip.pack(side="left", padx=(0, 6))
            self._chips[val] = chip

        # Table Container
        tbl_border = tk.Frame(self, bg=Colors.BORDER_SUBTLE, padx=1, pady=1)
        tbl_border.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        tbl_frame = tk.Frame(tbl_border, bg=Colors.BG_SURFACE)
        tbl_frame.pack(fill="both", expand=True)

        cols = ("chk", "type", "conf", "app", "path", "reason")
        self.tree = ttk.Treeview(tbl_frame, columns=cols, show="headings", style="Compact.Treeview", selectmode="browse")
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
        self._hovered_iid: Optional[str] = None

        vsb = ttk.Scrollbar(tbl_frame, orient="vertical", style="Modern.TScrollbar", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Double-1>", lambda _e: self._toggle_focused_row())
        self.tree.bind("<space>", lambda _e: self._toggle_focused_row())
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
        self.ctx_menu.add_command(label="Toggle Selection  (Space)", command=self._toggle_focused_row)
        self.ctx_menu.add_command(label="Copy Path / Registry Key", command=self._copy_focused_path)

        # Controls + Live Log Split Footer
        ctrl = tk.Frame(self, bg=Colors.BG_BASE, padx=20)
        ctrl.pack(fill="x", pady=(0, 8))

        self.btn_sel_all = ModernButton(ctrl, "Select Visible", command=self._select_visible, variant="secondary", width=112, height=30, bg_matte=Colors.BG_BASE)
        self.btn_sel_all.pack(side="left", padx=(0, 6))
        self.btn_sel_none = ModernButton(ctrl, "Deselect All", command=self._deselect_all, variant="secondary", width=102, height=30, bg_matte=Colors.BG_BASE)
        self.btn_sel_none.pack(side="left", padx=(0, 16))

        self.tog_dryrun = AppleToggle(ctrl, "Dry-Run Preview", initial=True, bg=Colors.BG_BASE)
        self.tog_dryrun.pack(side="left", padx=(0, 14))
        self.tog_backup = AppleToggle(ctrl, "Auto .reg Backup", initial=True, bg=Colors.BG_BASE)
        self.tog_backup.pack(side="left")

        self.btn_clean = ModernButton(
            ctrl,
            "Clean Selected (0)",
            command=self._start_clean,
            variant="warning",
            width=165,
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

    def _render_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.visible_indices.clear()
        self._hovered_iid = None

        for idx, item in enumerate(self.all_items):
            if self.active_category != "ALL" and item.junk_type.value != self.active_category:
                continue
            self.visible_indices.append(idx)
            chk = "☑" if idx in self.selected_indices else "☐"
            reason = item.reasons[0] if item.reasons else ""
            tag = "odd" if len(self.visible_indices) % 2 else "even"
            self.tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(chk, item.junk_type.value, item.confidence_level.value, item.app_name, item.path, reason),
                tags=(tag,),
            )
        self._update_clean_button()

    def _update_clean_button(self) -> None:
        cnt = len(self.selected_indices)
        self.btn_clean.set_text(f"Clean Selected ({cnt})")
        self.btn_clean.set_disabled(self._is_busy or cnt == 0)

    def _on_tree_click(self, event) -> None:
        col = self.tree.identify_column(event.x)
        row_iid = self.tree.identify_row(event.y)
        if col == "#1" and row_iid:
            self._toggle_iid(row_iid)

    def _on_tree_right_click(self, event) -> None:
        row_iid = self.tree.identify_row(event.y)
        if row_iid:
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

    def _toggle_focused_row(self) -> None:
        sel = self.tree.selection()
        if sel:
            self._toggle_iid(sel[0])

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
        vals = list(self.tree.item(iid, "values"))
        if vals:
            vals[0] = "☑" if idx in self.selected_indices else "☐"
            self.tree.item(iid, values=vals)
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
        self._render_tree()

    def _set_busy(self, busy: bool) -> None:
        self._is_busy = busy
        self.btn_scan_orphans.set_disabled(busy)
        self.btn_find_removed.set_disabled(busy)
        self._update_clean_button()

    def scan_system_orphans(self) -> None:
        if self._is_busy:
            return
        self._set_busy(True)
        _append_log(self.log, "Scanning system for verified orphaned leftovers...", "info")
        all_apps = self._get_all_apps()

        def _worker() -> None:
            items = JunkCleaner.scan_system_orphans(all_apps=all_apps, min_confidence=ConfidenceLevel.GOOD, deep_scan=True)

            def _done() -> None:
                self.all_items = items
                self.selected_indices = set(range(len(items)))
                self._set_busy(False)
                self._render_tree()
                _append_log(self.log, f"✓ Found {len(items)} verified orphaned leftover(s). Uncheck any items you want to keep.", "ok")
                if self._on_count_changed:
                    self._on_count_changed(len(items))

            self.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()

    def _trigger_removed_scan(self) -> None:
        if self._is_busy:
            return
        query = self.removed_search.get_query()
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
            return

        self._set_busy(True)
        _append_log(self.log, f"Scanning leftovers for removed app '{query}'...", "info")

        def _worker() -> None:
            ghost = ApplicationEntry(id=f"removed:{query.lower()}", display_name=query)
            items = JunkCleaner.scan_app_junk(ghost, all_apps=all_apps, min_confidence=ConfidenceLevel.GOOD, deep_scan=True)

            def _done() -> None:
                self.all_items = items
                self.selected_indices = set(range(len(items)))
                self.active_category = "ALL"
                for k, chip in self._chips.items():
                    chip.set_active(k == "ALL")
                self._set_busy(False)
                self._render_tree()
                _append_log(self.log, f"✓ Found {len(items)} leftover item(s) for removed app '{query}'.", "ok")

            self.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()

    def _start_clean(self) -> None:
        if self._is_busy or not self.selected_indices:
            return
        chosen = [self.all_items[i] for i in sorted(self.selected_indices) if i < len(self.all_items)]
        is_dryrun = self.tog_dryrun.value
        backup_reg = self.tog_backup.value
        self._set_busy(True)

        prefix = "[DRY-RUN] " if is_dryrun else ""
        _append_log(self.log, f"\n{prefix}Cleaning {len(chosen)} selected orphaned item(s)...", "warn")

        def _worker() -> None:
            results = JunkCleaner.clean_junk(chosen, dry_run=is_dryrun, backup_registry=backup_reg)

            def _done() -> None:
                ok_cnt = 0
                for item, ok, msg in results:
                    if ok:
                        ok_cnt += 1
                    else:
                        _append_log(self.log, f"  ✗ {item.junk_type.value}: {item.path} ({msg})", "err")
                _append_log(self.log, f"✓ {prefix}Finished: {ok_cnt}/{len(results)} item(s) processed successfully.", "ok")
                self._set_busy(False)

            self.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()


class AuditView(tk.Frame):
    """First-class Software Vulnerability & CVE Audit view."""

    SEVERITY_FILTERS = [
        ("All", "ALL"),
        ("Critical", SeverityLevel.CRITICAL.value),
        ("High", SeverityLevel.HIGH.value),
        ("Medium", SeverityLevel.MEDIUM.value),
        ("Low", SeverityLevel.LOW.value),
    ]

    def __init__(self, parent: tk.Misc, get_all_apps: Callable[[], List[ApplicationEntry]], on_count_changed: Optional[Callable[[int], None]] = None) -> None:
        super().__init__(parent, bg=Colors.BG_BASE)
        self._get_all_apps = get_all_apps
        self._on_count_changed = on_count_changed
        self.findings: List[VulnerabilityFinding] = []
        self.active_sev: str = "ALL"
        self._chips: Dict[str, FilterChip] = {}
        self._is_running = False
        self._current_ref_url: Optional[str] = None

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

        vsb = ttk.Scrollbar(tbl_frame, orient="vertical", style="Modern.TScrollbar", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select_finding)

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

    def _select_sev(self, val: str) -> None:
        self.active_sev = val
        for k, chip in self._chips.items():
            chip.set_active(k == val)
        self._render_findings()

    def _render_findings(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for idx, f in enumerate(self.findings):
            if self.active_sev != "ALL" and f.severity.value != self.active_sev:
                continue
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
        online = self.tog_online.value
        apps = self._get_all_apps()
        mode = "curated offline DB + OSV.dev" if online else "curated offline CVE DB"
        self.summary_lbl.configure(text=f"Scanning {len(apps)} applications against {mode}...", fg=Colors.ACCENT_BLUE_HOVER)

        def _worker() -> None:
            report: VulnerabilityReport = VulnerabilityAuditor.audit_all(apps, min_severity=SeverityLevel.LOW, online=online)

            def _done() -> None:
                self._is_running = False
                self.btn_run.set_disabled(False)
                self.findings = report.findings
                self._render_findings()
                if not report.findings:
                    self.summary_lbl.configure(
                        text=f"✓ Security Audit Passed! No known vulnerabilities across {report.total_scanned} scanned applications.",
                        fg=Colors.ACCENT_GREEN_HOVER,
                    )
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
                if self._on_count_changed:
                    self._on_count_changed(report.total_vulnerabilities)

            self.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()
