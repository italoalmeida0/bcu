"""
Apple / Linear-inspired dark theme, Windows 11 DWM seamless dark titlebar,
per-monitor High-DPI awareness, and zero-lag flat ttk styling for BCU Desktop GUI.
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import ttk

IS_WINDOWS = sys.platform == "win32"


class Colors:
    """Refined deep-obsidian Apple / Linear dark palette."""

    BG_BASE = "#0B0E14"          # Deep canvas / seamless titlebar
    BG_SIDEBAR = "#0E121A"       # Left navigation rail
    BG_SURFACE = "#121722"       # Primary cards, table body, inspector
    BG_ELEVATED = "#1A2130"      # Inputs, headers, subtle cards
    BG_HOVER = "#212A3C"         # Row / button hover
    BG_ACTIVE = "#28334A"        # Pressed state
    BG_SELECTED = "#1B355B"      # Selected row / nav active
    BG_ROW_ALT = "#0F141E"       # Subtle alternating table stripe
    BG_CODE = "#080B10"          # Monospace command/path wells

    BORDER = "#242D3F"
    BORDER_SUBTLE = "#1A2231"
    BORDER_FOCUS = "#58A6FF"

    TEXT_PRIMARY = "#F0F4F8"
    TEXT_SECONDARY = "#94A3B8"
    TEXT_MUTED = "#5E6D82"

    ACCENT_BLUE = "#3B82F6"
    ACCENT_BLUE_HOVER = "#60A5FA"
    ACCENT_GREEN = "#22C55E"
    ACCENT_GREEN_HOVER = "#4ADE80"
    ACCENT_RED = "#EF4444"
    ACCENT_RED_HOVER = "#F87171"
    ACCENT_AMBER = "#F59E0B"
    ACCENT_AMBER_HOVER = "#FBBF24"
    ACCENT_PURPLE = "#A855F7"
    ACCENT_CYAN = "#06B6D4"

    TINT_BLUE = "#132644"
    TINT_GREEN = "#102C1E"
    TINT_RED = "#341519"
    TINT_AMBER = "#33250F"
    TINT_PURPLE = "#24163A"


class Fonts:
    """Crisp system typography hierarchy."""

    FAMILY = "Segoe UI Variable Text" if IS_WINDOWS else "Helvetica"
    MONO = "Cascadia Mono" if IS_WINDOWS else "Courier"

    @classmethod
    def resolve(cls, root: tk.Misc) -> None:
        try:
            import tkinter.font as tkfont

            available = {f.lower() for f in tkfont.families(root)}
            for cand in ("segoe ui variable text", "segoe ui variable display", "segoe ui", "inter", "sf pro text"):
                if cand in available:
                    # Preserve canonical casing
                    for orig in tkfont.families(root):
                        if orig.lower() == cand:
                            cls.FAMILY = orig
                            break
                    break
            for cand in ("cascadia mono", "jetbrains mono", "consolas"):
                if cand in available:
                    for orig in tkfont.families(root):
                        if orig.lower() == cand:
                            cls.MONO = orig
                            break
                    break
        except Exception:
            pass

    @classmethod
    def hero(cls) -> tuple[str, int, str]:
        return (cls.FAMILY, 15, "bold")

    @classmethod
    def title(cls) -> tuple[str, int, str]:
        return (cls.FAMILY, 13, "bold")

    @classmethod
    def heading(cls) -> tuple[str, int, str]:
        return (cls.FAMILY, 11, "bold")

    @classmethod
    def body(cls) -> tuple[str, int]:
        return (cls.FAMILY, 10)

    @classmethod
    def body_bold(cls) -> tuple[str, int, str]:
        return (cls.FAMILY, 10, "bold")

    @classmethod
    def small(cls) -> tuple[str, int]:
        return (cls.FAMILY, 9)

    @classmethod
    def small_bold(cls) -> tuple[str, int, str]:
        return (cls.FAMILY, 9, "bold")

    @classmethod
    def micro(cls) -> tuple[str, int, str]:
        return (cls.FAMILY, 8, "bold")

    @classmethod
    def kpi(cls) -> tuple[str, int, str]:
        return (cls.FAMILY, 15, "bold")

    @classmethod
    def mono(cls) -> tuple[str, int]:
        return (cls.MONO, 9)

    @classmethod
    def mono_small(cls) -> tuple[str, int]:
        return (cls.MONO, 8)


class UiScale:
    """Tracks Windows HiDPI scale factor so pixel dimensions match scaled Tk fonts."""

    factor: float = 1.0

    @classmethod
    def resolve(cls, root: tk.Misc) -> float:
        try:
            dpi = float(root.winfo_fpixels("1i"))
            cls.factor = max(1.0, min(2.25, dpi / 96.0))
        except Exception:
            cls.factor = 1.0
        return cls.factor


def dp(px: int) -> int:
    """Scales logical pixels according to the current display DPI."""
    return max(1, int(round(px * UiScale.factor)))


def hide_dedicated_console_if_owned() -> None:
    """
    Hides the console window ONLY when this GUI process (and its PyInstaller onefile
    bootloader, if frozen) are the sole processes attached to the console (e.g., launched
    from Start Menu / Desktop shortcut or UAC runas), leaving interactive PowerShell /
    CMD / Windows Terminal sessions completely untouched.
    """
    if not IS_WINDOWS:
        return
    try:
        import ctypes
        import os
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        hwnd = kernel32.GetConsoleWindow()
        if not hwnd:
            return
        pids = (wintypes.DWORD * 8)()
        count = int(kernel32.GetConsoleProcessList(pids, 8))
        if count <= 0:
            return
        if count == 1:
            user32.ShowWindow(hwnd, 0)  # SW_HIDE
            return
        # PyInstaller --onefile attaches both bootloader parent and child Python process
        if getattr(sys, "frozen", False) and count <= 2:
            import psutil

            own_name = os.path.basename(sys.executable).lower()
            attached_names = []
            for i in range(count):
                try:
                    attached_names.append(psutil.Process(int(pids[i])).name().lower())
                except Exception:
                    return
            if attached_names and all(n == own_name for n in attached_names):
                user32.ShowWindow(hwnd, 0)  # SW_HIDE
    except Exception:
        pass


def enable_high_dpi() -> None:
    """Enables per-monitor DPI awareness on Windows for crisp HiDPI rendering."""
    if not IS_WINDOWS:
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def apply_windows_dark_titlebar(window: tk.Wm) -> None:
    """Applies Windows 11 native immersive dark titlebar seamlessly matching BG_BASE (#0B0E14)."""
    if not IS_WINDOWS:
        return
    try:
        import ctypes

        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        if not hwnd:
            hwnd = window.winfo_id()

        dwmapi = ctypes.windll.dwmapi
        dark_val = ctypes.c_int(1)
        for attr in (20, 19):
            dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(dark_val), ctypes.sizeof(dark_val))

        # DWMWA_CAPTION_COLOR = 35 (#0B0E14 -> COLORREF 0x00140E0B)
        caption = ctypes.c_int(0x00140E0B)
        dwmapi.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(caption), ctypes.sizeof(caption))

        # DWMWA_BORDER_COLOR = 34 (#242D3F -> 0x003F2D24)
        border = ctypes.c_int(0x003F2D24)
        dwmapi.DwmSetWindowAttribute(hwnd, 34, ctypes.byref(border), ctypes.sizeof(border))
    except Exception:
        pass


def configure_ttk_styles(root: tk.Misc) -> ttk.Style:
    """Configures ultra-clean, zero-bevel dark ttk styles."""
    UiScale.resolve(root)
    Fonts.resolve(root)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure(
        ".",
        background=Colors.BG_BASE,
        foreground=Colors.TEXT_PRIMARY,
        font=Fonts.body(),
        borderwidth=0,
        focuscolor=Colors.BORDER_FOCUS,
    )

    # Primary Application Treeview (38dp generous row height for crisp 22dp native icons)
    style.configure(
        "Modern.Treeview",
        background=Colors.BG_SURFACE,
        fieldbackground=Colors.BG_SURFACE,
        foreground=Colors.TEXT_PRIMARY,
        rowheight=dp(38),
        borderwidth=0,
        relief="flat",
        font=Fonts.body(),
    )
    style.map(
        "Modern.Treeview",
        background=[("selected", Colors.BG_SELECTED)],
        foreground=[("selected", "#FFFFFF")],
    )
    style.configure(
        "Modern.Treeview.Heading",
        background=Colors.BG_SURFACE,
        foreground=Colors.TEXT_MUTED,
        font=Fonts.micro(),
        relief="flat",
        borderwidth=0,
        padding=(dp(10), dp(9)),
    )
    style.map(
        "Modern.Treeview.Heading",
        background=[("active", Colors.BG_ELEVATED)],
        foreground=[("active", Colors.TEXT_PRIMARY)],
    )
    style.layout("Modern.Treeview", [("Modern.Treeview.treearea", {"sticky": "nswe"})])

    # Compact Treeview (Orphans & Security Audit)
    style.configure(
        "Compact.Treeview",
        background=Colors.BG_SURFACE,
        fieldbackground=Colors.BG_SURFACE,
        foreground=Colors.TEXT_PRIMARY,
        rowheight=dp(32),
        borderwidth=0,
        relief="flat",
        font=Fonts.small(),
    )
    style.map(
        "Compact.Treeview",
        background=[("selected", Colors.BG_SELECTED)],
        foreground=[("selected", "#FFFFFF")],
    )
    style.configure(
        "Compact.Treeview.Heading",
        background=Colors.BG_SURFACE,
        foreground=Colors.TEXT_MUTED,
        font=Fonts.micro(),
        relief="flat",
        borderwidth=0,
        padding=(dp(8), dp(8)),
    )
    style.map(
        "Compact.Treeview.Heading",
        background=[("active", Colors.BG_ELEVATED)],
        foreground=[("active", Colors.TEXT_PRIMARY)],
    )
    style.layout("Compact.Treeview", [("Compact.Treeview.treearea", {"sticky": "nswe"})])

    # Ultra-slim arrowless macOS/Linear dark scrollbars
    style.layout(
        "Vertical.Modern.TScrollbar",
        [
            (
                "Vertical.Scrollbar.trough",
                {
                    "sticky": "ns",
                    "children": [
                        ("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"}),
                    ],
                },
            )
        ],
    )
    style.layout(
        "Horizontal.Modern.TScrollbar",
        [
            (
                "Horizontal.Scrollbar.trough",
                {
                    "sticky": "we",
                    "children": [
                        ("Horizontal.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"}),
                    ],
                },
            )
        ],
    )
    for name in ("Vertical.Modern.TScrollbar", "Horizontal.Modern.TScrollbar"):
        style.configure(
            name,
            gripcount=0,
            background=Colors.BG_HOVER,
            darkcolor=Colors.BG_HOVER,
            lightcolor=Colors.BG_HOVER,
            troughcolor=Colors.BG_SURFACE,
            bordercolor=Colors.BG_SURFACE,
            width=dp(8),
            relief="flat",
            borderwidth=0,
        )
        style.map(
            name,
            background=[("active", "#3A4964"), ("pressed", Colors.ACCENT_BLUE)],
        )

    # Progressbar
    style.configure(
        "Modern.Horizontal.TProgressbar",
        troughcolor=Colors.BG_ELEVATED,
        background=Colors.ACCENT_BLUE,
        bordercolor=Colors.BG_ELEVATED,
        lightcolor=Colors.ACCENT_BLUE,
        darkcolor=Colors.ACCENT_BLUE,
        thickness=6,
        relief="flat",
        borderwidth=0,
    )

    style.configure("Modern.TPanedwindow", background=Colors.BG_BASE)
    style.configure("Sash", sashthickness=5, sashrelief="flat", background=Colors.BG_BASE)

    return style
