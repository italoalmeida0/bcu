"""
Apple / Linear-grade custom Tkinter widgets using 4x supersampled Pillow sprites
so corners, pills, search inputs, and toggle switches render smoothly with zero lag.
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional
from PIL import ImageTk

from bcu.gui.icons import make_rounded_rect_pil, make_toggle_pil
from bcu.gui.theme import Colors, Fonts, dp


class ModernButton(tk.Canvas):
    """Subpixel-smooth rounded pill button with hover, active, and disabled states."""

    VARIANTS = {
        "primary": (Colors.ACCENT_BLUE, Colors.ACCENT_BLUE_HOVER, "#FFFFFF", None),
        "danger": (Colors.ACCENT_RED, Colors.ACCENT_RED_HOVER, "#FFFFFF", None),
        "warning": (Colors.ACCENT_AMBER, Colors.ACCENT_AMBER_HOVER, "#0B0E14", None),
        "success": (Colors.ACCENT_GREEN, Colors.ACCENT_GREEN_HOVER, "#0B0E14", None),
        "secondary": (Colors.BG_ELEVATED, Colors.BG_HOVER, Colors.TEXT_PRIMARY, Colors.BORDER),
        "ghost": (Colors.BG_BASE, Colors.BG_ELEVATED, Colors.TEXT_SECONDARY, None),
        "danger-soft": (Colors.TINT_RED, "#471C22", Colors.ACCENT_RED_HOVER, "#522229"),
        "amber-soft": (Colors.TINT_AMBER, "#453214", Colors.ACCENT_AMBER_HOVER, "#543D18"),
        "blue-soft": (Colors.TINT_BLUE, "#1D3861", Colors.ACCENT_BLUE_HOVER, "#25467A"),
    }

    def __init__(
        self,
        parent: tk.Misc,
        text: str,
        command: Optional[Callable[[], None]] = None,
        variant: str = "secondary",
        width: int = 120,
        height: int = 32,
        radius: int = 8,
        font=None,
        bg_matte: Optional[str] = None,
        disabled: bool = False,
    ) -> None:
        self._bg_matte = bg_matte or str(parent.cget("bg"))
        btn_w = dp(width)
        btn_h = dp(height)
        super().__init__(
            parent,
            width=btn_w,
            height=btn_h,
            bg=self._bg_matte,
            highlightthickness=0,
            bd=0,
            cursor="arrow" if disabled else "hand2",
        )
        self._text = text
        self._command = command
        self._variant = variant
        # NEVER assign self._w — Tkinter uses self._w internally for the Tcl widget path!
        self._btn_w = btn_w
        self._btn_h = btn_h
        self._radius = dp(radius)
        self._font = font or Fonts.small_bold()
        self._disabled = disabled
        self._hovered = False
        self._pressed = False

        self._img_normal: Optional[ImageTk.PhotoImage] = None
        self._img_hover: Optional[ImageTk.PhotoImage] = None
        self._img_disabled: Optional[ImageTk.PhotoImage] = None
        self._bg_item = self.create_image(0, 0, anchor="nw")
        self._txt_item = self.create_text(
            btn_w // 2,
            btn_h // 2,
            text=text,
            font=self._font,
            fill=Colors.TEXT_PRIMARY,
        )

        self._rebuild_sprites()
        self._render()

        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_click)

    def _rebuild_sprites(self) -> None:
        fill, hover, _, border = self.VARIANTS.get(self._variant, self.VARIANTS["secondary"])
        self._img_normal = ImageTk.PhotoImage(
            make_rounded_rect_pil(self._btn_w, self._btn_h, self._radius, fill, border=border, bg_matte=self._bg_matte),
            master=self,
        )
        self._img_hover = ImageTk.PhotoImage(
            make_rounded_rect_pil(self._btn_w, self._btn_h, self._radius, hover, border=border, bg_matte=self._bg_matte),
            master=self,
        )
        self._img_disabled = ImageTk.PhotoImage(
            make_rounded_rect_pil(
                self._btn_w,
                self._btn_h,
                self._radius,
                Colors.BG_ELEVATED,
                border=Colors.BORDER_SUBTLE,
                bg_matte=self._bg_matte,
            ),
            master=self,
        )

    def _render(self) -> None:
        _, _, fg, _ = self.VARIANTS.get(self._variant, self.VARIANTS["secondary"])
        if self._disabled:
            self.itemconfigure(self._bg_item, image=self._img_disabled)
            self.itemconfigure(self._txt_item, text=self._text, fill=Colors.TEXT_MUTED)
            self.configure(cursor="arrow")
        else:
            self.itemconfigure(self._bg_item, image=self._img_hover if self._hovered else self._img_normal)
            self.itemconfigure(self._txt_item, text=self._text, fill=fg)
            self.coords(self._txt_item, self._btn_w // 2, (self._btn_h // 2) + (1 if self._pressed else 0))
            self.configure(cursor="hand2")

    def _on_enter(self, _e=None) -> None:
        if not self._disabled:
            self._hovered = True
            self._render()

    def _on_leave(self, _e=None) -> None:
        self._hovered = False
        self._pressed = False
        self._render()

    def _on_press(self, _e=None) -> None:
        if not self._disabled:
            self._pressed = True
            self._render()

    def _on_click(self, event) -> None:
        was_pressed = self._pressed
        self._pressed = False
        self._render()
        if self._disabled or self._command is None or not was_pressed:
            return
        if 0 <= event.x <= self._btn_w and 0 <= event.y <= self._btn_h:
            self._command()

    def set_text(self, new_text: str) -> None:
        self._text = new_text
        self.itemconfigure(self._txt_item, text=new_text)

    def set_disabled(self, disabled: bool) -> None:
        self._disabled = disabled
        if disabled:
            self._hovered = False
            self._pressed = False
        self._render()

    def set_variant(self, variant: str) -> None:
        if variant != self._variant:
            self._variant = variant
            self._rebuild_sprites()
            self._render()


class NavItem(tk.Frame):
    """Sleek Apple/Linear sidebar navigation item with active indicator bar and optional count pill."""

    def __init__(
        self,
        parent: tk.Misc,
        icon_glyph: str,
        label: str,
        command: Callable[[], None],
        badge_text: str = "",
    ) -> None:
        super().__init__(parent, bg=Colors.BG_SIDEBAR, cursor="hand2")
        self._command = command
        self._active = False
        self._hovered = False

        self._indicator = tk.Frame(self, width=3, bg=Colors.BG_SIDEBAR)
        self._indicator.pack(side="left", fill="y", pady=5)

        self._body = tk.Frame(self, bg=Colors.BG_SIDEBAR, padx=10, pady=8)
        self._body.pack(side="left", fill="both", expand=True)

        self._icon_lbl = tk.Label(self._body, text=icon_glyph, bg=Colors.BG_SIDEBAR, fg=Colors.TEXT_SECONDARY, font=Fonts.body())
        self._icon_lbl.pack(side="left", padx=(0, 8))

        self._text_lbl = tk.Label(self._body, text=label, bg=Colors.BG_SIDEBAR, fg=Colors.TEXT_SECONDARY, font=Fonts.body_bold())
        self._text_lbl.pack(side="left")

        self._badge_lbl = tk.Label(
            self._body,
            text=badge_text,
            bg=Colors.BG_ELEVATED,
            fg=Colors.TEXT_SECONDARY,
            font=Fonts.micro(),
            padx=6,
            pady=1,
        )
        if badge_text:
            self._badge_lbl.pack(side="right")

        for w in (self, self._indicator, self._body, self._icon_lbl, self._text_lbl, self._badge_lbl):
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)
            w.bind("<Button-1>", self._on_click)

    def _refresh(self) -> None:
        if self._active:
            bg = Colors.BG_ELEVATED
            fg = Colors.TEXT_PRIMARY
            ind = Colors.ACCENT_BLUE
            badge_bg = Colors.TINT_BLUE
            badge_fg = Colors.ACCENT_BLUE_HOVER
        elif self._hovered:
            bg = Colors.BG_SURFACE
            fg = Colors.TEXT_PRIMARY
            ind = Colors.BG_SURFACE
            badge_bg = Colors.BG_HOVER
            badge_fg = Colors.TEXT_PRIMARY
        else:
            bg = Colors.BG_SIDEBAR
            fg = Colors.TEXT_SECONDARY
            ind = Colors.BG_SIDEBAR
            badge_bg = Colors.BG_ELEVATED
            badge_fg = Colors.TEXT_MUTED

        self.configure(bg=bg)
        self._indicator.configure(bg=ind)
        self._body.configure(bg=bg)
        self._icon_lbl.configure(bg=bg, fg=Colors.ACCENT_BLUE if self._active else fg)
        self._text_lbl.configure(bg=bg, fg=fg)
        self._badge_lbl.configure(bg=badge_bg, fg=badge_fg)

    def _on_enter(self, _e=None) -> None:
        self._hovered = True
        self._refresh()

    def _on_leave(self, _e=None) -> None:
        self._hovered = False
        self._refresh()

    def _on_click(self, _e=None) -> None:
        self._command()

    def set_active(self, active: bool) -> None:
        self._active = active
        self._refresh()

    def set_badge(self, text: str) -> None:
        self._badge_lbl.configure(text=text)
        if text:
            if not self._badge_lbl.winfo_ismapped():
                self._badge_lbl.pack(side="right")
        else:
            self._badge_lbl.pack_forget()
        self._refresh()


class FilterChip(tk.Frame):
    """Minimal segmented filter pill with crisp 1px hairline border (Linear/macOS style)."""

    def __init__(
        self,
        parent: tk.Misc,
        text: str,
        value: str,
        on_select: Callable[[str], None],
        active: bool = False,
    ) -> None:
        super().__init__(parent, padx=1, pady=1, cursor="hand2")
        self.value = value
        self._on_select = on_select
        self._active = active
        self._hovered = False

        self._lbl = tk.Label(
            self,
            text=text,
            font=Fonts.small_bold(),
            padx=dp(8),
            pady=dp(3),
            cursor="hand2",
            bd=0,
            relief="flat",
        )
        self._lbl.pack()
        self._refresh()
        for w in (self, self._lbl):
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)
            w.bind("<Button-1>", lambda _e: self._on_select(self.value))

    def _refresh(self) -> None:
        if self._active:
            self.configure(bg="#2A538F")
            self._lbl.configure(bg=Colors.TINT_BLUE, fg=Colors.ACCENT_BLUE_HOVER)
        elif self._hovered:
            self.configure(bg="#33415C")
            self._lbl.configure(bg=Colors.BG_HOVER, fg=Colors.TEXT_PRIMARY)
        else:
            self.configure(bg=Colors.BORDER_SUBTLE)
            self._lbl.configure(bg=Colors.BG_ELEVATED, fg=Colors.TEXT_SECONDARY)

    def _on_enter(self, _e=None) -> None:
        self._hovered = True
        self._refresh()

    def _on_leave(self, _e=None) -> None:
        self._hovered = False
        self._refresh()

    def set_active(self, active: bool) -> None:
        self._active = active
        self._refresh()


class ModernSearchBar(tk.Frame):
    """Crisp dark search bar with focus border highlight, icon, placeholder, and instant clear button."""

    def __init__(
        self,
        parent: tk.Misc,
        placeholder: str = "Search...",
        on_change: Optional[Callable[[str], None]] = None,
        on_submit: Optional[Callable[[str], None]] = None,
        debounce_ms: int = 85,
    ) -> None:
        super().__init__(parent, bg=Colors.BORDER, padx=1, pady=1)
        self._placeholder = placeholder
        self._on_change = on_change
        self._on_submit = on_submit
        self._debounce_ms = debounce_ms
        self._after_id: Optional[str] = None
        self._has_placeholder = True

        self._inner = tk.Frame(self, bg=Colors.BG_ELEVATED, padx=10, pady=5)
        self._inner.pack(fill="both", expand=True)

        self._icon = tk.Label(self._inner, text="⌕", bg=Colors.BG_ELEVATED, fg=Colors.TEXT_MUTED, font=(Fonts.FAMILY, 12))
        self._icon.pack(side="left", padx=(0, 6))

        self.var = tk.StringVar()
        self.entry = tk.Entry(
            self._inner,
            textvariable=self.var,
            bg=Colors.BG_ELEVATED,
            fg=Colors.TEXT_MUTED,
            insertbackground=Colors.ACCENT_BLUE,
            selectbackground=Colors.BG_SELECTED,
            selectforeground="#FFFFFF",
            relief="flat",
            bd=0,
            font=Fonts.body(),
        )
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.insert(0, placeholder)

        self._clear_btn = tk.Label(
            self._inner,
            text="✕",
            bg=Colors.BG_ELEVATED,
            fg=Colors.TEXT_MUTED,
            font=Fonts.small_bold(),
            cursor="hand2",
            padx=4,
        )
        self._clear_btn.bind("<Button-1>", lambda _e: self.clear())

        self.entry.bind("<FocusIn>", self._on_focus_in)
        self.entry.bind("<FocusOut>", self._on_focus_out)
        self.entry.bind("<KeyRelease>", self._on_key)
        self.entry.bind("<Return>", self._on_return)

    def get_query(self) -> str:
        if self._has_placeholder:
            return ""
        return self.var.get().strip()

    def focus_input(self) -> None:
        self.entry.focus_set()

    def clear(self) -> None:
        self._has_placeholder = False
        self.var.set("")
        self.entry.configure(fg=Colors.TEXT_PRIMARY)
        self._clear_btn.pack_forget()
        if self._on_change:
            self._on_change("")
        self.entry.focus_set()

    def _on_focus_in(self, _e=None) -> None:
        self.configure(bg=Colors.BORDER_FOCUS)
        if self._has_placeholder:
            self._has_placeholder = False
            self.var.set("")
            self.entry.configure(fg=Colors.TEXT_PRIMARY)

    def _on_focus_out(self, _e=None) -> None:
        self.configure(bg=Colors.BORDER)
        if not self.var.get().strip():
            self._has_placeholder = True
            self.var.set(self._placeholder)
            self.entry.configure(fg=Colors.TEXT_MUTED)
            self._clear_btn.pack_forget()

    def _on_key(self, _e=None) -> None:
        if self._has_placeholder:
            return
        txt = self.var.get()
        if txt:
            if not self._clear_btn.winfo_ismapped():
                self._clear_btn.pack(side="right")
        else:
            self._clear_btn.pack_forget()
        if self._on_change:
            if self._after_id:
                self.after_cancel(self._after_id)
            self._after_id = self.after(self._debounce_ms, lambda: self._on_change(self.get_query()))

    def _on_return(self, _e=None) -> None:
        if self._on_submit:
            self._on_submit(self.get_query())


class AppleToggle(tk.Frame):
    """Apple-style smooth pill toggle switch with label (4x supersampled Pillow sprites)."""

    def __init__(
        self,
        parent: tk.Misc,
        label: str,
        initial: bool = False,
        on_change: Optional[Callable[[bool], None]] = None,
        subtitle: str = "",
        bg: Optional[str] = None,
    ) -> None:
        self._bg = bg or str(parent.cget("bg"))
        super().__init__(parent, bg=self._bg, cursor="hand2")
        self._value = initial
        self._on_change = on_change

        self._img_on = ImageTk.PhotoImage(make_toggle_pil(True, self._bg, width=dp(38), height=dp(20)), master=self)
        self._img_off = ImageTk.PhotoImage(make_toggle_pil(False, self._bg, width=dp(38), height=dp(20)), master=self)

        self._switch_lbl = tk.Label(self, image=self._img_on if initial else self._img_off, bg=self._bg, bd=0)
        self._switch_lbl.pack(side="left", padx=(0, 8))

        text_box = tk.Frame(self, bg=self._bg)
        text_box.pack(side="left", fill="x", expand=True)

        self._lbl = tk.Label(text_box, text=label, bg=self._bg, fg=Colors.TEXT_PRIMARY, font=Fonts.small_bold(), anchor="w")
        self._lbl.pack(fill="x")
        if subtitle:
            self._sub = tk.Label(text_box, text=subtitle, bg=self._bg, fg=Colors.TEXT_MUTED, font=Fonts.micro(), anchor="w")
            self._sub.pack(fill="x")
            self._sub.bind("<Button-1>", self._toggle)

        for w in (self, self._switch_lbl, text_box, self._lbl):
            w.bind("<Button-1>", self._toggle)

    @property
    def value(self) -> bool:
        return self._value

    def set_value(self, val: bool) -> None:
        self._value = bool(val)
        self._switch_lbl.configure(image=self._img_on if self._value else self._img_off)

    def _toggle(self, _e=None) -> None:
        self.set_value(not self._value)
        if self._on_change:
            self._on_change(self._value)


class MetricCard(tk.Frame):
    """Minimalist dark KPI card with subtle hairline border and left color accent."""

    def __init__(self, parent: tk.Misc, title: str, value: str, accent: str) -> None:
        super().__init__(parent, bg=Colors.BORDER_SUBTLE, padx=1, pady=1)
        inner = tk.Frame(self, bg=Colors.BG_SURFACE)
        inner.pack(fill="both", expand=True)

        tk.Frame(inner, width=3, bg=accent).pack(side="left", fill="y")

        content = tk.Frame(inner, bg=Colors.BG_SURFACE, padx=12, pady=8)
        content.pack(side="left", fill="both", expand=True)

        tk.Label(content, text=title, bg=Colors.BG_SURFACE, fg=Colors.TEXT_MUTED, font=Fonts.micro(), anchor="w").pack(fill="x")
        self._val_lbl = tk.Label(content, text=value, bg=Colors.BG_SURFACE, fg=Colors.TEXT_PRIMARY, font=Fonts.kpi(), anchor="w")
        self._val_lbl.pack(fill="x", pady=(2, 0))

    def set_value(self, text: str) -> None:
        self._val_lbl.configure(text=text)
