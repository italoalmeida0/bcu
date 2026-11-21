"""
Native Windows application icon extraction (pure ctypes ExtractIconExW + StoreApp AppxManifest
PNG reader) and 4x supersampled Apple-style Pillow vector sprites for zero-lag Tkinter UI.
"""

from __future__ import annotations

import os
import re
import sys
import threading
from pathlib import Path
from typing import Dict, Optional, Tuple
from PIL import Image, ImageDraw, ImageFont, ImageTk

from bcu.enrichers.detector import extract_executable_path
from bcu.models import ApplicationEntry, UninstallerType

IS_WINDOWS = sys.platform == "win32"

_TYPE_PALETTE: Dict[UninstallerType, Tuple[str, str]] = {
    UninstallerType.MSIEXEC: ("#2563EB", "#1D4ED8"),
    UninstallerType.INNO_SETUP: ("#16A34A", "#15803D"),
    UninstallerType.NSIS: ("#D97706", "#B45309"),
    UninstallerType.STORE_APP: ("#0891B2", "#0E7490"),
    UninstallerType.WINGET: ("#7C3AED", "#6D28D9"),
    UninstallerType.SCOOP: ("#059669", "#047857"),
    UninstallerType.CHOCOLATEY: ("#9333EA", "#7E22CE"),
    UninstallerType.STEAM: ("#1E40AF", "#1E3A8A"),
    UninstallerType.WINDOWS_FEATURE: ("#475569", "#334155"),
    UninstallerType.WINDOWS_UPDATE: ("#334155", "#1E293B"),
    UninstallerType.INSTALL_SHIELD: ("#EA580C", "#C2410C"),
    UninstallerType.CUSTOM: ("#3B82F6", "#2563EB"),
}

_FONT_CACHE: Dict[int, ImageFont.FreeTypeFont | ImageFont.ImageFont] = {}


def _get_pil_font(px_size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    cached = _FONT_CACHE.get(px_size)
    if cached is not None:
        return cached
    candidates = [
        r"C:\Windows\Fonts\seguisb.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\arialbd.ttf",
        "DejaVuSans-Bold.ttf",
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                f = ImageFont.truetype(path, px_size)
                _FONT_CACHE[px_size] = f
                return f
            except Exception:
                continue
    f = ImageFont.load_default()
    _FONT_CACHE[px_size] = f
    return f


def _hex_to_rgb(hex_color: str) -> Tuple[int, int, int]:
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def make_rounded_rect_pil(
    width: int,
    height: int,
    radius: int,
    fill: str,
    border: Optional[str] = None,
    border_width: int = 1,
    bg_matte: Optional[str] = None,
) -> Image.Image:
    """Renders a 4x supersampled subpixel-smooth rounded rectangle sprite."""
    scale = 4
    sw, sh = max(1, width * scale), max(1, height * scale)
    sr = min(radius * scale, min(sw, sh) // 2)

    if bg_matte:
        r, g, b = _hex_to_rgb(bg_matte)
        img = Image.new("RGBA", (sw, sh), (r, g, b, 255))
    else:
        img = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))

    draw = ImageDraw.Draw(img)
    fr, fg, fb = _hex_to_rgb(fill)
    if border:
        br, bg_c, bb = _hex_to_rgb(border)
        bw = max(1, border_width * scale)
        draw.rounded_rectangle(
            [bw // 2, bw // 2, sw - 1 - bw // 2, sh - 1 - bw // 2],
            radius=sr,
            fill=(fr, fg, fb, 255),
            outline=(br, bg_c, bb, 255),
            width=bw,
        )
    else:
        draw.rounded_rectangle([0, 0, sw - 1, sh - 1], radius=sr, fill=(fr, fg, fb, 255))

    return img.resize((max(1, width), max(1, height)), Image.Resampling.LANCZOS)


def make_toggle_pil(checked: bool, bg_matte: str, width: int = 38, height: int = 20) -> Image.Image:
    """Renders an Apple-style smooth pill toggle switch (4x supersampled)."""
    scale = 4
    sw, sh = width * scale, height * scale
    mr, mg, mb = _hex_to_rgb(bg_matte)
    img = Image.new("RGBA", (sw, sh), (mr, mg, mb, 255))
    draw = ImageDraw.Draw(img)

    track_color = (59, 130, 246, 255) if checked else (42, 52, 71, 255)
    border_color = (96, 165, 250, 255) if checked else (61, 74, 99, 255)
    draw.rounded_rectangle(
        [2, 2, sw - 3, sh - 3],
        radius=sh // 2,
        fill=track_color,
        outline=border_color,
        width=scale,
    )

    pad = 3 * scale
    knob_d = sh - 2 * pad
    kx0 = (sw - pad - knob_d) if checked else pad
    draw.ellipse([kx0, pad, kx0 + knob_d, pad + knob_d], fill=(248, 250, 252, 255))

    return img.resize((width, height), Image.Resampling.LANCZOS)


def make_app_logo_pil(size: int = 32) -> Image.Image:
    """Renders the BCU minimalist rounded shield/spark emblem (4x supersampled)."""
    scale = 4
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Smooth blue-indigo vertical gradient squircle
    c1 = _hex_to_rgb("#3B82F6")
    c2 = _hex_to_rgb("#6366F1")
    grad = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    gdraw = ImageDraw.Draw(grad)
    for y in range(s):
        t = y / max(1, s - 1)
        r = int(c1[0] + (c2[0] - c1[0]) * t)
        g = int(c1[1] + (c2[1] - c1[1]) * t)
        b = int(c1[2] + (c2[2] - c1[2]) * t)
        gdraw.line([(0, y), (s, y)], fill=(r, g, b, 255))

    mask = Image.new("L", (s, s), 0)
    mdraw = ImageDraw.Draw(mask)
    mdraw.rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.28), fill=255)
    img.paste(grad, (0, 0), mask)

    # Subtle glossy inner rim
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle(
        [scale, scale, s - 1 - scale, s - 1 - scale],
        radius=int(s * 0.26),
        outline=(255, 255, 255, 55),
        width=scale,
    )

    # Crisp stylized 'B' glyph
    font = _get_pil_font(int(s * 0.56))
    bbox = draw.textbbox((0, 0), "B", font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (s - tw) // 2 - bbox[0]
    ty = (s - th) // 2 - bbox[1]
    draw.text((tx, ty), "B", font=font, fill=(255, 255, 255, 245))

    return img.resize((size, size), Image.Resampling.LANCZOS)


def make_monogram_pil(app: ApplicationEntry, size: int = 22) -> Image.Image:
    """Renders an Apple-style anti-aliased squircle monogram fallback icon."""
    scale = 4
    s = size * scale
    c_top_hex, c_bot_hex = _TYPE_PALETTE.get(app.uninstaller_type, ("#3B82F6", "#2563EB"))
    c1, c2 = _hex_to_rgb(c_top_hex), _hex_to_rgb(c_bot_hex)

    grad = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    gdraw = ImageDraw.Draw(grad)
    for y in range(s):
        t = y / max(1, s - 1)
        r = int(c1[0] + (c2[0] - c1[0]) * t)
        g = int(c1[1] + (c2[1] - c1[1]) * t)
        b = int(c1[2] + (c2[2] - c1[2]) * t)
        gdraw.line([(0, y), (s, y)], fill=(r, g, b, 255))

    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.27), fill=255)
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    img.paste(grad, (0, 0), mask)

    draw = ImageDraw.Draw(img)
    name = (app.display_name_trimmed or "?").strip()
    letter = next((ch.upper() for ch in name if ch.isalnum()), "?")
    font = _get_pil_font(int(s * 0.54))
    bbox = draw.textbbox((0, 0), letter, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text(((s - tw) // 2 - bbox[0], (s - th) // 2 - bbox[1]), letter, font=font, fill=(255, 255, 255, 240))

    return img.resize((size, size), Image.Resampling.LANCZOS)


def _extract_hicon_to_pil(file_path: str, icon_index: int = 0) -> Optional[Image.Image]:
    """Extracts a Windows icon from an .exe/.dll/.ico using pure ctypes (zero MFC/pywin32 UI bloat)."""
    if not IS_WINDOWS or not file_path or not os.path.exists(file_path):
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class ICONINFO(ctypes.Structure):
            _fields_ = [
                ("fIcon", wintypes.BOOL),
                ("xHotspot", wintypes.DWORD),
                ("yHotspot", wintypes.DWORD),
                ("hbmMask", wintypes.HBITMAP),
                ("hbmColor", wintypes.HBITMAP),
            ]

        class BITMAP(ctypes.Structure):
            _fields_ = [
                ("bmType", wintypes.LONG),
                ("bmWidth", wintypes.LONG),
                ("bmHeight", wintypes.LONG),
                ("bmWidthBytes", wintypes.LONG),
                ("bmPlanes", wintypes.WORD),
                ("bmBitsPixel", wintypes.WORD),
                ("bmBits", wintypes.LPVOID),
            ]

        class BITMAPINFOHEADER(ctypes.Structure):
            _fields_ = [
                ("biSize", wintypes.DWORD),
                ("biWidth", wintypes.LONG),
                ("biHeight", wintypes.LONG),
                ("biPlanes", wintypes.WORD),
                ("biBitCount", wintypes.WORD),
                ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD),
                ("biXPelsPerMeter", wintypes.LONG),
                ("biYPelsPerMeter", wintypes.LONG),
                ("biClrUsed", wintypes.DWORD),
                ("biClrImportant", wintypes.DWORD),
            ]

        shell32 = ctypes.windll.shell32
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32

        h_large = wintypes.HICON()
        h_small = wintypes.HICON()
        extracted = shell32.ExtractIconExW(file_path, icon_index, ctypes.byref(h_large), ctypes.byref(h_small), 1)
        if extracted == 0 or (not h_large and not h_small):
            return None

        hicon = h_large if h_large else h_small
        info = ICONINFO()
        hdc = None
        try:
            if not user32.GetIconInfo(hicon, ctypes.byref(info)):
                return None
            if not info.hbmColor:
                return None

            bmp = BITMAP()
            if not gdi32.GetObjectW(info.hbmColor, ctypes.sizeof(bmp), ctypes.byref(bmp)):
                return None
            w, h = int(bmp.bmWidth), int(bmp.bmHeight)
            if w <= 0 or h <= 0 or w > 512 or h > 512:
                return None

            bmi = BITMAPINFOHEADER()
            bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
            bmi.biWidth = w
            bmi.biHeight = -h  # top-down DIB
            bmi.biPlanes = 1
            bmi.biBitCount = 32
            bmi.biCompression = 0  # BI_RGB

            color_buf = ctypes.create_string_buffer(w * h * 4)
            hdc = user32.GetDC(0)
            res = gdi32.GetDIBits(hdc, info.hbmColor, 0, h, color_buf, ctypes.byref(bmi), 0)
            if not res:
                return None

            raw = bytearray(color_buf.raw)
            # Check if alpha channel is all-zero (legacy 24-bit icon using hbmMask for transparency)
            has_alpha = any(raw[3::4])
            if not has_alpha and info.hbmMask:
                mask_buf = ctypes.create_string_buffer(w * h * 4)
                if gdi32.GetDIBits(hdc, info.hbmMask, 0, h, mask_buf, ctypes.byref(bmi), 0):
                    mask_raw = mask_buf.raw
                    for px in range(0, len(raw), 4):
                        raw[px + 3] = 0 if mask_raw[px] != 0 else 255
                else:
                    for px in range(3, len(raw), 4):
                        raw[px] = 255

            return Image.frombytes("RGBA", (w, h), bytes(raw), "raw", "BGRA")
        finally:
            if hdc:
                user32.ReleaseDC(0, hdc)
            if info.hbmColor:
                gdi32.DeleteObject(info.hbmColor)
            if info.hbmMask:
                gdi32.DeleteObject(info.hbmMask)
            if h_large:
                user32.DestroyIcon(h_large)
            if h_small:
                user32.DestroyIcon(h_small)
    except Exception:
        return None


def _find_store_app_logo(install_location: str) -> Optional[Path]:
    """Finds a PNG logo image for a Windows Store App inside its package folder."""
    try:
        root = Path(install_location)
        manifest = root / "AppxManifest.xml"
        if not manifest.exists():
            return None
        xml_text = manifest.read_text(encoding="utf-8", errors="ignore")
        for attr in ("Square44x44Logo", "Square150x150Logo", "Logo"):
            m = re.search(rf'{attr}\s*=\s*"([^"]+)"', xml_text, re.IGNORECASE)
            if not m:
                continue
            rel = m.group(1).replace("/", "\\")
            exact = root / rel
            if exact.exists() and exact.is_file():
                return exact
            # Store apps store scaled variants like Assets\AppList.targetsize-48.png or .scale-200.png
            parent = exact.parent
            if parent.exists():
                stem = exact.stem
                ext = exact.suffix or ".png"
                matches = sorted(
                    parent.glob(f"{stem}*{ext}"),
                    key=lambda p: (
                        "contrast" in p.name.lower(),
                        "unplated" not in p.name.lower(),
                        -p.stat().st_size if p.exists() else 0,
                    ),
                )
                if matches:
                    return matches[0]
    except Exception:
        pass
    return None


def _parse_display_icon_spec(raw_icon: str) -> Tuple[Optional[str], int]:
    """Parses Registry DisplayIcon values like '\"C:\\App\\app.exe\",0' or 'C:\\App\\icon.ico,-101'."""
    s = raw_icon.strip()
    if not s:
        return None, 0
    idx = 0
    if "," in s:
        left, right = s.rsplit(",", 1)
        try:
            idx = int(right.strip())
            s = left.strip()
        except ValueError:
            pass
    path = extract_executable_path(s) or s.strip('"').strip("'")
    path = os.path.expandvars(path)
    return (path if path and os.path.exists(path) else None), idx


def _is_visible_rgba(img: Image.Image) -> bool:
    """Rejects completely transparent dummy icons (common on some Windows system StoreApps)."""
    try:
        rgba = img if img.mode == "RGBA" else img.convert("RGBA")
        _, max_alpha = rgba.getchannel("A").getextrema()
        return max_alpha >= 16
    except Exception:
        return False


def _extract_raw_app_pil_icon(app: ApplicationEntry) -> Optional[Image.Image]:
    """
    Extracts the full-resolution native application icon as an RGBA Pillow Image.
    Returns None if no visible native icon is found.
    """
    # 1. Explicit Registry DisplayIcon
    if app.display_icon:
        icon_path, icon_idx = _parse_display_icon_spec(app.display_icon)
        if icon_path:
            ext = Path(icon_path).suffix.lower()
            if ext in (".ico", ".png", ".bmp"):
                try:
                    with Image.open(icon_path) as im:
                        rgba = im.convert("RGBA")
                        if _is_visible_rgba(rgba):
                            return rgba
                except Exception:
                    pass
            pil_img = _extract_hicon_to_pil(icon_path, icon_idx)
            if pil_img is not None and _is_visible_rgba(pil_img):
                return pil_img

    # 2. Store App AppxManifest PNG logo
    if app.uninstaller_type == UninstallerType.STORE_APP and app.install_location:
        logo_path = _find_store_app_logo(app.install_location)
        if logo_path:
            try:
                with Image.open(logo_path) as im:
                    rgba = im.convert("RGBA")
                    if _is_visible_rgba(rgba):
                        return rgba
            except Exception:
                pass

    # 3. Main executable in install_location (preferring non-uninstaller .exe)
    if app.install_location and os.path.isdir(app.install_location):
        try:
            exes = [
                p
                for p in Path(app.install_location).iterdir()
                if p.is_file() and p.suffix.lower() == ".exe"
            ]
            # Prefer real app binary over uninstall.exe / unins000.exe
            exes.sort(key=lambda p: ("unins" in p.name.lower() or "setup" in p.name.lower(), p.name.lower()))
            for exe_p in exes[:3]:
                pil_img = _extract_hicon_to_pil(str(exe_p), 0)
                if pil_img is not None and _is_visible_rgba(pil_img):
                    return pil_img
        except (PermissionError, OSError):
            pass

    # 4. Fallback to uninstaller exe itself (if not msiexec/cmd/powershell)
    if app.uninstall_string:
        u_exe = extract_executable_path(os.path.expandvars(app.uninstall_string))
        if u_exe and os.path.exists(u_exe):
            if os.path.basename(u_exe).lower() not in ("msiexec.exe", "cmd.exe", "powershell.exe", "rundll32.exe"):
                pil_img = _extract_hicon_to_pil(u_exe, 0)
                if pil_img is not None and _is_visible_rgba(pil_img):
                    return pil_img

    return None


def extract_app_pil_icon(app: ApplicationEntry, size: int = 22) -> Optional[Image.Image]:
    """
    Attempts to extract a real native application icon as a crisp RGBA Pillow Image.
    Returns None if no visible native icon is found (caller falls back to monogram icon).
    """
    raw = _extract_raw_app_pil_icon(app)
    if raw is None:
        return None
    if raw.size == (size, size):
        return raw
    return raw.resize((size, size), Image.Resampling.LANCZOS)


class AppIconCache:
    """Thread-safe cache of raw Pillow icons + main-thread Tk PhotoImage handles."""

    def __init__(self, master) -> None:
        self._master = master
        self._raw_cache: Dict[str, Optional[Image.Image]] = {}
        self._tk_cache: Dict[Tuple[str, int], ImageTk.PhotoImage] = {}
        self._monogram_tk: Dict[Tuple[str, int], ImageTk.PhotoImage] = {}
        self._lock = threading.Lock()

    def get_instant_tk_icon(self, app: ApplicationEntry, size: int = 22) -> ImageTk.PhotoImage:
        """Returns cached real icon if already extracted, else an instant crisp monogram icon."""
        key = (app.id, size)
        if key in self._tk_cache:
            return self._tk_cache[key]

        with self._lock:
            raw = self._raw_cache.get(app.id)
        if raw is not None:
            resized = raw if raw.size == (size, size) else raw.resize((size, size), Image.Resampling.LANCZOS)
            tk_img = ImageTk.PhotoImage(resized, master=self._master)
            self._tk_cache[key] = tk_img
            return tk_img

        # Instant monogram keyed by (uninstaller_type, first_letter, size) to keep memory tiny
        letter = next((ch.upper() for ch in (app.display_name_trimmed or "?") if ch.isalnum()), "?")
        m_key = (f"{app.uninstaller_type.value}:{letter}", size)
        if m_key not in self._monogram_tk:
            self._monogram_tk[m_key] = ImageTk.PhotoImage(make_monogram_pil(app, size=size), master=self._master)
        return self._monogram_tk[m_key]

    def extract_in_background(self, app: ApplicationEntry, size: int = 22) -> bool:
        """
        Extracts native icon into raw PIL cache once per app (safe from worker threads).
        Returns True if a real native icon is available and not yet promoted at `size`.
        """
        with self._lock:
            already_tried = app.id in self._raw_cache
            raw = self._raw_cache.get(app.id)
        if not already_tried:
            raw = _extract_raw_app_pil_icon(app)
            with self._lock:
                self._raw_cache[app.id] = raw
        return raw is not None and (app.id, size) not in self._tk_cache

    def promote_to_tk(self, app_id: str, size: int = 22) -> Optional[ImageTk.PhotoImage]:
        """Converts cached raw PIL icon into a Tk PhotoImage at `size` (MUST be called on Tk main thread)."""
        key = (app_id, size)
        if key in self._tk_cache:
            return self._tk_cache[key]
        with self._lock:
            raw = self._raw_cache.get(app_id)
        if raw is None:
            return None
        resized = raw if raw.size == (size, size) else raw.resize((size, size), Image.Resampling.LANCZOS)
        tk_img = ImageTk.PhotoImage(resized, master=self._master)
        self._tk_cache[key] = tk_img
        return tk_img
