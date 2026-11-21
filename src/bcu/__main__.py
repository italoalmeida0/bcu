"""
Main entry point when invoked via python -m bcu or standalone bcu.exe
"""

import sys

# Ensure UTF-8 console output on Windows (prevents mojibake in frozen PyInstaller builds)
if sys.platform == "win32":
    for _stream in (sys.stdout, sys.stderr):
        if _stream is not None and hasattr(_stream, "reconfigure"):
            try:
                _stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

from bcu.cli import main

if __name__ == "__main__":
    main()
