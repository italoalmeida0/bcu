"""
Global configuration and safety policies for BCU Python CLI.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Set

# Version information
VERSION = "0.1.0"
APP_NAME = "BCU-CLI"

# Protected / essential applications that should not be uninstalled carelessly
PROTECTED_PUBLISHERS: Set[str] = {
    "microsoft corporation",
    "microsoft windows",
}

# Blacklisted directory paths that must NEVER be deleted by the junk cleaner
# Normalized to lowercase for matching
PROHIBITED_DIRECTORIES: Set[str] = {
    "c:\\",
    "c:\\windows",
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\program files",
    "c:\\program files (x86)",
    "c:\\programdata",
    "c:\\users",
    "c:\\users\\public",
}

# Dynamically populate system paths if running on Windows
if sys.platform == "win32":
    system_root = os.environ.get("SystemRoot", "C:\\Windows").lower()
    program_files = os.environ.get("ProgramFiles", "C:\\Program Files").lower()
    program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)").lower()
    program_data = os.environ.get("ProgramData", "C:\\ProgramData").lower()
    user_profile = os.environ.get("USERPROFILE", "").lower()
    appdata = os.environ.get("APPDATA", "").lower()
    localappdata = os.environ.get("LOCALAPPDATA", "").lower()

    for p in [system_root, program_files, program_files_x86, program_data, user_profile, appdata, localappdata]:
        if p:
            PROHIBITED_DIRECTORIES.add(os.path.normpath(p).lower())

# Blacklisted registry key segments to never delete as whole keys
PROHIBITED_REGISTRY_KEYS: Set[str] = {
    "microsoft",
    "windows",
    "classes",
    "clients",
    "microsoft.net",
    "directx",
    "windows nt",
    "policies",
    "system",
    "security",
    "sam",
}

# Default uninstallation settings
DEFAULT_PROCESS_TIMEOUT_SEC = 300  # 5 minutes
DEFAULT_STALL_IDLE_TIMEOUT_SEC = 45  # 45 seconds of zero CPU / IO activity
MSIEXEC_BUSY_RETRY_INTERVAL_SEC = 2.0
MSIEXEC_MAX_RETRIES = 15

# Safety settings
ALLOW_SYSTEM_COMPONENT_UNINSTALL = False
USE_RECYCLE_BIN = True  # Send deleted files to recycle bin where available
