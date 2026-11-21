"""
Global configuration and safety policies for BCU Python CLI.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Set

# Version information
VERSION = "0.2.0"
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
    "c:\\windows\\sysarm32",
    "c:\\windows\\winsxs",
    "c:\\windows\\prefetch",
    "c:\\windows\\installer",
    "c:\\program files",
    "c:\\program files (x86)",
    "c:\\program files (arm)",
    "c:\\program files\\common files",
    "c:\\program files (x86)\\common files",
    "c:\\programdata",
    "c:\\programdata\\package cache",
    "c:\\users",
    "c:\\users\\public",
}

# System subtrees where NO child files or folders may ever be deleted
PROHIBITED_SUBTREE_PREFIXES: Set[str] = {
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\sysarm32",
    "c:\\windows\\winsxs",
    "c:\\windows\\boot",
    "c:\\windows\\servicing",
}

# Dynamically populate system paths if running on Windows
if sys.platform == "win32":
    system_root = os.environ.get("SystemRoot", "C:\\Windows").lower()
    program_files = os.environ.get("ProgramFiles", "C:\\Program Files").lower()
    program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)").lower()
    program_files_arm = os.environ.get("ProgramFiles(Arm)", "").lower()
    program_data = os.environ.get("ProgramData", "C:\\ProgramData").lower()
    user_profile = os.environ.get("USERPROFILE", "").lower()
    appdata = os.environ.get("APPDATA", "").lower()
    localappdata = os.environ.get("LOCALAPPDATA", "").lower()

    dynamic_paths = [
        system_root,
        os.path.join(system_root, "system32"),
        os.path.join(system_root, "syswow64"),
        os.path.join(system_root, "sysarm32"),
        os.path.join(system_root, "winsxs"),
        os.path.join(system_root, "prefetch"),
        os.path.join(system_root, "installer"),
        program_files,
        os.path.join(program_files, "common files"),
        program_files_x86,
        os.path.join(program_files_x86, "common files"),
        program_files_arm,
        program_data,
        os.path.join(program_data, "package cache"),
        user_profile,
        appdata,
        localappdata,
    ]
    if user_profile:
        for sub in (
            "appdata",
            "appdata\\locallow",
            "desktop",
            "documents",
            "downloads",
            "pictures",
            "music",
            "videos",
        ):
            dynamic_paths.append(os.path.join(user_profile, sub))
    if localappdata:
        dynamic_paths.append(os.path.join(localappdata, "programs"))
    if appdata:
        dynamic_paths.append(os.path.join(appdata, "programs"))

    for p in dynamic_paths:
        if p:
            PROHIBITED_DIRECTORIES.add(os.path.normpath(p).lower())

    if system_root:
        for sub in ("system32", "syswow64", "sysarm32", "winsxs", "boot", "servicing"):
            PROHIBITED_SUBTREE_PREFIXES.add(os.path.normpath(os.path.join(system_root, sub)).lower())

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
    "wow6432node",
    "software",
    "currentversion",
    "uninstall",
    "run",
    "runonce",
    "app paths",
    "clsid",
    "currentcontrolset",
    "controlset001",
    "controlset002",
    "services",
}

# Default uninstallation settings
DEFAULT_PROCESS_TIMEOUT_SEC = 300  # 5 minutes
DEFAULT_STALL_IDLE_TIMEOUT_SEC = 45  # 45 seconds of zero CPU / IO activity
MSIEXEC_BUSY_RETRY_INTERVAL_SEC = 2.0
MSIEXEC_MAX_RETRIES = 15

# Safety settings
ALLOW_SYSTEM_COMPONENT_UNINSTALL = False
USE_RECYCLE_BIN = True  # Send deleted files to recycle bin where available
