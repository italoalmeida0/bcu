"""
Platform abstractions, Windows Registry interface, and process utilities.
"""

from __future__ import annotations

import os
import sys
import subprocess
import shlex
import shutil
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import winreg
else:
    winreg = None  # type: ignore


class RegistryHelper:
    """Safely interact with Windows Registry keys and values."""

    HIVE_MAP = {
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE if winreg else None,
        "HKLM": winreg.HKEY_LOCAL_MACHINE if winreg else None,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER if winreg else None,
        "HKCU": winreg.HKEY_CURRENT_USER if winreg else None,
        "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT if winreg else None,
        "HKCR": winreg.HKEY_CLASSES_ROOT if winreg else None,
        "HKEY_USERS": winreg.HKEY_USERS if winreg else None,
        "HKU": winreg.HKEY_USERS if winreg else None,
    }

    @classmethod
    def split_hive_and_subpath(cls, full_path: str) -> Tuple[Optional[int], str]:
        """Splits full registry path (e.g. HKLM\\Software\\...) into hive constant and subkey path."""
        parts = full_path.replace("/", "\\").split("\\", 1)
        hive_name = parts[0].upper()
        subpath = parts[1] if len(parts) > 1 else ""
        hive = cls.HIVE_MAP.get(hive_name)
        return hive, subpath

    @classmethod
    def read_key_values(cls, hive: int, subpath: str, view_64: bool = True) -> Dict[str, Any]:
        """Reads all values under a registry key."""
        if not IS_WINDOWS or winreg is None:
            return {}

        access = winreg.KEY_READ
        if view_64:
            access |= winreg.KEY_WOW64_64KEY
        else:
            access |= winreg.KEY_WOW64_32KEY

        results: Dict[str, Any] = {}
        try:
            with winreg.OpenKey(hive, subpath, 0, access) as key:
                num_values = winreg.QueryInfoKey(key)[1]
                for i in range(num_values):
                    try:
                        val_name, val_data, _ = winreg.EnumValue(key, i)
                        results[val_name] = val_data
                    except (OSError, ValueError):
                        continue
        except (OSError, PermissionError, FileNotFoundError):
            pass
        return results

    @classmethod
    def enum_subkeys(cls, hive: int, subpath: str, view_64: bool = True) -> List[str]:
        """Enumerates child subkey names under a registry key."""
        if not IS_WINDOWS or winreg is None:
            return []

        access = winreg.KEY_READ
        if view_64:
            access |= winreg.KEY_WOW64_64KEY
        else:
            access |= winreg.KEY_WOW64_32KEY

        subkeys = []
        try:
            with winreg.OpenKey(hive, subpath, 0, access) as key:
                num_subkeys = winreg.QueryInfoKey(key)[0]
                for i in range(num_subkeys):
                    try:
                        subkeys.append(winreg.EnumKey(key, i))
                    except (OSError, ValueError):
                        continue
        except (OSError, PermissionError, FileNotFoundError):
            pass
        return subkeys

    @classmethod
    def key_exists(cls, hive: int, subpath: str, view_64: bool = True) -> bool:
        """Checks if a registry subkey exists."""
        if not IS_WINDOWS or winreg is None:
            return False

        access = winreg.KEY_READ
        if view_64:
            access |= winreg.KEY_WOW64_64KEY
        else:
            access |= winreg.KEY_WOW64_32KEY

        try:
            with winreg.OpenKey(hive, subpath, 0, access):
                return True
        except (OSError, PermissionError, FileNotFoundError):
            return False

    @classmethod
    def delete_key_recursively(cls, hive: int, subpath: str, view_64: bool = True) -> bool:
        """Recursively deletes a registry subkey and all its children."""
        if not IS_WINDOWS or winreg is None:
            return False

        access = winreg.KEY_ALL_ACCESS
        if view_64:
            access |= winreg.KEY_WOW64_64KEY
        else:
            access |= winreg.KEY_WOW64_32KEY

        try:
            # First delete all children recursively
            children = cls.enum_subkeys(hive, subpath, view_64)
            for child in children:
                child_subpath = f"{subpath}\\{child}"
                cls.delete_key_recursively(hive, child_subpath, view_64)

            # Now delete the key itself
            parent_path, key_name = subpath.rsplit("\\", 1) if "\\" in subpath else ("", subpath)
            with winreg.OpenKey(hive, parent_path, 0, access) as parent:
                winreg.DeleteKey(parent, key_name)
            return True
        except Exception:
            return False

    @classmethod
    def delete_value(cls, hive: int, subpath: str, value_name: str, view_64: bool = True) -> bool:
        """Deletes a specific value from a registry key."""
        if not IS_WINDOWS or winreg is None:
            return False

        access = winreg.KEY_SET_VALUE
        if view_64:
            access |= winreg.KEY_WOW64_64KEY
        else:
            access |= winreg.KEY_WOW64_32KEY

        try:
            with winreg.OpenKey(hive, subpath, 0, access) as key:
                winreg.DeleteValue(key, value_name)
            return True
        except Exception:
            return False


def run_powershell_command(cmd: str, timeout_sec: int = 30) -> Tuple[int, str, str]:
    """Runs a PowerShell command and returns (return_code, stdout, stderr)."""
    if not IS_WINDOWS:
        return 1, "", "PowerShell is only supported on Windows"

    full_cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        cmd,
    ]
    try:
        proc = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            encoding="utf-8",
            errors="replace",
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)


def delete_path_to_recycle_bin(path_str: str) -> Tuple[bool, str]:
    """Sends a file or folder to the Windows Recycle Bin using native Win32 SHFileOperationW."""
    if not IS_WINDOWS:
        return delete_path_permanent(path_str)

    abs_path = os.path.abspath(path_str)
    if not os.path.exists(abs_path):
        return True, "Path does not exist"

    try:
        import ctypes
        from ctypes import wintypes

        class SHFILEOPSTRUCTW(ctypes.Structure):
            _fields_ = [
                ("hwnd", wintypes.HWND),
                ("wFunc", wintypes.UINT),
                ("pFrom", wintypes.LPCWSTR),
                ("pTo", wintypes.LPCWSTR),
                ("fFlags", wintypes.WORD),
                ("fAnyOperationsAborted", wintypes.BOOL),
                ("hNameMappings", wintypes.LPVOID),
                ("lpszProgressTitle", wintypes.LPCWSTR),
            ]

        FO_DELETE = 0x0003
        FOF_ALLOWUNDO = 0x0040
        FOF_NOCONFIRMATION = 0x0010
        FOF_SILENT = 0x0004
        FOF_NOERRORUI = 0x0400

        # Double null-terminated string required by SHFileOperationW
        p_from = f"{abs_path}\0\0"

        file_op = SHFILEOPSTRUCTW()
        file_op.hwnd = None
        file_op.wFunc = FO_DELETE
        file_op.pFrom = p_from
        file_op.pTo = None
        file_op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
        file_op.fAnyOperationsAborted = False
        file_op.hNameMappings = None
        file_op.lpszProgressTitle = None

        result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(file_op))
        if result == 0 and not file_op.fAnyOperationsAborted:
            return True, "Moved to Recycle Bin"
        
        # Fallback to permanent deletion if shell operation failed
        return delete_path_permanent(path_str)
    except Exception:
        return delete_path_permanent(path_str)


def delete_path_permanent(path_str: str) -> Tuple[bool, str]:
    """Permanently deletes a file or directory."""
    p = Path(path_str)
    if not p.exists():
        return True, "Path does not exist"

    try:
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
        return True, "Permanently deleted"
    except Exception as e:
        return False, str(e)


def delete_path_safe(path_str: str, use_recycle_bin: bool = True) -> Tuple[bool, str]:
    """Safely deletes a file or directory, sending to Recycle Bin if enabled."""
    if use_recycle_bin and IS_WINDOWS:
        return delete_path_to_recycle_bin(path_str)
    return delete_path_permanent(path_str)


def create_system_restore_point(description: str) -> Tuple[bool, str]:
    """
    Creates a Windows System Restore Point before uninstallation operations.
    Requires administrative privileges.
    """
    if not IS_WINDOWS:
        return False, "System Restore is only available on Windows"

    clean_desc = description.replace("'", "").replace('"', "")[:80]
    ps_cmd = (
        f"Checkpoint-Computer -Description '{clean_desc}' "
        f"-RestorePointType 'APPLICATION_UNINSTALL' -ErrorAction Stop"
    )
    code, stdout, stderr = run_powershell_command(ps_cmd, timeout_sec=60)
    if code == 0:
        return True, f"System Restore Point created: '{clean_desc}'"
    return False, stderr or "Failed to create System Restore Point (Admin privileges required)"


def verify_authenticode_signature(file_path: str) -> Tuple[bool, Optional[str]]:
    """
    Verifies the Authenticode digital signature of an executable file on Windows.
    Returns (is_valid, signer_subject).
    """
    if not IS_WINDOWS or not file_path or not os.path.exists(file_path):
        return False, None

    clean_path = file_path.replace("'", "''")
    ps_cmd = (
        f"Get-AuthenticodeSignature -FilePath '{clean_path}' | "
        "Select-Object Status, @{Name='Signer'; Expression={$_.SignerCertificate.Subject}} | "
        "ConvertTo-Json -Compress"
    )
    code, stdout, _ = run_powershell_command(ps_cmd, timeout_sec=15)
    if code == 0 and stdout:
        try:
            import json
            data = json.loads(stdout)
            status = str(data.get("Status", "")).lower()
            signer = data.get("Signer")
            is_valid = status == "valid"
            return is_valid, signer
        except Exception:
            pass
    return False, None


def normalize_path(path_str: Optional[str]) -> str:
    """Normalizes path string for consistent comparison."""
    if not path_str:
        return ""
    clean = path_str.strip().strip('"').strip("'")
    if not clean:
        return ""
    return os.path.normpath(clean).lower()
