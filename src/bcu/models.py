"""
Data models for BCU (Bulk Crap Uninstaller) Python CLI.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class UninstallerType(str, enum.Enum):
    """Types of uninstallers recognized by BCU."""
    UNKNOWN = "Unknown"
    MSIEXEC = "Msiexec"
    INNO_SETUP = "InnoSetup"
    NSIS = "Nsis"
    INSTALL_SHIELD = "InstallShield"
    SDB_INST = "SdbInst"
    WINDOWS_FEATURE = "WindowsFeature"
    WINDOWS_UPDATE = "WindowsUpdate"
    STORE_APP = "StoreApp"
    SIMPLE_DELETE = "SimpleDelete"
    CHOCOLATEY = "Chocolatey"
    SCOOP = "Scoop"
    WINGET = "Winget"
    STEAM = "Steam"
    OCULUS = "Oculus"
    POWER_SHELL = "PowerShell"
    CUSTOM = "Custom"


class ConfidenceLevel(str, enum.Enum):
    """Confidence levels for detected junk remnants."""
    UNKNOWN = "Unknown"
    BAD = "Bad"
    QUESTIONABLE = "Questionable"
    GOOD = "Good"
    VERY_GOOD = "VeryGood"

    @property
    def numeric_rank(self) -> int:
        ranks = {
            ConfidenceLevel.UNKNOWN: 0,
            ConfidenceLevel.BAD: 1,
            ConfidenceLevel.QUESTIONABLE: 2,
            ConfidenceLevel.GOOD: 3,
            ConfidenceLevel.VERY_GOOD: 4,
        }
        return ranks.get(self, 0)

    def __ge__(self, other: ConfidenceLevel | str) -> bool:
        if isinstance(other, str):
            try:
                other = ConfidenceLevel(other)
            except ValueError:
                return False
        return self.numeric_rank >= other.numeric_rank

    def __gt__(self, other: ConfidenceLevel | str) -> bool:
        if isinstance(other, str):
            try:
                other = ConfidenceLevel(other)
            except ValueError:
                return False
        return self.numeric_rank > other.numeric_rank

    def __le__(self, other: ConfidenceLevel | str) -> bool:
        if isinstance(other, str):
            try:
                other = ConfidenceLevel(other)
            except ValueError:
                return False
        return self.numeric_rank <= other.numeric_rank

    def __lt__(self, other: ConfidenceLevel | str) -> bool:
        if isinstance(other, str):
            try:
                other = ConfidenceLevel(other)
            except ValueError:
                return False
        return self.numeric_rank < other.numeric_rank


class JunkType(str, enum.Enum):
    """Types of detected remnant items."""
    REGISTRY_KEY = "RegistryKey"
    REGISTRY_VALUE = "RegistryValue"
    DIRECTORY = "Directory"
    FILE = "File"
    SHORTCUT = "Shortcut"
    STARTUP_ENTRY = "StartupEntry"
    SERVICE = "Service"
    SCHEDULED_TASK = "ScheduledTask"
    FIREWALL_RULE = "FirewallRule"
    APP_PATH = "AppPath"
    COM_CLSID = "ComClsid"
    APP_COMPAT = "AppCompat"
    CRASH_DUMP = "CrashDump"
    PREFETCH = "Prefetch"
    AUDIO_POLICY = "AudioPolicy"


class UninstallStatus(str, enum.Enum):
    """Lifecycle statuses for uninstallation jobs."""
    WAITING = "Waiting"
    RUNNING = "Running"
    COMPLETED = "Completed"
    SKIPPED = "Skipped"
    FAILED = "Failed"
    INVALID = "Invalid"


class JunkItem(BaseModel):
    """Represents a leftover junk item associated with an application."""
    id: str = Field(default_factory=lambda: "")
    app_id: str
    app_name: str
    junk_type: JunkType
    path: str
    confidence_level: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    raw_score: int = 0
    reasons: List[str] = Field(default_factory=list)
    size_bytes: Optional[int] = None
    is_protected: bool = False
    backup_file_path: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = f"{self.junk_type.value}:{self.path}"


class ApplicationEntry(BaseModel):
    """Represents an installed application discovered on the system."""
    id: str
    display_name: str
    display_version: Optional[str] = None
    publisher: Optional[str] = None
    install_location: Optional[str] = None
    uninstall_string: Optional[str] = None
    quiet_uninstall_string: Optional[str] = None
    install_date: Optional[str] = None
    estimated_size_bytes: Optional[int] = None
    uninstaller_type: UninstallerType = UninstallerType.UNKNOWN
    is_system_component: bool = False
    is_protected: bool = False
    is_64_bit: bool = False
    registry_path: Optional[str] = None
    registry_key_name: Optional[str] = None
    bundle_provider_key: Optional[str] = None
    about_url: Optional[str] = None
    install_source: Optional[str] = None
    display_icon: Optional[str] = None
    comments: Optional[str] = None
    source_scanner: str = "Registry"
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def display_name_trimmed(self) -> str:
        return (self.display_name or "").strip()

    @property
    def publisher_trimmed(self) -> str:
        return (self.publisher or "").strip()

    @property
    def quiet_uninstall_possible(self) -> bool:
        return bool(self.quiet_uninstall_string and self.quiet_uninstall_string.strip())

    @property
    def has_valid_uninstaller(self) -> bool:
        return bool(
            (self.uninstall_string and self.uninstall_string.strip())
            or (self.quiet_uninstall_string and self.quiet_uninstall_string.strip())
            or (self.uninstaller_type == UninstallerType.STORE_APP)
            or (self.uninstaller_type == UninstallerType.SIMPLE_DELETE and self.install_location)
        )


class UninstallResult(BaseModel):
    """Outcome of an uninstallation operation."""
    app_id: str
    app_name: str
    status: UninstallStatus
    exit_code: Optional[int] = None
    duration_sec: float = 0.0
    command_executed: Optional[str] = None
    error_message: Optional[str] = None
    junk_cleaned_count: int = 0
    cleaned_junk_items: List[JunkItem] = Field(default_factory=list)
    backup_file_path: Optional[str] = None


class FilterCriteria(BaseModel):
    """Filter criteria for searching and selecting applications."""
    query: Optional[str] = None
    publisher: Optional[str] = None
    uninstaller_type: Optional[UninstallerType] = None
    include_system: bool = False
    include_protected: bool = False
    min_size_bytes: Optional[int] = None
    max_size_bytes: Optional[int] = None
    has_quiet_only: bool = False
    source_scanner: Optional[str] = None
    regex_match: bool = False


class SeverityLevel(str, enum.Enum):
    """Vulnerability severity rankings."""
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def numeric_rank(self) -> int:
        ranks = {
            SeverityLevel.UNKNOWN: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }
        return ranks.get(self, 0)

    def __ge__(self, other: SeverityLevel | str) -> bool:
        if isinstance(other, str):
            try:
                other = SeverityLevel(other.capitalize())
            except ValueError:
                return False
        return self.numeric_rank >= other.numeric_rank

    def __gt__(self, other: SeverityLevel | str) -> bool:
        if isinstance(other, str):
            try:
                other = SeverityLevel(other.capitalize())
            except ValueError:
                return False
        return self.numeric_rank > other.numeric_rank

    def __le__(self, other: SeverityLevel | str) -> bool:
        if isinstance(other, str):
            try:
                other = SeverityLevel(other.capitalize())
            except ValueError:
                return False
        return self.numeric_rank <= other.numeric_rank

    def __lt__(self, other: SeverityLevel | str) -> bool:
        if isinstance(other, str):
            try:
                other = SeverityLevel(other.capitalize())
            except ValueError:
                return False
        return self.numeric_rank < other.numeric_rank


class VulnerabilityFinding(BaseModel):
    """Represents a discovered vulnerability or security advisory matching an application."""
    id: str  # e.g. "CVE-2023-38831"
    app_id: str
    app_name: str
    installed_version: str
    affected_range: str
    fixed_version: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM
    cvss_score: Optional[float] = None
    title: str
    description: str
    references: List[str] = Field(default_factory=list)


class VulnerabilityReport(BaseModel):
    """Comprehensive summary of vulnerability audit."""
    total_scanned: int = 0
    vulnerable_apps_count: int = 0
    total_vulnerabilities: int = 0
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)

