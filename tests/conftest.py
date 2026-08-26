"""
Pytest configuration and shared fixtures for BCU tests.
"""

from __future__ import annotations

import pytest
from bcu.models import ApplicationEntry, ConfidenceLevel, JunkItem, JunkType, UninstallerType


@pytest.fixture
def sample_inno_app() -> ApplicationEntry:
    return ApplicationEntry(
        id="reg:hklm:notepadplusplus",
        display_name="Notepad++ (64-bit x64)",
        display_version="8.5.8",
        publisher="Notepad++ Team",
        install_location="C:\\Program Files\\Notepad++",
        uninstall_string='"C:\\Program Files\\Notepad++\\uninstall.exe"',
        estimated_size_bytes=15000000,
        uninstaller_type=UninstallerType.INNO_SETUP,
        is_64_bit=True,
    )


@pytest.fixture
def sample_msi_app() -> ApplicationEntry:
    return ApplicationEntry(
        id="reg:hklm:{33d1fd90-4274-48a1-9bc1-97e33d9c2d6f}",
        display_name="Microsoft Visual C++ 2019 X64 Additional Runtime",
        display_version="14.28.29913",
        publisher="Microsoft Corporation",
        uninstall_string="MsiExec.exe /X{33D1FD90-4274-48A1-9BC1-97E33D9C2D6F}",
        bundle_provider_key="{33D1FD90-4274-48A1-9BC1-97E33D9C2D6F}",
        estimated_size_bytes=24000000,
        uninstaller_type=UninstallerType.MSIEXEC,
        is_system_component=True,
        is_protected=True,
    )


@pytest.fixture
def sample_store_app() -> ApplicationEntry:
    return ApplicationEntry(
        id="store:microsoft.bingweather_4.53.51131.0_x64__8wekyb3d8bbwe",
        display_name="MSN Weather (Store App)",
        display_version="4.53.51131.0",
        publisher="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
        uninstaller_type=UninstallerType.STORE_APP,
        raw_metadata={
            "IsStoreApp": True,
            "PackageFullName": "Microsoft.BingWeather_4.53.51131.0_x64__8wekyb3d8bbwe",
        },
    )


@pytest.fixture
def sample_apps_list(sample_inno_app, sample_msi_app, sample_store_app) -> list[ApplicationEntry]:
    return [sample_inno_app, sample_msi_app, sample_store_app]
