"""
Unit tests for data models, validation, and serialization.
"""

from bcu.models import ApplicationEntry, FilterCriteria, JunkItem, JunkType, ConfidenceLevel, UninstallerType
from bcu.scanners.manager import ScannerManager


def test_application_entry_properties(sample_inno_app: ApplicationEntry):
    assert sample_inno_app.display_name_trimmed == "Notepad++ (64-bit x64)"
    assert sample_inno_app.publisher_trimmed == "Notepad++ Team"
    assert sample_inno_app.has_valid_uninstaller is True


def test_filter_criteria(sample_apps_list: list[ApplicationEntry]):
    # Query match
    res = ScannerManager.filter_entries(sample_apps_list, FilterCriteria(query="Notepad"))
    assert len(res) == 1
    assert res[0].id == "reg:hklm:notepadplusplus"

    # Exclude system components
    res_no_sys = ScannerManager.filter_entries(sample_apps_list, FilterCriteria(include_system=False))
    assert all(not a.is_system_component for a in res_no_sys)

    # Include system components
    res_sys = ScannerManager.filter_entries(sample_apps_list, FilterCriteria(include_system=True, include_protected=True))
    assert any(a.is_system_component for a in res_sys)


def test_junk_item_model():
    item = JunkItem(
        app_id="app:test",
        app_name="Test App",
        junk_type=JunkType.REGISTRY_KEY,
        path="HKCU\\Software\\TestApp",
        confidence_level=ConfidenceLevel.VERY_GOOD,
        raw_score=10,
    )
    assert item.id == "RegistryKey:HKCU\\Software\\TestApp"
    assert item.confidence_level == ConfidenceLevel.VERY_GOOD
