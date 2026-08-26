"""
Unit tests for confidence scoring and level mapping.
"""

from bcu.junk.confidence import ConfidenceCalculator
from bcu.models import ApplicationEntry, ConfidenceLevel


def test_confidence_perfect_match(sample_inno_app: ApplicationEntry):
    level, score, reasons = ConfidenceCalculator.evaluate_confidence(
        app=sample_inno_app,
        item_name="Notepad++",
        item_parent_path="C:\\Program Files",
        depth_level=0,
    )
    assert level == ConfidenceLevel.VERY_GOOD
    assert score >= 5
    assert any("perfect match" in r.lower() for r in reasons)


def test_confidence_parent_company_match():
    app = ApplicationEntry(
        id="app:photoshop",
        display_name="Photoshop CC 2024",
        publisher="Adobe Systems",
    )
    level, score, reasons = ConfidenceCalculator.evaluate_confidence(
        app=app,
        item_name="Photoshop CC 2024",
        item_parent_path="C:\\Program Files\\Adobe",
        depth_level=1,
    )
    assert level == ConfidenceLevel.VERY_GOOD
    assert any("company name" in r.lower() for r in reasons)


def test_confidence_level_comparison():
    assert ConfidenceLevel.VERY_GOOD > ConfidenceLevel.GOOD
    assert ConfidenceLevel.GOOD > ConfidenceLevel.QUESTIONABLE
    assert ConfidenceLevel.QUESTIONABLE > ConfidenceLevel.BAD
    assert ConfidenceLevel.GOOD >= ConfidenceLevel.GOOD
    assert ConfidenceLevel.BAD < ConfidenceLevel.GOOD
