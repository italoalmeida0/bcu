"""
Unit tests for Sift4 string distance and similarity calculations.
"""

from bcu.utils.sift4 import sift4_simplest_distance, similarity_ratio


def test_sift4_identical_strings():
    assert sift4_simplest_distance("notepad", "notepad") == 0
    assert similarity_ratio("notepad", "notepad") == 1.0


def test_sift4_empty_strings():
    assert sift4_simplest_distance("", "test") == 4
    assert sift4_simplest_distance("test", "") == 4
    assert sift4_simplest_distance("", "") == 0
    assert similarity_ratio("", "") == 1.0


def test_sift4_small_difference():
    # 1 character difference
    dist = sift4_simplest_distance("photoshop", "photoshope", max_offset=2)
    assert dist <= 1
    assert similarity_ratio("photoshop", "photoshope") >= 0.85


def test_sift4_completely_different():
    dist = sift4_simplest_distance("adobe", "spotify", max_offset=2)
    assert dist >= 4
    assert similarity_ratio("adobe", "spotify") < 0.5
