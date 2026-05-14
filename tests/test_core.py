import pytest
from is_it_safe.main import validate_url
from is_it_safe.modules.utils import calculate_confidence

def test_validate_url():
    # Test with protocol
    url, host, error = validate_url("https://example.com")
    assert url == "https://example.com"
    assert host == "example.com"
    assert error is None

    # Test without protocol
    url, host, error = validate_url("example.com")
    assert url == "https://example.com"
    assert host == "example.com"
    assert error is None

    # Test invalid URL
    url, host, error = validate_url("")
    assert url is None
    assert host is None
    assert error == "No target provided"

def test_calculate_confidence():
    assert calculate_confidence(10, 10) == "high"
    assert calculate_confidence(8, 10) == "high"
    assert calculate_confidence(5, 10) == "medium"
    assert calculate_confidence(4, 10) == "medium"
    assert calculate_confidence(2, 10) == "low"
    assert calculate_confidence(0, 10) == "low"
    assert calculate_confidence(0, 0) == "low"
