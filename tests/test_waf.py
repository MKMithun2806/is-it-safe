import pytest
from unittest.mock import MagicMock
from is_it_safe.modules.waf import check_response_for_waf, detect_waf

def test_check_response_for_waf():
    # Mock response with Cloudflare headers
    mock_resp = MagicMock()
    mock_resp.headers = {"cf-ray": "12345", "server": "cloudflare"}
    mock_resp.cookies = {}
    
    assert check_response_for_waf(mock_resp, "Cloudflare") is True
    assert check_response_for_waf(mock_resp, "Akamai") is False

def test_check_response_for_waf_cookies():
    # Mock response with Akamai cookies
    mock_resp = MagicMock()
    mock_resp.headers = {}
    mock_resp.cookies = {"ak_bmsc": "somevalue"}
    
    assert check_response_for_waf(mock_resp, "Akamai") is True

@pytest.fixture
def mock_safe_request(mocker):
    return mocker.patch("is_it_safe.modules.waf.safe_request")

def test_detect_waf_signature_match(mock_safe_request):
    mock_resp = MagicMock()
    mock_resp.headers = {"cf-ray": "12345"}
    mock_resp.cookies = {}
    mock_safe_request.return_value = mock_resp
    
    results = detect_waf("https://example.com")
    assert any(r["name"] == "Cloudflare" for r in results)
    assert any(r["confidence"] == "high" for r in results)

def test_detect_waf_no_connection(mock_safe_request):
    mock_safe_request.return_value = None
    
    results = detect_waf("https://example.com")
    assert results[0]["name"] == "Unable to connect"
