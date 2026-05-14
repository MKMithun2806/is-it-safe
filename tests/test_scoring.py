import pytest
from is_it_safe.main import calculate_score

def test_calculate_score_empty():
    results = {
        "waf": [],
        "network": [],
        "fail2ban": [],
        "ids_ips": []
    }
    score, safe = calculate_score(results)
    assert score == 0
    assert safe == "Yes"

def test_calculate_score_no_detections():
    results = {
        "waf": [{"name": "No WAF detected", "confidence": "low"}],
        "network": [{"name": "Generic Infrastructure", "confidence": "low"}],
        "fail2ban": [{"name": "No SSH service", "confidence": "low"}],
        "ids_ips": [{"name": "No strong evidence", "confidence": "low"}]
    }
    score, safe = calculate_score(results)
    assert score == 0
    assert safe == "Yes"

def test_calculate_score_high_risk():
    results = {
        "waf": [{"name": "Cloudflare", "confidence": "high"}],
        "network": [{"name": "Cloudflare (Header)", "confidence": "high"}],
        "fail2ban": [{"name": "No SSH service", "confidence": "low"}],
        "ids_ips": [{"name": "No strong evidence", "confidence": "low"}]
    }
    score, safe = calculate_score(results)
    # WAF high (40) + Network high (10) = 50
    assert score == 50
    assert safe == "No"

def test_calculate_score_medium_risk():
    results = {
        "waf": [{"name": "Generic Behavioral WAF", "confidence": "medium"}],
        "network": [{"name": "Generic Infrastructure", "confidence": "low"}],
        "fail2ban": [{"name": "No SSH service", "confidence": "low"}],
        "ids_ips": [{"name": "No strong evidence", "confidence": "low"}]
    }
    score, safe = calculate_score(results)
    # WAF medium (40 * 0.6 = 24)
    assert score == 24
    assert safe == "Yes"

def test_calculate_score_multiple_layers():
    results = {
        "waf": [{"name": "Sucuri", "confidence": "high"}],
        "network": [{"name": "Sucuri (Header)", "confidence": "high"}],
        "fail2ban": [{"name": "Fail2Ban SSH", "confidence": "high"}],
        "ids_ips": [{"name": "Likely IPS", "confidence": "high"}]
    }
    score, safe = calculate_score(results)
    # WAF high (40) + Network high (10) + Fail2Ban high (30) + IDS high (50) = 130 -> 100
    assert score == 100
    assert safe == "No"
