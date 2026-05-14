"""WAF detection module for is-it-safe."""
import logging
from typing import List, Dict, Any, Optional, Set
from .utils import safe_request, apply_jitter

logger = logging.getLogger(__name__)

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "cookies": ["__cfduid", "cf_clearance"],
        "confidence": "high"
    },
    "Akamai": {
        "headers": ["x-akamai", "akamai-ghost", "server: akamaighost"],
        "cookies": ["ak_bmsc", "bm_sz"],
        "confidence": "high"
    },
    "AWS CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "server: cloudfront"],
        "cookies": [],
        "confidence": "high"
    },
    "Imperva/Incapsula": {
        "headers": ["x-iinfo", "incap_ses", "x-cdn: incapsula"],
        "cookies": ["incap_ses", "visid_incap"],
        "confidence": "high"
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri/cloudproxy"],
        "cookies": ["sucuri_cloudproxy_uuid"],
        "confidence": "high"
    },
    "F5 BIG-IP": {
        "headers": ["x-cpro-rule", "server: big-ip", "x-wa-info"],
        "cookies": ["bigipserver", "mrhsessions"],
        "confidence": "medium"
    },
    "ModSecurity": {
        "headers": ["x-mod-security", "server: mod_security"],
        "cookies": ["noYB"],
        "confidence": "medium"
    },
    "Barracuda": {
        "headers": ["server: barracuda", "x-barracuda-brts"],
        "cookies": ["barra_counter_session", "bni__b_pool"],
        "confidence": "medium"
    },
    "FortiWeb": {
        "headers": ["server: fortiweb-waf"],
        "cookies": ["fortiwafsid"],
        "confidence": "high"
    },
    "Radware AppWall": {
        "headers": ["x-sl-compid", "server: radware"],
        "cookies": [],
        "confidence": "medium"
    }
}

BENIGN_PAYLOADS = ["", "?id=1", "/favicon.ico"]
SUSPICIOUS_PAYLOADS = ["?id=1' OR '1'='1", "?id=<script>alert(1)</script>", "/etc/passwd", "?cmd=ls"]

def check_response_for_waf(response: Any, waf_name: str) -> bool:
    """Check if response headers/cookies match WAF signatures."""
    if not response:
        return False
    
    sigs = WAF_SIGNATURES[waf_name]
    headers_str = "\n".join([f"{k}: {v}" for k, v in response.headers.items()]).lower()
    
    for header in sigs["headers"]:
        if header.lower() in headers_str:
            return True
            
    for cookie in response.cookies.keys():
        for sig_cookie in sigs["cookies"]:
            if sig_cookie.lower() in cookie.lower():
                return True
                
    return False

def test_response_behavior(url: str, jitter: bool = True) -> Optional[Dict[str, Any]]:
    """Compare behavior between benign and suspicious payloads."""
    apply_jitter(enabled=jitter)
    benign_resp = safe_request(url)
    if not benign_resp:
        return None
    
    apply_jitter(enabled=jitter)
    for payload in SUSPICIOUS_PAYLOADS:
        # Properly append query params
        if "?" in url:
            suspicious_url = url + "&" + payload.lstrip("?")
        else:
            suspicious_url = url + payload
        resp = safe_request(suspicious_url)
        
        if not resp:
            # Connection dropped/reset often indicates a WAF/IPS
            return {"type": "Connection Drop", "payload": payload}
            
        if resp.status_code != benign_resp.status_code:
            if resp.status_code in [403, 406, 501, 429, 999]:
                return {"type": "Status Code Change", "code": resp.status_code, "payload": payload}
        
        # Check for WAF strings in body (some WAFs return 200 with a block page)
        block_keywords = ["blocked by", "waf", "security challenge", "incident id", "request id"]
        for kw in block_keywords:
            if kw in resp.text.lower() and kw not in benign_resp.text.lower():
                return {"type": "Block Page Content", "keyword": kw, "payload": payload}
                
    return None

def detect_waf(target_url: str, timeout: int = 10, jitter: bool = True) -> List[Dict[str, str]]:
    """Detect WAF with confidence scoring."""
    results = []
    matched_wafs: Set[str] = set()
    
    response = safe_request(target_url, timeout=timeout)
    if not response:
        return [{"name": "Unable to connect", "confidence": "low", "details": "Initial request failed"}]
    
    # Signature matching - only one WAF per detection
    for waf_name in WAF_SIGNATURES:
        if check_response_for_waf(response, waf_name):
            matched_wafs.add(waf_name)
    
    # Prioritize high confidence matches
    for waf_name in matched_wafs:
        results.append({
            "name": waf_name, 
            "confidence": WAF_SIGNATURES[waf_name]["confidence"],
            "details": "Signature match in headers/cookies"
        })
    
    # Behavioral testing
    behavior = test_response_behavior(target_url, jitter)
    if behavior:
        results.append({
            "name": "Generic Behavioral WAF", 
            "confidence": "medium",
            "details": f"Behavioral anomaly: {behavior['type']} on payload '{behavior.get('payload', '')}'"
        })
    
    if not results:
        results.append({"name": "No WAF detected", "confidence": "low", "details": "No signatures or behavioral anomalies found"})
    
    return results
