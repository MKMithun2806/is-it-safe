import random
import time
import requests

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
]

WAF_SIGNATURES = {
    "Cloudflare": ["__cfduid", "cf-ray", "cloudflare"],
    "ModSecurity": ["mod_security", "NOYB"],
    "Barracuda": ["barra_counter_session", "BNI__B_pool"],
    "Sucuri": ["sucuri_cloudproxy_uuid", "x-sucuri-id"],
    "Akamai": ["akamai-ghost", "ak_bmsc", "bm_sz"],
    "F5 BIG-IP": ["BigIP", "TS01", "MRHSession"],
    "Imperva": ["_incap_ses", "visid_incap", "X-Iinfo"]
}

def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0"
    }

def apply_jitter(min_delay=0.5, max_delay=2.0):
    time.sleep(random.uniform(min_delay, max_delay))

def detect_waf(target_url):
    results = []
    print(f"[*] Analyzing WAF for {target_url}...")
    
    try:
        # 1. Baseline Request
        apply_jitter()
        headers = get_random_headers()
        response = requests.get(target_url, headers=headers, timeout=10)
        
        # Check Headers & Cookies
        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if any(sig.lower() in str(v).lower() for v in response.headers.values()) or \
                   any(sig.lower() in k.lower() for k in response.cookies.get_dict().keys()):
                    results.append(waf_name)
                    break
        
        # 2. Crafted "Malicious" Request (Stealthy)
        # Just a simple SQLi attempt to see if it triggers a block
        apply_jitter()
        malicious_url = f"{target_url}?id=1' OR '1'='1"
        try:
            mal_response = requests.get(malicious_url, headers=get_random_headers(), timeout=10)
            if mal_response.status_code in [403, 406, 501]:
                results.append(f"Generic WAF (Blocked with {mal_response.status_code})")
        except requests.RequestException:
            results.append("Possible IPS/WAF (Connection Reset on Payload)")

    except requests.RequestException as e:
        return [f"Error connecting: {e}"]

    return list(set(results))
