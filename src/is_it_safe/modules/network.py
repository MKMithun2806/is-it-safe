"""Network layer identification module for is-it-safe."""
import logging
import socket
from typing import List, Dict
from .utils import safe_request, resolve_host

logger = logging.getLogger(__name__)

CDN_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray"],
    "Akamai": ["akamai", "edgekey"],
    "AWS CloudFront": ["cloudfront"],
    "Fastly": ["fastly"],
    "Google Cloud": ["google"],
    "Azure Front Door": ["azure"],
    "Incapsula": ["incapsula", "imperva"]
}

def identify_network_layer(url: str, host: str) -> List[Dict[str, str]]:
    """Identify CDN and infrastructure providers."""
    results = []
    
    # 1. DNS-based identification (CNAME/PTR)
    try:
        # Basic reverse DNS check if possible, or just look for known patterns in hostname
        addr = resolve_host(host)
        if addr:
            try:
                ptr = socket.gethostbyaddr(addr)[0]
                for provider, sigs in CDN_SIGNATURES.items():
                    for sig in sigs:
                        if sig in ptr.lower():
                            results.append({"name": f"{provider} (DNS)", "confidence": "high", "details": f"PTR: {ptr}"})
                            break
            except (socket.herror, socket.gaierror):
                pass
    except Exception as e:
        logger.debug(f"DNS identification error: {e}")

    # 2. Header-based identification (redundant with WAF but good for network layer)
    resp = safe_request(url, timeout=5)
    if resp:
        server_header = resp.headers.get("Server", "").lower()
        for provider, sigs in CDN_SIGNATURES.items():
            for sig in sigs:
                if sig in server_header:
                    results.append({"name": f"{provider} (Header)", "confidence": "high", "details": f"Server: {resp.headers.get('Server')}"})
                    break

    if not results:
        results.append({"name": "Generic Infrastructure", "confidence": "low", "details": "No specific CDN/Cloud provider detected"})
        
    return results
