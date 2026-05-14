"""Utility functions for is-it-safe."""
import logging
import random
import time
import socket
from typing import Optional, Dict, List, Any
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0"
]

def get_random_headers() -> Dict[str, str]:
    """Return randomized HTTP headers."""
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
        "DNT": "1"
    }

def apply_jitter(enabled: bool = True, min_delay: float = 0.5, max_delay: float = 1.5) -> None:
    """Add random delay between requests for stealth."""
    if enabled:
        delay = random.uniform(min_delay, max_delay)
        logger.debug(f"Applying jitter: {delay:.2f}s")
        time.sleep(delay)

def resolve_host(target: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        # Strip protocol if present
        if "://" in target:
            target = target.split("://")[1].split("/")[0]
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def safe_request(url: str, timeout: int = 10, allow_redirects: bool = True, headers: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
    """Make a safe HTTP request with retries and error handling."""
    if headers is None:
        headers = get_random_headers()
        
    session = requests.Session()
    retries = Retry(total=2, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))

    try:
        response = session.get(
            url, 
            headers=headers, 
            timeout=timeout, 
            allow_redirects=allow_redirects,
            verify=True
        )
        return response
    except requests.exceptions.SSLError as e:
        logger.warning(f"SSL verification failed for {url}, falling back to verify=False: {e}")
        try:
            response = session.get(
                url, 
                headers=headers, 
                timeout=timeout, 
                allow_redirects=allow_redirects,
                verify=False
            )
            return response
        except requests.RequestException as e:
            logger.debug(f"Request error for {url}: {e}")
            return None
    except requests.RequestException as e:
        logger.debug(f"Request error for {url}: {e}")
        return None

def calculate_confidence(matches: int, total_signals: int) -> str:
    """Calculate confidence level based on signal matches."""
    if total_signals == 0:
        return "low"
    ratio = matches / total_signals
    if ratio >= 0.8:
        return "high"
    elif ratio >= 0.4:
        return "medium"
    return "low"
