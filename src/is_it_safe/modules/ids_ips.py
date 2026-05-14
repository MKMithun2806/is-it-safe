"""IDS/IPS detection module for is-it-safe."""
import os
import logging
import time
from typing import List, Dict, Any, Optional
from .utils import safe_request

logger = logging.getLogger(__name__)

SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, sr1 # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    logger.warning("scapy not installed - TCP-level IDS/IPS detection disabled")

def detect_ids_ips_tcp(target_host: str, port: int = 80) -> List[Dict[str, str]]:
    """Detect IDS/IPS using TCP-level signals."""
    results = []
    
    if not SCAPY_AVAILABLE:
        results.append({"name": "scapy required", "confidence": "low", "details": "Install scapy for TCP detection: pip install scapy"})
        return results
    
    if os.geteuid() != 0:
        results.append({"name": "root required", "confidence": "low", "details": "Run as root for TCP-level IDS/IPS detection"})
        return results
    
    try:
        # 1. Test for TCP Reset on suspicious payload-like sequence numbers or unusual flags
        pkt_syn = IP(dst=target_host)/TCP(dport=port, flags="S", seq=12345)
        start = time.time()
        ans = sr1(pkt_syn, timeout=2, verbose=0)
        
        if not ans:
            results.append({"name": "Packet Drop", "confidence": "medium", "details": "No response to SYN packet"})
        elif ans.haslayer(TCP):
            if ans[TCP].flags == 0x14: # RST-ACK
                results.append({"name": "TCP Reset", "confidence": "high", "details": "Immediate RST received"})
        
        # 2. Timing anomalies (Latency spikes)
        latencies = []
        for _ in range(3):
            s = time.time()
            sr1(IP(dst=target_host)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
            latencies.append(time.time() - s)
        
        if max(latencies) - min(latencies) > 0.5:
             results.append({"name": "Timing Anomaly", "confidence": "low", "details": "Jitter/latency spike detected"})

    except Exception as e:
        logger.warning(f"TCP IDS/IPS detection error: {e}")
    
    return results

def detect_ids_ips_http(target_url: str) -> List[Dict[str, str]]:
    """Detect IDS/IPS using HTTP-level signals (Rate limiting, blocking)."""
    results = []
    
    # 1. Rate limiting behavior
    codes = []
    for _ in range(5):
        resp = safe_request(target_url, timeout=5)
        if resp:
            codes.append(resp.status_code)
        else:
            codes.append(None)
    
    if 429 in codes:
        results.append({"name": "Rate Limiting", "confidence": "high", "details": "HTTP 429 received after rapid requests"})
    elif codes.count(None) >= 2:
        results.append({"name": "Connection Instability", "confidence": "medium", "details": "Intermittent connection drops detected"})

    # 2. Suspicious payload blocking
    suspicious_payloads = ["/etc/passwd", "?id=1' OR '1'='1"]
    for p in suspicious_payloads:
        try:
            resp = safe_request(target_url + p, timeout=5)
            if resp is None:
                results.append({"name": "Likely IPS", "confidence": "high", "details": f"Connection reset on payload: {p}"})
        except Exception:
            pass

    return results

def detect_ids_ips(target: str, url: Optional[str] = None, use_tcp: bool = True) -> List[Dict[str, str]]:
    """Combined IDS/IPS detection."""
    all_results = []
    
    if url:
        all_results.extend(detect_ids_ips_http(url))
    
    if use_tcp:
        host = target
        if "://" in host:
            host = host.split("://")[1].split("/")[0]
        
        tcp_res = detect_ids_ips_tcp(host)
        all_results.extend(tcp_res)
    
    if not all_results:
        return [{"name": "No strong evidence", "confidence": "low", "details": "No IDS/IPS signals detected"}]
    
    return all_results
