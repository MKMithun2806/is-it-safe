import os
import sys
import random
import time

try:
    from scapy.all import IP, TCP, sr1, conf
except ImportError:
    pass # Handled in the main script

def detect_ids_ips(target_host):
    results = []
    
    if os.geteuid() != 0:
        return ["Skipped: Root privileges required for IDS/IPS detection"]

    print(f"[*] Analyzing IDS/IPS for {target_host}...")

    try:
        # 1. TTL Analysis (Simple)
        # Send a packet with a low TTL and see if we get a response from an unexpected middlebox
        # This is a heuristic and can be noisy, but it's a classic technique.
        ttl_val = random.randint(2, 5)
        pkt = IP(dst=target_host, ttl=ttl_val)/TCP(dport=80, flags="S")
        ans = sr1(pkt, timeout=2, verbose=0)
        
        if ans and ans.src != target_host:
             results.append(f"Possible Intermediate Device (TTL {ttl_val} reached {ans.src})")

        # 2. Invalid Checksum Test
        # Many IPS will drop packets with invalid checksums, while some might alert on them.
        # If the target normally responds but doesn't to this, a middlebox might be dropping it.
        pkt_bad_cksum = IP(dst=target_host)/TCP(dport=80, flags="S", chksum=0x1234)
        ans_bad = sr1(pkt_bad_cksum, timeout=2, verbose=0)
        
        # Compare with a normal SYN
        pkt_normal = IP(dst=target_host)/TCP(dport=80, flags="S")
        ans_normal = sr1(pkt_normal, timeout=2, verbose=0)
        
        if ans_normal and not ans_bad:
            results.append("Possible IPS (Dropped packet with invalid checksum)")

    except Exception as e:
        results.append(f"IDS/IPS detection error: {e}")

    return results
