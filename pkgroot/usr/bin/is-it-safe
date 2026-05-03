#!/usr/bin/env python3
import argparse
import sys
import os
from urllib.parse import urlparse

# Add local modules to path if running from source
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))
sys.path.append('/usr/share/is-it-safe/modules')

try:
    from waf import detect_waf
except ImportError:
    print("[!] Error: Could not load WAF module. Ensure 'requests' is installed.")
    sys.exit(1)

try:
    from ids_ips import detect_ids_ips
except ImportError:
    def detect_ids_ips(target):
        return ["Skipped: 'scapy' not installed or IDS module missing"]

def banner():
    print("""
    ╔╦╗╔═╗  ╦╔╦╗  ╔═╗╔═╗╔═╗╔═╗
     ║ ╚═╗  ║ ║   ╚═╗╠═╣╠╣ ║╣ 
    ╩ ╚═╝  ╩ ╩   ╚═╝╩ ╩╚  ╚═╝
    Stealthy Security Layer Detector
    """)

def main():
    parser = argparse.ArgumentParser(description="is-it-safe: Stealthy WAF/IDS/IPS detector")
    parser.add_argument("target", help="Target URL or Hostname (e.g., https://example.com or example.com)")
    parser.add_argument("-s", "--stealth", action="store_true", help="Enable maximum stealth (higher jitter)")
    
    args = parser.parse_args()
    banner()

    target = args.target
    if not target.startswith(('http://', 'https://')):
        url = f"https://{target}"
        host = target
    else:
        url = target
        host = urlparse(target).netloc

    print(f"[*] Starting scan for {target}...")
    
    waf_results = detect_waf(url)
    ids_results = detect_ids_ips(host)

    print("\n" + "="*40)
    print(" SCAN RESULTS")
    print("="*40)
    
    print("\n[+] WAF Detection:")
    if waf_results:
        for r in waf_results:
            print(f"  - {r}")
    else:
        print("  - No obvious WAF detected.")

    print("\n[+] IDS/IPS/Proxy Detection:")
    if ids_results:
        for r in ids_results:
            print(f"  - {r}")
    else:
        print("  - No obvious IDS/IPS detected.")
    
    print("\n" + "="*40)

if __name__ == "__main__":
    main()
