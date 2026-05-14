#!/usr/bin/env python3
import argparse
import sys
import logging
import json
from typing import Optional, Dict, Any, List
import urllib3
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler
from rich.theme import Theme

from .modules.waf import detect_waf
from .modules.ids_ips import detect_ids_ips
from .modules.network import identify_network_layer
from .modules.fail2ban import detect_fail2ban

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Custom theme for professional look
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "high": "bold green",
    "medium": "bold yellow",
    "low": "dim white",
})

console = Console(theme=custom_theme)

def setup_logging(verbose: bool):
    """Configure logging with Rich."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console)]
    )
    
    # Suppress verbose urllib3 retry warnings
    logging.getLogger('urllib3').setLevel(logging.ERROR)

def banner():
    """Print a stylish banner."""
    banner_text = """
    ╔╦╗╔═╗  ╦╔╦╗  ╔═╗╔═╗╔═╗╔═╗
     ║ ╚═╗  ║ ║   ╚═╗╠═╣╠╣ ║╣ 
    ╩ ╚═╝  ╩ ╩   ╚═╝╩ ╩╚  ╚═╝
    Stealthy Security Layer Detector v5.0
    """
    console.print(Panel(banner_text, style="info", expand=False))

def validate_url(target: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Validate and normalize the target URL."""
    if not target:
        return None, None, "No target provided"
    
    if not target.startswith(('http://', 'https://')):
        normalized_url = f"https://{target}"
    else:
        normalized_url = target
        
    try:
        parsed = urlparse(normalized_url)
        if not parsed.netloc:
            return None, target, "Missing hostname"
        return normalized_url, parsed.netloc, None
    except Exception as e:
        return None, None, f"URL parsing error: {e}"

def calculate_score(results: Dict[str, Any]) -> tuple[int, str]:
    """Calculate a security risk score and safety recommendation."""
    score = 0
    
    weights = {
        "high": 1.0,
        "medium": 0.6,
        "low": 0.2
    }
    
    category_points = {
        "waf": 40,
        "ids_ips": 50,
        "fail2ban": 30,
        "network": 10
    }
    
    for cat, detections in results.items():
        if cat not in category_points:
            continue
            
        cat_base = category_points[cat]
        for d in detections:
            name = d.get("name", "").lower()
            conf = d.get("confidence", "low").lower()
            
            # Skip negative or informational detections
            skip_keywords = ["no ", "none", "unable to", "required", "needed", "skipped", "no strong evidence", "generic infrastructure"]
            if any(x in name for x in skip_keywords):
                continue
            
            score += int(cat_base * weights.get(conf, 0.2))
            
    # Cap score at 100
    score = min(score, 100)
    
    # Safe if score is low (under 30)
    safe = "Yes" if score < 30 else "No"
    return score, safe

def display_results(results: Dict[str, Any], verbose: bool):
    """Display scan results in a professional table."""
    table = Table(title=f"Scan Results for: [bold]{results['target']}[/bold]", show_header=True, header_style="bold magenta")
    table.add_column("Category", style="cyan")
    table.add_column("Detection", style="white")
    table.add_column("Confidence", justify="center")
    
    categories = {
        "WAF": results["waf"],
        "Network": results["network"],
        "Fail2Ban": results["fail2ban"],
        "IDS/IPS": results["ids_ips"]
    }
    
    for cat_name, detections in categories.items():
        for i, d in enumerate(detections):
            conf = d.get("confidence", "low")
            conf_style = f"[{conf}]{conf}[/]"
            
            row_name = cat_name if i == 0 else ""
            table.add_row(row_name, d["name"], conf_style)
            
            if verbose and d.get("details"):
                table.add_row("", f"[dim]> {d['details']}[/dim]", "")
        
        table.add_section()
        
    console.print(table)
    
    # Display Score and Safety Recommendation
    score = results.get("risk_score", 0)
    safe = results.get("safe_to_scan", "Yes")
    
    score_color = "success" if score < 30 else "warning" if score < 60 else "error"
    safe_color = "success" if safe == "Yes" else "error"
    
    console.print(f"\n[bold]Risk Score:[/] [{score_color}]{score}/100[/]")
    console.print(f"[bold]Safe to Scan:[/] [{safe_color}]{safe}[/]\n")

def main():
    parser = argparse.ArgumentParser(
        description="is-it-safe: Stealthy WAF/IDS/IPS/fail2ban detector v5.0",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("target", nargs="?", help="Target URL, Hostname, or IP")
    parser.add_argument("-v", "--version", action="store_true", help="Show version and exit")
    parser.add_argument("-s", "--stealth", action="store_true", help="Enable maximum stealth (higher jitter)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--jitter", action="store_true", help="Add random delays between requests")
    parser.add_argument("--verbose", action="store_true", help="Show detailed detection signals")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port for fail2ban detection")
    args = parser.parse_args()

    if args.version:
        console.print("is-it-safe v5.0.0")
        sys.exit(0)

    if not args.target:
        parser.print_help()
        console.print("\n[info]Example:[/] [bold]is-it-safe example.com[/bold]")
        sys.exit(1)
    
    setup_logging(args.verbose)
    
    url, host, error = validate_url(args.target)
    
    if not host:
        console.print(f"[error]Error:[/] {error}")
        sys.exit(1)

    if not args.json:
        banner()
        console.print(f"[*] Starting scan for [bold cyan]{host}[/]...")
    
    # Check if HTTP service is available
    http_available = url is not None
    
    with console.status("[bold green]Scanning security layers...") as status:
        if http_available:
            status.update("[bold green]Detecting WAF...")
            waf_results = detect_waf(url, timeout=args.timeout, jitter=args.jitter or args.stealth)
            
            status.update("[bold green]Identifying Network Layer...")
            network_results = identify_network_layer(url, host=host)
        else:
            waf_results = [{"name": "No HTTP service detected", "confidence": "low", "details": "Target has no web service on port 80/443"}]
            network_results = [{"name": "No HTTP service detected", "confidence": "low", "details": "Target has no web service on port 80/443"}]
        
        status.update("[bold green]Probing for Fail2Ban (SSH)...")
        fail2ban_results = detect_fail2ban(host, port=args.ssh_port)
        
        status.update("[bold green]Testing IDS/IPS signals...")
        if http_available:
            ids_results = detect_ids_ips(host, url=url, use_tcp=True)
        else:
            ids_results = [{"name": "No HTTP service", "confidence": "low", "details": "Skipped - no web service to test"}]

    results = {
        "target": host,
        "http_available": http_available,
        "waf": waf_results,
        "network": network_results,
        "fail2ban": fail2ban_results,
        "ids_ips": ids_results
    }

    # Calculate score
    score, safe = calculate_score(results)
    results["risk_score"] = score
    results["safe_to_scan"] = safe

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        display_results(results, args.verbose)
        console.print("[success]Scan complete.[/]")

if __name__ == "__main__":
    main()
