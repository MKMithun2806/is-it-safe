"""fail2ban detection module for is-it-safe."""
import logging
import socket
import time
import ipaddress
from typing import List, Dict, Tuple, Optional
from .utils import resolve_host

logger = logging.getLogger(__name__)

PARAMIKO_AVAILABLE = False
try:
    import paramiko # type: ignore
    PARAMIKO_AVAILABLE = True
except ImportError:
    logger.warning("paramiko not installed - SSH detection limited. Install: pip install paramiko")

INVALID_USERNAMES = ["admin", "root", "user", "test", "guest", "oracle", "ubuntu"]
DEFAULT_SSH_PORT = 22
MAX_ATTEMPTS = 4

def is_valid_target(target: str) -> Tuple[bool, Optional[str]]:
    """Validate that target is a valid IP or hostname."""
    if not target:
        return False, "No target provided"
    
    try:
        ipaddress.ip_address(target)
        return True, None
    except ValueError:
        pass
    
    if len(target) < 1 or len(target) > 253:
        return False, "Invalid hostname length"
    
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
    if not all(c in allowed for c in target):
        return False, "Invalid characters in target"
    
    return True, None

def check_ssh_banner(target_host: str, port: int = 22, timeout: int = 5) -> Optional[str]:
    """Grab SSH banner to identify service."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target_host, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner
    except Exception as e:
        logger.debug(f"SSH banner grab failed: {e}")
        return None

def detect_fail2ban_ssh(target_host: str, port: int = 22, timeout: int = 5) -> List[Dict[str, str]]:
    """Detect fail2ban by probing SSH with multiple auth attempts."""
    results = []
    
    if not PARAMIKO_AVAILABLE:
        return [{"name": "paramiko not installed", "confidence": "low", 
                 "details": "pip install paramiko for SSH detection"}]
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        for i, username in enumerate(INVALID_USERNAMES[:MAX_ATTEMPTS]):
            start_time = time.time()
            try:
                client.connect(
                    target_host, 
                    port=port, 
                    username=username, 
                    password="wrong_password_12345",
                    timeout=timeout,
                    allow_agent=False,
                    look_for_keys=False
                )
                client.close()
            except paramiko.AuthenticationException:
                elapsed = time.time() - start_time
                if elapsed > 3:
                    results.append({
                        "name": "Fail2Ban SSH",
                        "confidence": "high",
                        "details": f"Slow auth ({elapsed:.1f}s) after {i+1} attempts - possible tarpit"
                    })
                    break
            except paramiko.SSHException as e:
                error_msg = str(e).lower()
                if "too many" in error_msg or "ban" in error_msg or "denied" in error_msg:
                    results.append({
                        "name": "Fail2Ban SSH",
                        "confidence": "high",
                        "details": f"Blocked: {e}"
                    })
                    break
            except socket.timeout:
                results.append({
                    "name": "Fail2Ban SSH",
                    "confidence": "medium", 
                    "details": "Connection timeout - possible SSH tarpit"
                })
                break
            except EOFError:
                results.append({
                    "name": "Fail2Ban SSH", 
                    "confidence": "high",
                    "details": "EOF received - possibly banned"
                })
                break
            except Exception as e:
                logger.debug(f"SSH probe {i+1} error: {e}")
                
            time.sleep(0.5)
            
    except Exception as e:
        logger.debug(f"SSH Detection error: {e}")
    
    return results

def detect_ssh_service(target_host: str, port: int = 22) -> List[Dict[str, str]]:
    """Basic SSH service detection."""
    results = []
    
    banner = check_ssh_banner(target_host, port)
    if banner:
        if "openssh" in banner.lower():
            results.append({
                "name": "SSH (OpenSSH)",
                "confidence": "high",
                "details": banner.strip()
            })
        elif "dropbear" in banner.lower():
            results.append({
                "name": "SSH (Dropbear)",
                "confidence": "high", 
                "details": banner.strip()
            })
        else:
            results.append({
                "name": "SSH Service",
                "confidence": "medium",
                "details": banner.strip()
            })
    
    return results

def detect_fail2ban(target: str, port: int = 22) -> List[Dict[str, str]]:
    """Combined fail2ban detection for SSH."""
    all_results = []
    
    valid, error = is_valid_target(target)
    if not valid:
        return [{"name": "Invalid target", "confidence": "low", "details": error or "Target validation failed"}]
    
    host = target
    if "://" in host:
        host = host.split("://")[1].split("/")[0]
    
    if not host:
        return [{"name": "No target", "confidence": "low", "details": "Invalid target"}]
    
    ssh_service = detect_ssh_service(host, port)
    if not ssh_service:
        all_results.append({"name": "No SSH service", "confidence": "low", "details": "SSH port closed/not found"})
        return all_results
    
    all_results.extend(ssh_service)
    
    if PARAMIKO_AVAILABLE:
        fail2ban_results = detect_fail2ban_ssh(host, port)
        all_results.extend(fail2ban_results)
    else:
        all_results.append({"name": "paramiko needed", "confidence": "low", "details": "Install paramiko for fail2ban detection"})
    
    return all_results
