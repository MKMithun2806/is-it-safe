# is-it-safe 🛡️

**Stealthy Security Layer Detector v5.0**

`is-it-safe` is a powerful, stealthy tool designed to identify security layers protecting a target. It detects Web Application Firewalls (WAF), Intrusion Detection/Prevention Systems (IDS/IPS), and Fail2Ban instances without triggering aggressive alarms.

## Features

- **WAF Detection:** Identifies 10+ major WAF vendors via signature matching and behavioral analysis.
- **IDS/IPS Detection:** Uses TCP-level signals (requires root) and HTTP behavioral anomalies.
- **Fail2Ban Probing:** Safely identifies SSH tarpits and ban policies.
- **Network Layer Fingerprinting:** Detects CDNs and infrastructure providers (Cloudflare, Akamai, AWS, etc.).
- **Stealth Mode:** Implements randomized jitter, user-agents, and request patterns to avoid detection.
- **JSON Output:** Easy integration with other tools.

## Installation

### From Source

```bash
git clone https://github.com/mithun/is-it-safe.git
cd is-it-safe
pip install .
```

For full features (including TCP IDS detection and SSH probing):

```bash
pip install ".[full]"
```

## Usage

```bash
# Basic scan
is-it-safe example.com

# Verbose scan with stealth enabled
is-it-safe example.com --stealth --verbose

# Scan specific SSH port for Fail2Ban
sudo is-it-safe example.com --ssh-port 2222
```

> **Note:** Some IDS/IPS detection features require root privileges for raw socket access.

## Development

Install development dependencies:

```bash
pip install ".[test]"
pytest
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
