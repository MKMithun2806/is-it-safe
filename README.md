# is-it-safe 🛡️

[![PyPI version](https://img.shields.io/pypi/v/is-it-safe.svg)](https://pypi.org/project/is-it-safe/)
[![Python versions](https://img.shields.io/pypi/pyversions/is-it-safe.svg)](https://pypi.org/project/is-it-safe/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Stealthy Security Layer Fingerprinting & Detection v5.0**

`is-it-safe` is a modern, high-performance security utility designed to map and identify protective layers surrounding a target without triggering aggressive defense mechanisms. It provides deep visibility into infrastructure security by fingerprinting WAFs, IDS/IPS, and automated blocking systems.

##  Key Features

*   🛡️ **WAF Fingerprinting:** Identifies 10+ major WAF vendors (Cloudflare, Akamai, AWS, Imperva, etc.) via signature-based and behavioral analysis.
*   🕵️ **Stealth-First Detection:** Implements adaptive jitter, randomized headers, and low-signal request patterns to bypass basic rate-limiters and heuristics.
*   🚦 **IDS/IPS Probing:** Uses low-level TCP signals and HTTP response anomalies to detect deep packet inspection and network-level interception.
*   🚫 **Fail2Ban Discovery:** Safely identifies SSH tarpits, "honey-pots," and active ban policies through non-destructive authentication probing.
*   🎨 **Modern Interface:** Built with `rich` for professional, structured terminal output and high-visibility results.
*   🤖 **Automation Ready:** Native JSON output mode for seamless integration into larger security pipelines.

##  Installation

### The Modern Way (Recommended)
Use [uv](https://github.com/astral-sh/uv) for the fastest experience:

```bash
# Run instantly without installing
uvx is-it-safe example.com

# Or install it
uv pip install is-it-safe
```

### The Traditional Way
```bash
pip install is-it-safe
```

### From Source
```bash
git clone https://github.com/your-username/is-it-safe.git
cd is-it-safe
pip install .
```

## 🛠 Usage

```bash
# Basic scan
is-it-safe example.com

# Verbose scan with stealth enabled
is-it-safe example.com --stealth --verbose

# Scan specific SSH port for Fail2Ban
sudo is-it-safe example.com --ssh-port 2222

# Output results as JSON
is-it-safe example.com --json > results.json
```

> [!IMPORTANT]
> Some IDS/IPS detection features require **root privileges** for raw socket access.

##  Publishing to PyPI

This project is configured for easy distribution. To publish your own version:

1. **Build the package:**
   ```bash
   uv build
   ```
2. **Publish to PyPI:**
   ```bash
   uv publish
   ```
   *Note: You will need a PyPI API token.*

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

