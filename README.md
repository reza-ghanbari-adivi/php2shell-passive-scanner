Here is the updated, comprehensive `README.md` file that reflects all the latest professional features of your tool, including multi-port scanning, port ranges, and report exporting.

You can update your `README.md` file with the following content:

```markdown
# PHP2Shell Passive Scanner (`php2shell-passive-scanner`)

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security Audit](https://img.shields.io/badge/security-audit-orange.svg)

A professional, safe, and non-destructive network/VLAN auditing tool designed to detect exposed PHP runtimes vulnerable to **CVE-2026-109618** and **CVE-2026-109619** (commonly referenced as **"PHP2Shell"**). 

This tool performs **passive version inspection** via HTTP headers (`Server` and `X-Powered-By`) across target subnets, CIDR blocks, and multiple custom ports without executing any payloads or causing service disruptions.

---

## 🔍 Vulnerability Overview

**CVE-2026-109618** and **CVE-2026-109619** are critical remote code execution (RCE) vulnerabilities residing in PHP core components (Zend Memory Manager and session upload progress handling). 

### Affected & Patched Versions
To secure systems against these vulnerabilities, administrators must upgrade to the following secure releases or later:
* **PHP 8.5** $\rightarrow$ Patched in **8.5.12**
* **PHP 8.4** $\rightarrow$ Patched in **8.4.27**
* **PHP 8.3** $\rightarrow$ Patched in **8.3.36**
* **PHP 8.2** $\rightarrow$ Patched in **8.2.35**
* *All versions prior to PHP 8.2 and specific unsupported branches are considered vulnerable.*

---

## 🚀 Key Features

* **Subnet & VLAN Support:** Seamlessly parse CIDR notation (e.g., `87.107.84.0/24`) to audit entire network blocks.
* **Multi-Port Scanning & Ranges:** Scan single ports, comma-separated port lists (e.g., `80,443,8080`), or port ranges (e.g., `80-443`).
* **Comprehensive Default Web Ports:** Automatically checks common web servers, hosting control panels (cPanel, CyberPanel), and alternative ports out of the box.
* **High Performance:** Multi-threaded architecture (`ThreadPoolExecutor`) for rapid IP x Port matrix scanning.
* **Non-Destructive Inspection:** Uses HTTP `HEAD` requests and safe header extraction to evaluate risk without triggering memory corruption or crashes.
* **Flexible Output Formats:** Export scan findings directly to structured **JSON** or **CSV** reports for penetration testing documentation.

---

## 📦 Installation

Clone the repository and install the package locally in editable mode:

```bash
git clone https://github.com/reza-ghanbari-adivi/php2shell-passive-scanner.git
cd php2shell-passive-scanner

# Optional: Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install package
pip install -e .
```

---

## 💻 Usage

Run the scanner directly from the command line by specifying a target CIDR block:

```bash
python3 vlan_scanner.py <CIDR_RANGE> [OPTIONS]
```

### Command-Line Arguments

| Argument / Flag | Description | Default |
| :--- | :--- | :--- |
| `cidr` | Target VLAN / Subnet CIDR (e.g., `87.107.135.0/24`) | *Required* |
| `-p`, `--ports` | Ports to scan (single, comma-separated, or ranges like `80-443`) | `80,443,8080,8443,8000,8888,3000,5000,2082,2083,2095,2096,8090,8880` |
| `-t`, `--threads` | Concurrency thread count | `100` |
| `--timeout` | Connection timeout in seconds | `2.0` |
| `-o`, `--output` | Save results to file (`report.json` or `report.csv`) | `None` |

### Examples

**1. Scan an entire subnet on default common web ports and save to JSON:**
```bash
python3 vlan_scanner.py 87.107.135.0/24 -o audit_report.json
```

**2. Scan a specific port list with custom threads:**
```bash
python3 vlan_scanner.py 87.107.84.0/24 -p 80,443,8080,8443 -t 150 -o results.csv
```

**3. Scan a port range (e.g., ports 80 through 443) on a single host (/32):**
```bash
python3 vlan_scanner.py 87.107.135.15/32 -p 80-443
```

---

## 📂 Project Structure

```text
php2shell-passive-scanner/
├── vlan_scanner.py        # Core scanning engine & CLI logic
├── pyproject.toml         # Python package configuration
├── README.md              # Project documentation
└── .gitignore             # Git ignore rules
```

---

## 🛡️ Legal Disclaimer

This tool is created strictly for **authorized security auditing, educational purposes, and defensive vulnerability management**. Do not use this tool against targets without explicit prior written authorization from the system owners. The author assumes no liability for any misuse or damage caused by this software.

---

