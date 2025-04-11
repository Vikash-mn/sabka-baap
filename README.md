
# Advanced Network Security Scanner

![Security Scanner](https://img.shields.io/badge/Type-Penetration%20Testing%20Tool-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![License](https://img.shields.io/badge/License-MIT-orange)

A comprehensive network security scanner with advanced features for penetration testing and vulnerability assessment. Combines multiple scanning techniques into a single powerful tool.

---

## Features

### Scan Types
- **Quick Scan**: Basic checks (DNS, headers, open ports)
- **Full Scan**: Comprehensive scan (network + web + vulnerabilities)
- **Web Application Scan**: Focused web application testing
- **Network Scan**: Infrastructure and port scanning
- **Vulnerability Assessment**: Deep vulnerability scanning

### Capabilities
- Port scanning with service detection  
- Web spidering and technology fingerprinting  
- Vulnerability scanning (SQLi, XSS, RCE, etc.)  
- Security header analysis  
- SSL/TLS configuration checks  
- DNS reconnaissance  
- Cloud provider detection  
- WAF/CDN identification  
- API endpoint discovery  
- Authentication testing  
- Wi-Fi network scanning (requires monitor mode)  

---

## Installation

### Prerequisites
- Python 3.8+
- Linux system (recommended)
- Root/sudo privileges for some scans

### Install Dependencies
```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3-pip nmap nikto chromium-chromedriver tor

# Install Python packages
pip3 install -r requirements.txt
```

---

## Basic Usage
```bash
python3 scan.py [TARGET] [OPTIONS]
```

### Target Specification
`TARGET` can be:
- IP address (`192.168.1.1`)
- Domain name (`example.com`)
- URL (`https://example.com`)

---

## Common Scan Examples

### Basic Scans
```bash
# Quick basic scan
python3 scan.py example.com -t quick

# Comprehensive scan (default)
python3 scan.py example.com -t full

# Web application focused scan
python3 scan.py https://example.com -t web
```

### Network Scans
```bash
# Network infrastructure scan
python3 scan.py 192.168.1.1 -t network

# Stealthy network scan
sudo python3 scan.py 192.168.1.1 -t network --stealth

# Full port scan (1-65535)
python3 scan.py 192.168.1.1 --full-ports
```

### Vulnerability Scans
```bash
# Deep vulnerability assessment
python3 scan.py example.com -t vulnerability

# Test for specific vulnerabilities
python3 scan.py https://example.com --sqli --xss --lfi
```

### Web Application Scans
```bash
# Full web scan with all vulnerability tests
python3 scan.py https://example.com -t web --aggressive

# Directory bruteforcing
python3 scan.py https://example.com --dirs

# Subdomain enumeration
python3 scan.py example.com --subdomains
```

### Wi-Fi Scans (requires root)
```bash
# Scan for nearby Wi-Fi networks
sudo python3 scan.py --wifi-scan

# Capture WPA handshake
sudo python3 scan.py --wifi-capture TARGET_SSID
```

---

## Output Options
```bash
# Save results to JSON
python3 scan.py example.com -o results.json

# Generate HTML report
python3 scan.py example.com --html-report

# Verbosity levels
python3 scan.py example.com -v      # Verbose
python3 scan.py example.com -vv     # Very verbose
python3 scan.py example.com -vvv    # Debug
```

---

## Configuration

The scanner is configured via the `CONFIG` dictionary in the script. Key settings include:
- API keys (VirusTotal, Shodan, etc.)
- Scan parameters (ports, threads, timeouts)
- Paths to wordlists and tools
- Advanced options (stealth mode, rate limiting)

---

## Output Structure

Results include:
- Metadata (scan time, version)
- Target information
- Network scan results
- Web application findings
- Vulnerability data
- Risk assessment
- Executive summary

---

## Limitations
- Some features require root privileges
- Aggressive scans may trigger security systems
- Browser-based scans require Chrome/Chromium
- API services require valid keys
