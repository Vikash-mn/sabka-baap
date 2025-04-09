# 🔍 Ultimate Network and Web Security Scanner

A comprehensive Python-based toolkit that performs network reconnaissance, vulnerability assessment, web technology detection, SSL analysis, content discovery, and much more — all packed into a single powerful script.

## 🚀 Features

- 🔎 Network Scanning (via Nmap)  
- 🌐 Web Technology Detection (via Wappalyzer)  
- 🔐 SSL/TLS Analysis (via SSLyze)  
- 🕷️ Deep Spidering (with Selenium for JS support)  
- ⚠️ Vulnerability Scanning (Nikto, Nuclei)  
- 🗂️ CMS Detection (WordPress etc.)  
- 🧠 Risk Assessment and Relationship Mapping  
- 📸 Screenshot Capture of Web Pages  
- 🧪 SQLi, XSS, CORS, CSRF, Clickjacking Tests  
- 🌍 GeoIP, WHOIS, DNS Enumeration  
- 📡 Wi-Fi Scanning with Scapy  

## 🧰 Requirements

- Python 3.8+  
- Google Chrome or Chromium (for Selenium)  
- Nmap, Nikto, and Nuclei installed and added to `$PATH`  

## 📦 Installation

```bash
pip install -r requirements.txt
```

Make sure Chrome is installed, and Chromedriver is accessible from your `PATH`.

## ⚙️ Usage

```bash
python scan.py [target] [options]
```

**Example:**

```bash
python scan.py https://example.com --web --full --hidden-ports -o result.json
```

## 🚠 Command-line Options

| Option           | Description                           |
|------------------|---------------------------------------|
| `target`         | Target domain/IP/URL                  |
| `--web`          | Perform web-based scanning            |
| `--network`      | Perform network-based scanning        |
| `--wifi`         | Perform Wi-Fi scan (requires interface) |
| `--full`         | Perform full/extended scan            |
| `--hidden-ports` | Include less common web ports         |
| `-p, --ports`    | Custom ports for scanning             |
| `-t, --threads`  | Number of threads to use              |
| `-o, --output`   | Save result to a JSON file            |
| `-v, --verbose`  | Verbose output                        |

## 📂 Output

All results are stored in structured JSON format and optionally include:

- Scan metadata  
- Open ports with service details  
- Vulnerabilities found (via Nuclei/Nikto)  
- Screenshots of target pages  
- Web spidered data and forms  
- SSL/TLS certificate details  
- And much more...

## 🔐 API Keys

Edit the `CONFIG` dictionary inside `scan.py` to insert your API keys for:

- VirusTotal  
- Shodan  
- AbuseIPDB  
- WhoisXML  
- MaxMind  

## ⚠️ Disclaimer

This tool is intended for educational and authorized security testing **only**. Unauthorized scanning of systems is **illegal**.

