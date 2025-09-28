# Ultimate Security Scanner - Complete Edition

🚀 **The most comprehensive security scanner available** - Now with both Command-Line and GUI interfaces!

A powerful, feature-rich security scanning tool that combines multiple scanning techniques into one unified platform. This scanner provides enterprise-grade security testing capabilities with an intuitive graphical interface.

## 🌟 Features

### 🔍 **Comprehensive Scanning Capabilities**
- **Network Scanning**: Advanced port scanning with Nmap integration
- **Web Application Security**: SQL injection, XSS, IDOR, SSRF, LFI, RCE testing
- **Database Security**: Authentication testing, default credential checks
- **SSL/TLS Analysis**: Certificate validation, vulnerability assessment
- **Container Security**: Docker image scanning, privilege analysis
- **IoT Device Detection**: Network device fingerprinting and vulnerability assessment
- **Machine Learning**: AI-powered vulnerability detection and behavioral analysis
- **Advanced Evasion**: Timing randomization, payload obfuscation, decoy traffic

### 🎛️ **Multiple Interface Options**
- **Command-Line Interface**: Full-featured CLI for automation and scripting
- **Graphical User Interface**: Intuitive desktop application for ease of use
- **API Integration**: VirusTotal, Shodan, and other security service integration

### 📊 **Advanced Reporting**
- **Executive Summaries**: High-level security overviews
- **Detailed Findings**: Comprehensive vulnerability reports
- **Risk Assessments**: Severity-based categorization
- **Export Functionality**: JSON, HTML, and other formats
- **Real-time Progress**: Live scan monitoring and updates

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command-Line Usage](#command-line-usage)
- [GUI Usage](#gui-usage)
- [Configuration](#configuration)
- [Scan Types Explained](#scan-types-explained)
- [Advanced Features](#advanced-features)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)

## 🚀 Installation

### Prerequisites

**Required Dependencies:**
```bash
pip install -r requirements.txt
```

**Core Requirements:**
- Python 3.7 or higher
- Nmap (system package)
- Network connectivity for external API calls

**Optional Dependencies (Enhanced Features):**
- **Wappalyzer**: Technology stack detection
- **PyTorch & Transformers**: Machine learning vulnerability detection
- **Docker SDK**: Container security scanning
- **Kubernetes SDK**: K8s security analysis
- **YARA**: Advanced pattern matching
- **VirusTotal API Key**: Malware analysis
- **Shodan API Key**: Internet device search

### Installation Steps

1. **Clone or download** the scanner files
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Install system packages**:
   ```bash
   # Ubuntu/Debian
   sudo apt install nmap

   # CentOS/RHEL
   sudo yum install nmap

   # macOS
   brew install nmap
   ```
4. **Test installation**:
   ```bash
   python scan.py --help
   python gui_launcher.py
   ```

## 🎯 Quick Start

### Command-Line Quick Start
```bash
# Quick scan of a website
python scan.py example.com -t quick

# Comprehensive scan with verbose output
python scan.py example.com -t full -v

# Ultra scan with all advanced features
python scan.py example.com -t ultra --aggressive
```

### GUI Quick Start
```bash
# Launch the graphical interface
python gui_launcher.py
```

## 💻 Command-Line Usage

### Basic Syntax
```bash
python scan.py <target> [options]
```

### Target Specification
- **Domain**: `example.com`
- **IP Address**: `192.168.1.1`
- **URL**: `https://example.com`
- **IP Range**: `192.168.1.0/24`

### Command-Line Options

#### Scan Type Selection
```bash
-t, --type SCAN_TYPE    # Scan type: quick, full, web, network, vulnerability, ultra
-o, --output FILE       # Save results to JSON file
--aggressive           # Enable aggressive scanning
--stealth              # Enable stealth mode
-v, --verbose          # Verbose output (-vv for more detail)
```

#### Examples
```bash
# Quick network scan
python scan.py 192.168.1.1 -t quick

# Full web application scan
python scan.py example.com -t full --aggressive -v

# Ultra scan with all features
python scan.py example.com -t ultra -o results.json

# Stealthy vulnerability scan
python scan.py example.com -t vulnerability --stealth
```

## 🖥️ GUI Usage

### Launching the GUI
```bash
python gui_launcher.py
```

### Step-by-Step Usage

#### 1. **Target Configuration**
- Enter target in the **Target** field
- Select appropriate **Scan Type** radio button
- Configure scan options (Aggressive, Stealth, Verbose)

#### 2. **Start Scanning**
- Click **"Start Scan"** button
- Monitor progress in real-time
- View detailed logs and status updates

#### 3. **Review Results**
Navigate through result tabs:
- **Executive Summary**: High-level overview
- **Vulnerabilities**: Security findings by severity
- **Open Ports**: Network services discovered
- **Web Findings**: Web application issues
- **Network**: Infrastructure analysis

#### 4. **Export Results**
- Click **"Export"** button
- Choose filename and location
- Results saved as JSON format

### GUI Interface Layout

```
┌─────────────────────────────────────────────────────────┐
│                    Menu Bar                             │
├─────────────────────────────────────────────────────────┤
│  Target: [__________________]  Scan Type: ● Quick ○ Full │
│  ○ Aggressive  ○ Stealth  ○ Verbose                    │
│  [Start Scan] [Stop Scan] [Clear] [Export]              │
├─────────────────────────────────────────────────────────┤
│  Scan Log:                                              │
│  [================================================]     │
│  Real-time scan progress and messages...                │
├─────────────────────────────────────────────────────────┤
│  Tabs: [Scan] [Results] [Configuration] [About]         │
│  ├─ Results Sub-tabs:                                   │
│  │  └─ [Executive Summary] [Vulnerabilities]            │
│  │     [Open Ports] [Web Findings] [Network]           │
└─────────────────────────────────────────────────────────┘
```

## ⚙️ Configuration

### API Keys Configuration
Edit the `CONFIG` section in `scan.py`:

```python
"api_keys": {
    "virustotal": "your_virustotal_api_key_here",
    "shodan": "your_shodan_api_key_here",
    "censys": "your_censys_api_key_here",
    "binaryedge": "your_binaryedge_api_key_here",
}
```

### Scan Settings
```python
"scan": {
    "default_ports": "21,22,80,443,3389,8080,8443",
    "full_ports": "1-65535",
    "scan_threads": 900,
    "timeout": 90,
    "max_pages": 500,
    "max_depth": 10,
}
```

### Advanced Options
```python
"advanced": {
    "rate_limit_delay": 0.05,
    "aggressive_scan": False,
    "stealth_mode": False,
}
```

## 📖 Scan Types Explained

### Quick Scan
- **Duration**: 1-3 minutes
- **Coverage**: Basic ports, essential services
- **Use Case**: Initial reconnaissance, fast assessment
- **Detection Risk**: Low

### Full Scan
- **Duration**: 5-15 minutes
- **Coverage**: All common ports, comprehensive service analysis
- **Use Case**: Thorough security assessment
- **Detection Risk**: Medium

### Web Scan
- **Duration**: 3-10 minutes
- **Coverage**: Web applications, content analysis, forms
- **Use Case**: Web application security testing
- **Detection Risk**: Medium

### Network Scan
- **Duration**: 5-20 minutes
- **Coverage**: Network infrastructure, OS detection
- **Use Case**: Network security analysis
- **Detection Risk**: High

### Vulnerability Scan
- **Duration**: 5-15 minutes
- **Coverage**: Targeted vulnerability testing
- **Use Case**: Specific vulnerability assessment
- **Detection Risk**: Medium-High

### Ultra Scan (Most Comprehensive)
- **Duration**: 10-30+ minutes
- **Coverage**: Everything + ML detection, containers, IoT
- **Use Case**: Maximum security coverage
- **Detection Risk**: High

## 🔧 Advanced Features

### Machine Learning Detection
- AI-powered vulnerability detection
- Behavioral analysis
- Anomaly detection
- Pattern recognition

### Container Security
- Docker image vulnerability scanning
- Privilege escalation detection
- Network configuration analysis
- Container escape detection

### IoT Security
- Device fingerprinting
- Protocol analysis
- Known vulnerability detection
- Weak configuration identification

### Advanced Evasion
- Timing randomization
- Payload obfuscation
- Decoy traffic generation
- Fragmented packet transmission

## 💡 Examples

### Example 1: Website Security Audit
```bash
# Command Line
python scan.py example.com -t full --aggressive -v -o website_audit.json

# GUI
# 1. Enter: example.com
# 2. Select: Full scan type
# 3. Enable: Aggressive mode
# 4. Click: Start Scan
# 5. Review: All result tabs
# 6. Export: Results
```

### Example 2: Network Infrastructure Scan
```bash
# Command Line
python scan.py 192.168.1.0/24 -t network --stealth -v

# GUI
# 1. Enter: 192.168.1.0/24
# 2. Select: Network scan type
# 3. Enable: Stealth mode
# 4. Click: Start Scan
# 5. Review: Open Ports and Network tabs
```

### Example 3: Web Application Testing
```bash
# Command Line
python scan.py https://testphp.vulnweb.com -t web --aggressive

# GUI
# 1. Enter: https://testphp.vulnweb.com
# 2. Select: Web scan type
# 3. Enable: Aggressive and Verbose
# 4. Click: Start Scan
# 5. Review: Web Findings tab
```

### Example 4: Comprehensive Security Audit
```bash
# Command Line
python scan.py company.com -t ultra --aggressive -v -o comprehensive_audit.json

# GUI
# 1. Enter: company.com
# 2. Select: Ultra scan type
# 3. Enable: Aggressive mode
# 4. Click: Start Scan
# 5. Review: All result tabs for complete analysis
```

## 🚨 Troubleshooting

### Common Issues

#### Import Errors
```bash
# Solution: Install missing dependencies
pip install -r requirements.txt

# Check if package exists
python -c "import requests; print('Requests OK')"
```

#### Nmap Not Found
```bash
# Ubuntu/Debian
sudo apt install nmap

# CentOS/RHEL
sudo yum install nmap

# macOS
brew install nmap
```

#### GUI Won't Launch
```bash
# Check tkinter installation
python -c "import tkinter; print('Tkinter OK')"

# Try alternative launch method
python -c "from scanner_gui import main; main()"
```

#### Scan Failures
- Verify target is reachable
- Check network connectivity
- Ensure proper permissions
- Review firewall settings

#### Performance Issues
- Reduce scan threads in configuration
- Use Quick scan for initial testing
- Disable verbose mode for faster execution
- Close other applications during scanning

### Debug Mode
```bash
# Enable debug logging
python scan.py target -t full -vv

# Check system resources
python scan.py --debug-info
```

## 🔒 Security Considerations

### ⚠️ Important Legal Notice
**This tool is for AUTHORIZED SECURITY TESTING ONLY**

- Only scan systems you own or have written permission to test
- Respect applicable laws and regulations
- Use responsibly and ethically
- Be aware of local network policies

### Best Practices
- **Start Small**: Begin with Quick scans
- **Test Safely**: Use test environments first
- **Document Everything**: Keep records of authorized testing
- **Rate Limiting**: Respect target system limits
- **Clean Up**: Remove any test data after scanning

### Risk Mitigation
- Use **Stealth mode** for production environments
- Avoid **Aggressive mode** on sensitive systems
- Monitor system impact during scans
- Have rollback plans for any changes

## 📞 Support

### Getting Help
1. Check the troubleshooting section
2. Review scan logs for error messages
3. Test with simple targets first
4. Verify all dependencies are installed

### Feature Requests
The scanner is actively developed with new features added regularly.

### Bug Reports
Please report issues with:
- Clear description of the problem
- Steps to reproduce
- System information
- Relevant log output

## 🔄 Updates and Development

### Checking for Updates
```bash
python scan.py --check-updates
```

### Development Version
For the latest features and improvements, check the development repository.

## 📄 License

This security scanner is provided for educational and authorized security testing purposes. Users are responsible for compliance with all applicable laws and regulations.

---

**Happy Scanning! 🔍**

*This scanner represents the culmination of advanced security research and development, providing enterprise-grade capabilities in an accessible package.*
