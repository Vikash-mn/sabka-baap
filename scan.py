import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.robotparser
from datetime import datetime
from functools import lru_cache
from tkinter import *
from tkinter import ttk, messagebox, filedialog, simpledialog
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import dns.resolver
import nmap
import paramiko
import requests
import scapy.all as scapy
import sslyze
from bs4 import BeautifulSoup
from cryptography import x509
from fake_useragent import UserAgent
from PIL import Image, ImageTk
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from wappalyzer import Wappalyzer, WebPage

# Global Configuration
CONFIG = {
    "virustotal_key": "81fcb279085331b577c95830aacb4baf90b1eb8dc16c890af5ecc1e36ec73398",
    "abuseipdb_key": "313eefef29f0a99a2e9218e2b7913e024e46ecb006f5e0f1322feac71b822e547f275663e68facba",
    "shodan_key": "Y5VLGOqBwOJvHX2oCJrNy5xZq4jerrmr4",
    "whoisxml_key": "44db1963e1e94b4fab95a5d88732c18bSXML_KEY",
    "maxmind_key": "",
    "theme": "dark",
    "default_ports": "21,22,80,443,3389,8080",
    "scan_threads": 100,
    "timeout": 5,
    "geoip_db_path": "GeoLite2-City.mmdb",
    'wordlists': {
        'dirs': '/usr/share/wordlists/dirb/common.txt',
        'subdomains': '/usr/share/wordlists/subdomains-top1million-5000.txt',
        'passwords': '/usr/share/wordlists/rockyou.txt',
    },
    'ports': {
        'default': '80,443,8080,8443,8888,4443,4444,10443,18080,28080',
        'hidden': '3000-4000,5000-6000,7000-8000,9000-10000',
        'full': '1-65535',
        'common_web': '81,591,2082,2087,2095,2096,3000,3306,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7002,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8530,8531,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,16080,18091,18092,20720,28017',
        'database': '1433,1434,1521,1830,3306,3351,5432,5984,6379,7199,7474,7473,7687,8000,8087,8091,8142,8182,8529,8629,8666,8765,8843,8888,8983,9000,9042,9060,9070,9080,9091,9092,9200,9300,9418,9999,11211,27017,27018,28015,50000',
    },
    'output_dir': 'scan_results',
    'screenshots_dir': 'screenshots',
    'max_pages': 100,
    'max_depth': 5,
    'max_threads': 15,
    'rate_limit_delay': 0.1,
}

class UltimateNetworkToolkit:
    """Main application class combining all network security tools"""
    
    def __init__(self, root=None, cli_mode=False):
        if not cli_mode:
            self.root = root
            self.root.title("Ultimate Network Security Toolkit v4.0")
            self.root.geometry("1280x900")
            self.setup_theme()
            self.create_widgets()
            self.create_menu()
            self.load_icons()
            self.setup_tabs()
            self.setup_status_bar()
            self.setup_network_monitor()
        else:
            self.cli_mode = True

    # ======================================
    # GUI Methods (from ipscan.py)
    # ======================================
    
    def setup_theme(self):
        self.style = ttk.Style()
        if CONFIG["theme"] == "dark":
            self.root.configure(bg='#2d2d2d')
            self.style.theme_use('clam')
            self.style.configure('.', background='#2d2d2d', foreground='white')
            self.style.map('TNotebook.Tab', background=[('selected', '#3d3d3d')])
            self.bg_color = '#2d2d2d'
            self.fg_color = 'white'
            self.entry_bg = '#3d3d3d'
        else:
            self.bg_color = 'white'
            self.fg_color = 'black'
            self.entry_bg = 'white'

    def create_widgets(self):
        # Header with logo
        header = Frame(self.root, bg=self.bg_color)
        header.pack(fill=X, pady=10)
        
        try:
            logo_img = Image.open("icons/logo.png").resize((150,40))
            self.logo = ImageTk.PhotoImage(logo_img)
            Label(header, image=self.logo, bg=self.bg_color).pack(side=LEFT, padx=10)
        except:
            Label(header, text="Ultimate Network Security Toolkit", font=("Helvetica", 16), 
                 bg=self.bg_color, fg=self.fg_color).pack(side=LEFT, padx=10)
        
        # Main input area
        input_frame = Frame(self.root, bg=self.bg_color)
        input_frame.pack(pady=15)
        
        Label(input_frame, text="Target IP/Domain/URL:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, padx=5)
        self.target_entry = Entry(input_frame, width=40, bg=self.entry_bg, fg=self.fg_color, 
                                insertbackground=self.fg_color)
        self.target_entry.grid(row=0, column=1, padx=5)
        self.target_entry.bind("<Return>", lambda e: self.analyze_target())
        
        Button(input_frame, text="Analyze", command=self.analyze_target, 
              bg='#4CAF50', fg='white').grid(row=0, column=2, padx=5)
        Button(input_frame, text="Quick Scan", command=self.quick_scan, 
              bg='#2196F3', fg='white').grid(row=0, column=3, padx=5)
        
        # Main notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)

    def create_menu(self):
        menubar = Menu(self.root)
        
        # File menu
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Report", command=self.generate_report)
        file_menu.add_command(label="Export Data", command=self.export_data)
        file_menu.add_command(label="Load Targets", command=self.load_targets)
        file_menu.add_separator()
        file_menu.add_command(label="Settings", command=self.open_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Speed Test", command=self.run_speed_test)
        tools_menu.add_command(label="Packet Loss Test", command=self.packet_loss_test)
        tools_menu.add_command(label="Port Scanner", command=self.focus_port_scanner)
        tools_menu.add_command(label="Network Sniffer", command=self.start_sniffer)
        tools_menu.add_command(label="Wi-Fi Analyzer", command=self.wifi_analyzer)
        tools_menu.add_command(label="Website Scanner", command=self.launch_web_scanner)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # View menu
        view_menu = Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dark Theme", command=lambda: self.change_theme("dark"))
        view_menu.add_command(label="Light Theme", command=lambda: self.change_theme("light"))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Help menu
        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="Check for Updates", command=self.check_updates)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)

    def setup_tabs(self):
        # Overview Tab
        self.overview_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.overview_tab, text="Overview")
        self.setup_overview_tab()
        
        # Geolocation Tab
        self.geo_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.geo_tab, text="Geolocation")
        self.setup_geolocation_tab()
        
        # Network Tab
        self.network_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.network_tab, text="Network")
        self.setup_network_tab()
        
        # Security Tab
        self.security_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.security_tab, text="Security")
        self.setup_security_tab()
        
        # DNS Tab
        self.dns_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.dns_tab, text="DNS Tools")
        self.setup_dns_tab()
        
        # Port Scan Tab
        self.ports_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.ports_tab, text="Port Scanner")
        self.setup_ports_tab()
        
        # Tools Tab
        self.tools_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.tools_tab, text="Network Tools")
        self.setup_tools_tab()
        
        # Vulnerability Scanner Tab
        self.vuln_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.vuln_tab, text="Vulnerability Scanner")
        self.setup_vuln_tab()
        
        # Website Scanner Tab (New)
        self.webscan_tab = Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.webscan_tab, text="Website Scanner")
        self.setup_webscan_tab()

    def setup_webscan_tab(self):
        """Setup the website scanner tab"""
        # Website scanner controls
        web_controls = Frame(self.webscan_tab, bg=self.bg_color)
        web_controls.pack(fill=X, padx=5, pady=5)
        
        Label(web_controls, text="Website URL:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, padx=5)
        self.web_target_entry = Entry(web_controls, width=40, bg=self.entry_bg, fg=self.fg_color, 
                                    insertbackground=self.fg_color)
        self.web_target_entry.grid(row=0, column=1, padx=5)
        
        self.web_scan_type = StringVar(value="quick")
        OptionMenu(web_controls, self.web_scan_type, "quick", "full", "hidden", "aggressive").grid(row=0, column=2, padx=5)
        
        Button(web_controls, text="Scan Website", command=self.run_web_scan, 
              bg='#FF5722', fg='white').grid(row=0, column=3, padx=5)
        
        # Website scan results
        self.webscan_text = Text(self.webscan_tab, wrap=WORD, bg=self.entry_bg, fg=self.fg_color, 
                               insertbackground=self.fg_color, font=("Consolas", 10))
        scroll = Scrollbar(self.webscan_tab, command=self.webscan_text.yview)
        self.webscan_text.configure(yscrollcommand=scroll.set)
        
        scroll.pack(side=RIGHT, fill=Y)
        self.webscan_text.pack(fill=BOTH, expand=True)

    def run_web_scan(self):
        """Run the website scanner"""
        url = self.web_target_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a website URL")
            return
            
        self.webscan_text.delete(1.0, END)
        self.append_text(self.webscan_text, f"Starting {self.web_scan_type.get()} scan on {url}...\n")
        self.root.update()
        
        try:
            # Create a scanner instance
            scanner = UltimateWebScanner(url)
            
            # Run the scan based on selected type
            scan_type = self.web_scan_type.get()
            if scan_type == "quick":
                results = scanner.run(full_scan=False, hidden_ports=False, aggressive=False)
            elif scan_type == "full":
                results = scanner.run(full_scan=True, hidden_ports=False, aggressive=False)
            elif scan_type == "hidden":
                results = scanner.run(full_scan=False, hidden_ports=True, aggressive=False)
            elif scan_type == "aggressive":
                results = scanner.run(full_scan=True, hidden_ports=True, aggressive=True)
            
            # Display results
            self.append_text(self.webscan_text, "\n=== Website Scan Results ===\n")
            self.append_text(self.webscan_text, json.dumps(results, indent=2))
            
            self.append_text(self.webscan_text, "\n\nWebsite scan completed\n")
        except Exception as e:
            self.append_text(self.webscan_text, f"Website scan failed: {str(e)}\n")

    # ======================================
    # Core Scanning Methods (combined from all scripts)
    # ======================================
    
    def analyze_target(self):
        """Analyze a target (IP, domain, or URL)"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
            
        try:
            self.clear_results()
            self.status.set(f"Analyzing {target}...")
            self.root.update()
            
            # Check if it's a URL (contains http:// or https://)
            if target.startswith(('http://', 'https://')):
                self.launch_web_scanner(target)
                return
            
            # Resolve domain to IP if needed
            if not self.is_valid_ip(target):
                try:
                    resolved_ip = socket.gethostbyname(target)
                    self.append_text(self.overview_text, f"Resolved {target} to {resolved_ip}\n")
                    target = resolved_ip
                except socket.gaierror:
                    messagebox.showerror("Error", "Could not resolve domain")
                    return
            
            ip = ipaddress.ip_address(target)
            
            # Update port scan target
            self.port_target_entry.delete(0, END)
            self.port_target_entry.insert(0, str(ip))
            self.vuln_target_entry.delete(0, END)
            self.vuln_target_entry.insert(0, str(ip))
            
            # Start analysis
            self.show_basic_info(ip)
            self.show_geolocation(ip)
            self.show_network_info(ip)
            self.run_security_checks(ip)
            
            # If target was a domain, use it for DNS lookups
            if not self.is_valid_ip(self.target_entry.get().strip()):
                self.dns_entry.delete(0, END)
                self.dns_entry.insert(0, self.target_entry.get().strip())
                self.perform_dns_lookup()
            
            self.status.set("Analysis completed successfully")
            messagebox.showinfo("Success", "Analysis completed successfully")
            
        except ValueError:
            messagebox.showerror("Error", "Invalid IP address format")
        except Exception as e:
            self.status.set(f"Analysis failed: {str(e)}")
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")

    def launch_web_scanner(self, url=None):
        """Launch the website scanner with the given URL"""
        if not url:
            url = self.target_entry.get().strip()
            if not url:
                messagebox.showerror("Error", "Please enter a website URL")
                return
        
        # Switch to the website scanner tab
        self.notebook.select(self.webscan_tab)
        
        # Populate the URL field
        self.web_target_entry.delete(0, END)
        self.web_target_entry.insert(0, url)
        
        # Start the scan
        self.run_web_scan()

    # ======================================
    # Web Scanner Class (from webscan.py)
    # ======================================
    
    class UltimateWebScanner:
        """Website scanner component"""
        
        def __init__(self, url: str):
            self.url = self.normalize_url(url)
            self.domain = urlparse(self.url).hostname
            self.base_url = f"{urlparse(self.url).scheme}://{urlparse(self.url).netloc}"
            self.results = {
                'metadata': {
                    'url': self.url,
                    'domain': self.domain,
                    'base_url': self.base_url,
                    'timestamp': datetime.utcnow().isoformat(),
                    'tool_version': '3.1'
                },
                'findings': {}
            }
            self.visited_urls: Set[str] = set()
            self.session = self._init_session()
            self.selenium_driver = self.init_selenium()
            
        @staticmethod
        def normalize_url(url: str) -> str:
            """Ensure URL has proper scheme and format"""
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'
            return url.rstrip('/')
        
        def _init_session(self) -> requests.Session:
            """Initialize requests session with random user agents and proper headers"""
            ua = UserAgent()
            session = requests.Session()
            session.headers.update({
                'User-Agent': ua.random,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0',
            })
            session.timeout = CONFIG['timeouts']['requests']
            session.verify = False  # Disable SSL verification for compatibility
            return session
        
        def init_selenium(self) -> webdriver.Chrome:
            """Initialize headless Chrome for JS-rendered content"""
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--window-size=1920,1080')
            options.add_argument(f'user-agent={UserAgent().random}')
            
            # Additional security and performance options
            options.add_argument('--disable-extensions')
            options.add_argument('--disable-popup-blocking')
            options.add_argument('--disable-notifications')
            options.add_argument('--ignore-certificate-errors')
            
            # Try to find Chrome binary in common locations
            chrome_paths = [
                '/usr/bin/google-chrome',
                '/usr/bin/chromium',
                '/usr/bin/chromium-browser',
                '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
            ]
            
            for path in chrome_paths:
                if os.path.exists(path):
                    options.binary_location = path
                    break
            
            try:
                return webdriver.Chrome(options=options)
            except Exception as e:
                print(f"[-] Selenium initialization failed: {str(e)}")
                print("[*] Falling back to requests-only mode")
                return None
        
        def run(self, full_scan: bool = False, hidden_ports: bool = False, aggressive: bool = False) -> Dict:
            """Execute exhaustive scan with parallel operations"""
            print(f"[*] Starting ULTIMATE scan of {self.url}")
            start_time = time.time()
            
            # Create output directories
            os.makedirs(CONFIG['output_dir'], exist_ok=True)
            os.makedirs(CONFIG['screenshots_dir'], exist_ok=True)
            
            # Prepare scan tasks
            scan_tasks = self._prepare_scan_tasks(full_scan, hidden_ports, aggressive)
            
            # Execute scans concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['max_threads']) as executor:
                futures = {name: executor.submit(task) for name, task in scan_tasks.items()}
                completed = concurrent.futures.wait(futures.values())
                
                # Store results
                self._process_scan_results(futures)
            
            # Post-processing
            self._post_processing()
            
            # Calculate execution time
            self.results['metadata']['execution_time'] = time.time() - start_time
            
            # Clean up
            if self.selenium_driver:
                self.selenium_driver.quit()
            
            return self.results
        
        def _prepare_scan_tasks(self, full_scan: bool, hidden_ports: bool, aggressive: bool) -> Dict:
            """Prepare all scan tasks to be executed"""
            port_config = (
                CONFIG['ports']['full'] if full_scan else
                f"{CONFIG['ports']['default']},{CONFIG['ports']['hidden']},{CONFIG['ports']['common_web']}"
                if hidden_ports else CONFIG['ports']['default']
            )
            
            return {
                # Network layer scans
                'ip_dns': lambda: self.get_ip_and_dns(),
                'ports': lambda: self.scan_ports(port_config),
                'hidden_services': lambda: self.detect_hidden_services(),
                'dns_enum': lambda: self.dns_enumeration(),
                'cloud_assets': lambda: self.find_cloud_assets(),
                'whois': lambda: self.get_whois_info(),
                
                # Web layer scans
                'headers': lambda: self.fetch_http_headers(),
                'tech': lambda: self.detect_web_technologies(),
                'ssl': lambda: self.get_ssl_info(),
                'cms': lambda: self.detect_cms(),
                'cookies': lambda: self.analyze_cookies(),
                'robots': lambda: self.check_robots_txt(),
                'sitemap': lambda: self.check_sitemap(),
                'dns_prefetch': lambda: self.check_dns_prefetch(),
                'cache_analysis': lambda: self.analyze_caching(),
                
                # Content analysis
                'spider': lambda: self.deep_spider(),
                'forms': lambda: self.extract_forms(),
                'comments': lambda: self.extract_comments_js(),
                'seo': lambda: self.analyze_seo(),
                'screenshot': lambda: self.take_screenshot(),
                'wordpress': lambda: self.scan_wordpress() if 'wordpress' in self.url.lower() else None,
                
                # Security checks
                'vulns': lambda: self.comprehensive_vuln_scan(),
                'cors': lambda: self.check_cors(),
                'headers_sec': lambda: self.check_security_headers(),
                'sensitive_files': lambda: self.find_sensitive_files(),
                'auth': lambda: self.check_auth_mechanisms(),
                'csrf': lambda: self.check_csrf(),
                'clickjacking': lambda: self.check_clickjacking(),
                'sql_injection': lambda: self.check_sql_injection(),
                'xss': lambda: self.check_xss(),
                'idor': lambda: self.check_idor(),
                
                # Performance
                'perf': lambda: self.analyze_performance(),
                
                # JavaScript analysis
                'js_analysis': lambda: self.analyze_javascript(),
                
                # API detection
                'api': lambda: self.detect_apis(),
            }
        
        def _process_scan_results(self, futures: Dict):
            """Process and organize all scan results"""
            self.results['findings'] = {
                'network': {
                    'ip_dns': futures['ip_dns'].result(),
                    'open_ports': futures['ports'].result(),
                    'hidden_services': futures['hidden_services'].result(),
                    'dns_enumeration': futures['dns_enum'].result(),
                    'cloud_assets': futures['cloud_assets'].result(),
                    'whois': futures['whois'].result(),
                },
                'web': {
                    'headers': futures['headers'].result(),
                    'technologies': futures['tech'].result(),
                    'ssl_tls': futures['ssl'].result(),
                    'cms': futures['cms'].result(),
                    'cookies': futures['cookies'].result(),
                    'robots_txt': futures['robots'].result(),
                    'sitemap': futures['sitemap'].result(),
                    'dns_prefetch': futures['dns_prefetch'].result(),
                    'caching': futures['cache_analysis'].result(),
                },
                'content': {
                    'spidered': futures['spider'].result(),
                    'forms': futures['forms'].result(),
                    'comments': futures['comments'].result(),
                    'seo': futures['seo'].result(),
                    'screenshot': f"{CONFIG['screenshots_dir']}/{self.domain}.png",
                    'wordpress': futures['wordpress'].result() if futures['wordpress'] else None,
                },
                'security': {
                    'vulnerabilities': futures['vulns'].result(),
                    'cors': futures['cors'].result(),
                    'security_headers': futures['headers_sec'].result(),
                    'sensitive_files': futures['sensitive_files'].result(),
                    'authentication': futures['auth'].result(),
                    'csrf': futures['csrf'].result(),
                    'clickjacking': futures['clickjacking'].result(),
                    'sql_injection': futures['sql_injection'].result(),
                    'xss': futures['xss'].result(),
                    'idor': futures['idor'].result(),
                },
                'performance': futures['perf'].result(),
                'javascript': futures['js_analysis'].result(),
                'api': futures['api'].result(),
            }
        
        def _post_processing(self):
            """Perform post-processing on scan results"""
            self.check_cloudflare()
            self.check_waf()
            self.generate_risk_assessment()
            self.calculate_hashes()
            self.analyze_relationships()
        
        def get_ip_and_dns(self) -> Dict:
            """Comprehensive IP and DNS reconnaissance"""
            result = {'ip': [], 'dns': {}, 'geoip': {}, 'cdn': None}
            
            try:
                # Basic resolution (IPv4 and IPv6)
                result['ip'].extend(socket.getaddrinfo(self.domain, None))
                
                # Advanced DNS records with caching
                resolver = dns.resolver.Resolver()
                resolver.lifetime = 10  # Set timeout for DNS queries
                
                for record in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'SPF', 'DKIM', 'DMARC']:
                    try:
                        answers = resolver.resolve(self.domain, record)
                        result['dns'][record] = [str(r) for r in answers]
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        continue
                
                # Check for common CDNs
                cdn_headers = ['server', 'via', 'x-cdn', 'x-cache', 'cf-ray']
                try:
                    response = self.session.get(self.url)
                    for header in cdn_headers:
                        if header in response.headers:
                            result['cdn'] = response.headers[header]
                            break
                except:
                    pass
                    
            except Exception as e:
                result['error'] = str(e)
                
            return result
        
        def scan_ports(self, ports: str) -> Dict:
            """Ultimate port scanning with service and vulnerability detection"""
            result = {}
            
            try:
                nm = nmap.PortScanner()
                scan_args = '-sV -T4 --script=banner,vulners,ssl-enum-ciphers,http-title,http-headers,http-enum,http-sitemap-generator'
                
                if not ports:
                    ports = CONFIG['ports']['default']
                
                print(f"[*] Scanning ports: {ports}")
                nm.scan(hosts=self.domain, ports=ports, arguments=scan_args)
                
                for host in nm.all_hosts():
                    result[host] = {}
                    for proto in nm[host].all_protocols():
                        result[host][proto] = {}
                        for port, data in nm[host][proto].items():
                            if data['state'] == 'open':
                                service = {
                                    'name': data.get('name', 'unknown'),
                                    'product': data.get('product', ''),
                                    'version': data.get('version', ''),
                                    'cpe': data.get('cpe', ''),
                                    'scripts': {},
                                    'vulnerabilities': []
                                }
                                
                                # Extract script results
                                if 'script' in data:
                                    for script, output in data['script'].items():
                                        service['scripts'][script] = output
                                        # Extract vulnerabilities from vulners script
                                        if script == 'vulners':
                                            vulns = []
                                            for line in output.split('\n'):
                                                if 'CVE-' in line:
                                                    vulns.append(line.strip())
                                            service['vulnerabilities'] = vulns
                                
                                result[host][proto][port] = service
                
                # Perform deeper HTTP analysis on web ports
                self.analyze_web_ports(result)
                
            except Exception as e:
                result['error'] = str(e)
                
            return result
        
        def detect_hidden_services(self) -> Dict:
            """Deep detection for hidden/less-common web services"""
            result = {}
            
            try:
                # Combine all potential web ports
                web_ports = list(set(
                    [int(p) for p in CONFIG['ports']['common_web'].split(',')] +
                    [int(p) for p in CONFIG['ports']['default'].split(',')] +
                    [int(p) for p in CONFIG['ports']['hidden'].split(',') if '-' not in p]
                ))
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    futures = {port: executor.submit(self.check_port_service, port) for port in web_ports}
                    for port, future in futures.items():
                        try:
                            service_info = future.result()
                            if service_info:
                                result[port] = service_info
                        except:
                            continue
                
                # Special checks
                self.check_websockets(result)
                self.check_graphql(result)
                self.check_grpc(result)
                
            except Exception as e:
                result['error'] = str(e)
                
            return result
        
        def check_port_service(self, port: int) -> Optional[Dict]:
            """Check a single port for web services"""
            try:
                # Try HTTP
                http_url = f"http://{self.domain}:{port}"
                response = requests.get(http_url, timeout=5, verify=False, allow_redirects=True)
                if response.status_code < 500:  # Accept even 4xx as valid responses
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title = soup.title.string if soup.title else None
                    
                    service_info = {
                        'protocol': 'http',
                        'status': response.status_code,
                        'title': title,
                        'headers': dict(response.headers),
                        'content_type': response.headers.get('Content-Type', ''),
                        'body_hash': hashlib.sha256(response.content).hexdigest(),
                        'body_length': len(response.content),
                    }
                    
                    # Check for API indicators
                    if 'application/json' in response.headers.get('Content-Type', ''):
                        service_info['api'] = True
                        try:
                            service_info['json_sample'] = response.json()
                        except:
                            pass
                    
                    return service_info
                
                # Try HTTPS if HTTP didn't work
                https_url = f"https://{self.domain}:{port}"
                response = requests.get(https_url, timeout=5, verify=False, allow_redirects=True)
                if response.status_code < 500:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title = soup.title.string if soup.title else None
                    
                    service_info = {
                        'protocol': 'https',
                        'status': response.status_code,
                        'title': title,
                        'headers': dict(response.headers),
                        'content_type': response.headers.get('Content-Type', ''),
                        'body_hash': hashlib.sha256(response.content).hexdigest(),
                        'body_length': len(response.content),
                    }
                    
                    # Get SSL info for HTTPS services
                    try:
                        cert = ssl.get_server_certificate((self.domain, port))
                        x509_cert = x509.load_pem_x509_certificate(cert.encode())
                        service_info['ssl'] = {
                            'issuer': x509_cert.issuer.rfc4514_string(),
                            'subject': x509_cert.subject.rfc4514_string(),
                            'not_valid_before': x509_cert.not_valid_before.isoformat(),
                            'not_valid_after': x509_cert.not_valid_after.isoformat(),
                            'serial_number': str(x509_cert.serial_number),
                        }
                    except:
                        pass
                    
                    return service_info
                
            except:
                return None
        
        def fetch_http_headers(self) -> Dict:
            """Fetch headers with advanced analysis"""
            result = {}
            
            try:
                response = self.session.get(self.url, allow_redirects=True)
                result = {
                    'status_code': response.status_code,
                    'final_url': response.url,
                    'redirect_chain': [{'url': r.url, 'status': r.status_code} for r in response.history],
                    'headers': dict(response.headers),
                    'cookies': dict(response.cookies),
                    'content_type': response.headers.get('Content-Type', ''),
                    'content_length': len(response.content),
                    'response_time': response.elapsed.total_seconds(),
                    'server': response.headers.get('Server', ''),
                    'x_powered_by': response.headers.get('X-Powered-By', ''),
                    'content_security_policy': response.headers.get('Content-Security-Policy', ''),
                    'strict_transport_security': response.headers.get('Strict-Transport-Security', ''),
                }
                
                # Check for HTTP/2
                result['http_version'] = 'HTTP/2' if response.raw.version == 20 else 'HTTP/1.1'
                
                # Check for security headers
                security_headers = [
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'X-XSS-Protection',
                    'Referrer-Policy',
                    'Feature-Policy',
                    'Permissions-Policy'
                ]
                result['security_headers'] = {
                    h: response.headers.get(h, 'MISSING') for h in security_headers
                }
                
            except Exception as e:
                result['error'] = str(e)
                
            return result
        
        @lru_cache(maxsize=128)
        def detect_web_technologies(self) -> Dict:
            """Enhanced technology detection with version fingerprinting and caching"""
            result = {}
            
            try:
                wappalyzer = Wappalyzer.latest()
                webpage = WebPage.new_from_url(self.url)
                technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
                
                # Enhanced version detection
                for tech, data in technologies.items():
                    if 'versions' in data and data['versions']:
                        data['latest_version'] = max(data['versions'])
                        data['version_count'] = len(data['versions'])
                    else:
                        # Try to extract version from headers or HTML
                        version = self.extract_version_from_headers(tech)
                        if version:
                            data['versions'] = [version]
                            data['latest_version'] = version
                            data['version_count'] = 1
                
                result = technologies
            except Exception as e:
                result['error'] = str(e)
                
            return result
        
        def get_ssl_info(self) -> Dict:
            """Comprehensive SSL/TLS assessment with SSLyze"""
            result = {}
            
            try:
                # Basic SSL info
                hostname = self.domain
                context = ssl.create_default_context()
                
                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        
                        # Certificate info
                        result['certificate'] = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'validity': {
                                'not_before': cert['notBefore'],
                                'not_after': cert['notAfter'],
                                'expires_in_days': (ssl.cert_time_to_seconds(cert['notAfter']) - time.time()) / 86400,
                            },
                            'serial': cert.get('serialNumber', ''),
                            'version': cert.get('version', ''),
                            'extensions': cert.get('extensions', []),
                        }
                        
                        # Cipher info
                        result['cipher'] = {
                            'name': cipher[0],
                            'version': cipher[1],
                            'bits': cipher[2],
                        }
                
                # Advanced SSLyze scan
                try:
                    scanner = sslyze.Scanner()
                    command = sslyze.ScanCommand(
                        hostname=hostname,
                        scan_commands={
                            'ssl_2_0_cipher_suites',
                            'ssl_3_0_cipher_suites',
                            'tls_1_0_cipher_suites',
                            'tls_1_1_cipher_suites',
                            'tls_1_2_cipher_suites',
                            'tls_1_3_cipher_suites',
                            'heartbleed',
                            'openssl_ccs_injection',
                            'reneg',
                            'robot',
                            'session_resumption',
                            'compression',
                            'certificate_info',
                            'http_headers',
                        },
                    )
                    scan_result = scanner.run_scan_command(command)
                    result['sslyze'] = scan_result.as_json()
                except:
                    pass
                
            except Exception as e:
                result['error'] = str(e)
                
            return result
        
        def deep_spider(self) -> Dict:
            """Advanced spidering with Selenium for JS-rendered content"""
            result = {
                'pages': [],
                'links': [],
                'external_links': [],
                'resources': [],
                'forms': [],
                'statistics': {
                    'total_pages': 0,
                    'internal_links': 0,
                    'external_links': 0,
                    'forms_found': 0,
                }
            }
            
            if not self.selenium_driver:
                result['error'] = 'Selenium not available'
                return result
            
            try:
                self.selenium_driver.get(self.url)
                time.sleep(3)  # Wait for JS to load
                
                # Get all links
                links = self.selenium_driver.find_elements(By.TAG_NAME, 'a')
                for link in links:
                    try:
                        href = link.get_attribute('href')
                        if href:
                            if self.domain in href:
                                result['links'].append(href)
                                result['statistics']['internal_links'] += 1
                            else:
                                result['external_links'].append(href)
                                result['statistics']['external_links'] += 1
                    except:
                        continue
                
                # Get all resources
                for tag in ['img', 'script', 'link', 'iframe']:
                    elements = self.selenium_driver.find_elements(By.TAG_NAME, tag)
                    for el in elements:
                        try:
                            src = el.get_attribute('src') or el.get_attribute('href')
                            if src:
                                result['resources'].append({
                                    'type': tag,
                                    'url': src,
                                    'external': self.domain not in src
                                })
                        except:
                            continue
                
                # Get current page info
                current_page = {
                    'url': self.selenium_driver.current_url,
                    'title': self.selenium_driver.title,
                    'source': self.selenium_driver.page_source[:1000] + '...' if len(self.selenium_driver.page_source) > 1000 else self.selenium_driver.page_source,
                    'screenshot': f"{CONFIG['screenshots_dir']}/{self.domain}_home.png",
                }
                self.selenium_driver.save_screenshot(current_page['screenshot'])
                result['pages'].append(current_page)
                
                # Limited recursive spidering
                self.recursive_spider(self.url, result, depth=1)
                
                result['statistics']['total_pages'] = len(result['pages'])
                
            except Exception as e:
                result['error'] = str(e)
                
            return result
        
        def recursive_spider(self, url: str, result: Dict, depth: int):
            """Recursively spider the website up to a certain depth"""
            if depth > CONFIG['max_depth'] or len(result['pages']) >= CONFIG['max_pages']:
                return
            
            try:
                self.selenium_driver.get(url)
                time.sleep(2)  # Wait for page to load
                
                # Get new links on this page
                links = self.selenium_driver.find_elements(By.TAG_NAME, 'a')
                new_links = []
                
                for link in links:
                    try:
                        href = link.get_attribute('href')
                        if href and href not in self.visited_urls and self.domain in href:
                            new_links.append(href)
                            self.visited_urls.add(href)
                    except:
                        continue
                
                # Process new links
                for link in new_links[:10]:  # Limit to 10 links per page to avoid explosion
                    try:
                        self.selenium_driver.get(link)
                        time.sleep(1)
                        
                        page_info = {
                            'url': self.selenium_driver.current_url,
                            'title': self.selenium_driver.title,
                            'source': self.selenium_driver.page_source[:500] + '...',
                            'screenshot': f"{CONFIG['screenshots_dir']}/{hashlib.md5(link.encode()).hexdigest()}.png",
                        }
                        
                        self.selenium_driver.save_screenshot(page_info['screenshot'])
                        result['pages'].append(page_info)
                        
                        # Recurse
                        self.recursive_spider(link, result, depth + 1)
                    except:
                        continue
                        
            except Exception as e:
                print(f"[-] Error during spidering: {str(e)}")
        
        def comprehensive_vuln_scan(self) -> Dict:
            """Run multiple vulnerability scanners"""
            result = {
                'nikto': {},
                'nuclei': {},
                'zap': {},
                'manual_checks': {},
            }
            
            try:
                # Nikto scan
                nikto_result = self.run_subprocess([
                    'nikto', '-h', self.url, 
                    '-Format', 'json',
                    '-Tuning', 'x4567890abc'
                ])
                
                if nikto_result and not nikto_result.startswith('Error'):
                    result['nikto'] = json.loads(nikto_result)
                else:
                    result['nikto']['error'] = nikto_result
                    
                # Nuclei scan
                nuclei_result = self.run_subprocess([
                    'nuclei', '-u', self.url, 
                    '-json',
                    '-severity', 'low,medium,high,critical',
                    '-templates', '/usr/local/nuclei-templates'
                ])
                
                if nuclei_result and not nuclei_result.startswith('Error'):
                    result['nuclei'] = [json.loads(line) for line in nuclei_result.splitlines() if line.strip()]
                else:
                    result['nuclei']['error'] = nuclei_result
                    
                # Manual checks
                result['manual_checks'] = {
                    'admin_interfaces': self.check_admin_interfaces(),
                    'debug_endpoints': self.check_debug_endpoints(),
                    'exposed_database_interfaces': self.check_database_interfaces(),
                }
                
            except Exception as e:
                result['error'] = str(e)
                
            return result
        
        def check_admin_interfaces(self) -> List[str]:
            """Check for common admin interfaces"""
            admin_paths = [
                '/admin', '/wp-admin', '/administrator', '/manager', 
                '/cpanel', '/whm', '/webadmin', '/adminpanel',
                '/backend', '/console', '/controlpanel'
            ]
            
            found = []
            for path in admin_paths:
                try:
                    url = urljoin(self.base_url, path)
                    response = self.session.get(url, timeout=5)
                    if response.status_code < 400:  # 2xx or 3xx
                        found.append({
                            'url': url,
                            'status': response.status_code,
                            'title': BeautifulSoup(response.text, 'html.parser').title.string if response.text else None
                        })
                except:
                    continue
                    
            return found
        
        @staticmethod
        def run_subprocess(command: List[str]) -> str:
            """Execute subprocess command with error handling"""
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=CONFIG['timeouts']['subprocess']
                )
                return result.stdout if result.returncode == 0 else result.stderr
            except Exception as e:
                return f"Error: {str(e)}"
        
        def analyze_relationships(self):
            """Analyze relationships between different findings"""
            tech = self.results['findings']['web']['technologies']
            vulns = self.results['findings']['security']['vulnerabilities']
            
            if isinstance(tech, dict) and isinstance(vulns, dict):
                outdated = []
                for name, data in tech.items():
                    if 'latest_version' in data and 'versions' in data:
                        current = data['versions'][0]
                        latest = data['latest_version']
                        if current != latest:
                            outdated.append({
                                'technology': name,
                                'current': current,
                                'latest': latest,
                                'vulnerabilities': [
                                    v for v in vulns.get('nuclei', [])
                                    if name.lower() in v.get('templateID', '').lower()
                                ]
                            })
                
                if outdated:
                    self.results['findings']['security']['outdated_technologies'] = outdated

    # ======================================
    # CLI Interface (from scan.py)
    # ======================================
    
    def cli_main(self):
        """Command line interface for the toolkit"""
        parser = argparse.ArgumentParser(
            description="Ultimate Network Security Toolkit",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        
        # Common options
        parser.add_argument('target', help="Target to scan (IP, domain, or URL)")
        parser.add_argument('-o', '--output', help="Output file for results")
        parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
        
        # Scan type options
        scan_group = parser.add_argument_group('Scan Types')
        scan_group.add_argument('--network', action='store_true', help="Perform network scan")
        scan_group.add_argument('--web', action='store_true', help="Perform website scan")
        scan_group.add_argument('--wifi', action='store_true', help="Perform Wi-Fi scan")
        
        # Network scan options
        net_group = parser.add_argument_group('Network Scan Options')
        net_group.add_argument('-p', '--ports', help="Ports to scan (e.g. '80,443' or '1-1000')")
        net_group.add_argument('-t', '--threads', type=int, default=CONFIG['scan_threads'], 
                             help="Number of threads to use")
        
        # Web scan options
        web_group = parser.add_argument_group('Website Scan Options')
        web_group.add_argument('--full', action='store_true', help="Perform full website scan")
        web_group.add_argument('--hidden-ports', action='store_true', help="Scan for hidden web ports")
        web_group.add_argument('--aggressive', action='store_true', help="Aggressive scanning mode")
        
        # Wi-Fi scan options
        wifi_group = parser.add_argument_group('Wi-Fi Scan Options')
        wifi_group.add_argument('-i', '--interface', help="Network interface to use")
        wifi_group.add_argument('-c', '--channel', type=int, help="Specific channel to scan")
        wifi_group.add_argument('--timeout', type=int, default=30, help="Scan duration in seconds")
        
        args = parser.parse_args()
        
        # Update config based on arguments
        CONFIG['scan_threads'] = args.threads
        
        print(f"[*] Starting scan of {args.target}")
        
        try:
            results = {}
            
            # Determine scan type if not specified
            if not any([args.network, args.web, args.wifi]):
                if args.target.startswith(('http://', 'https://')):
                    args.web = True
                else:
                    args.network = True
            
            # Run the appropriate scans
            if args.network:
                print("[*] Running network scan...")
                results['network'] = self.cli_network_scan(args.target, args.ports)
            
            if args.web:
                print("[*] Running website scan...")
                scanner = self.UltimateWebScanner(args.target)
                results['web'] = scanner.run(
                    full_scan=args.full,
                    hidden_ports=args.hidden_ports,
                    aggressive=args.aggressive
                )
            
            if args.wifi:
                print("[*] Running Wi-Fi scan...")
                results['wifi'] = self.cli_wifi_scan(args)
            
            # Output results
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"[+] Results saved to {args.output}")
            else:
                print(json.dumps(results, indent=2))
            
            print("[+] Scan completed successfully")
            
        except Exception as e:
            print(f"[-] Error during scan: {str(e)}")
            sys.exit(1)
    
    def cli_network_scan(self, target, ports=None):
        """Perform network scan from CLI"""
        if not ports:
            ports = CONFIG['default_ports']
        
        try:
            # Resolve domain to IP if needed
            if not self.is_valid_ip(target):
                try:
                    target = socket.gethostbyname(target)
                except socket.gaierror:
                    print("[-] Could not resolve domain")
                    return None
            
            # Create nmap scanner
            nm = nmap.PortScanner()
            scan_args = '-sV -T4'
            
            print(f"[*] Scanning ports: {ports}")
            nm.scan(hosts=target, ports=ports, arguments=scan_args)
            
            result = {}
            for host in nm.all_hosts():
                result[host] = {}
                for proto in nm[host].all_protocols():
                    result[host][proto] = {}
                    for port, data in nm[host][proto].items():
                        if data['state'] == 'open':
                            service = {
                                'name': data.get('name', 'unknown'),
                                'product': data.get('product', ''),
                                'version': data.get('version', ''),
                                'cpe': data.get('cpe', ''),
                            }
                            result[host][proto][port] = service
            
            return result
            
        except Exception as e:
            return {'error': str(e)}
    
    def cli_wifi_scan(self, args):
        """Perform Wi-Fi scan from CLI"""
        try:
            # Windows-specific setup
            if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
                print("ERROR: This script requires Administrator privileges!")
                time.sleep(2)
                sys.exit(1)
            
            # Interface detection
            interface = self.get_wifi_interface(args.interface)
            if not interface:
                return {'error': 'No wireless interface found'}
            
            print(f"\n[*] Starting scan on {interface}")
            
            # Channel setup
            if args.channel:
                self.channel_operations(interface, args)
            else:
                hopper = threading.Thread(target=self.channel_operations, args=(interface, args))
                hopper.daemon = True
                hopper.start()
            
            # Packet capture
            networks = {}
            try:
                scapy.sniff(iface=interface,
                           prn=lambda pkt: self.process_wifi_packet(pkt, args, networks),
                           timeout=args.timeout,
                           store=0)
            except Exception as e:
                return {'error': f"Capture error: {str(e)}"}
            
            return {'networks': networks}
            
        except Exception as e:
            return {'error': str(e)}
    
    def process_wifi_packet(self, pkt, args, networks):
        """Process Wi-Fi packets for network discovery"""
        try:
            if pkt.haslayer(scapy.Dot11):
                # Beacon frames (network discovery)
                if pkt.type == 0 and pkt.subtype == 8:
                    bssid = pkt.addr2
                    ssid = pkt[scapy.Dot11Elt][0].info.decode(errors='ignore') or "<hidden>"
                    
                    try:
                        channel = int(ord(pkt[scapy.Dot11Elt][2].info))
                    except (IndexError, TypeError):
                        channel = "N/A"
                    
                    dbm_signal = pkt[scapy.RadioTap].dBm_AntSignal if pkt.haslayer(scapy.RadioTap) else None
                    
                    encryption = "Open"
                    for elt in pkt[scapy.Dot11Elt]:
                        if elt.ID == 48:  # RSN Information Element
                            encryption = "WPA2"
                            break
                        elif elt.ID == 221 and b'WPA' in elt.info:
                            encryption = "WPA"
                            break
                    
                    networks[bssid] = {
                        'ssid': ssid,
                        'channel': channel,
                        'signal': dbm_signal,
                        'encryption': encryption,
                        'last_seen': time.time()
                    }
                    
                    if args.verbose:
                        print(f"Found: {ssid} ({bssid}) | Ch{channel} | {dbm_signal}dBm | {encryption}")
                        
        except Exception as e:
            if args.verbose:
                print(f"Packet error: {str(e)}")

    # ======================================
    # Helper Methods (from all scripts)
    # ======================================
    
    def is_valid_ip(self, address):
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    def append_text(self, widget, text):
        widget.config(state=NORMAL)
        widget.insert(END, text)
        widget.config(state=DISABLED)
        widget.see(END)
    
    def clear_results(self):
        for widget in [self.overview_text, self.geo_text, self.network_text, 
                      self.security_text, self.dns_text, self.ports_text, 
                      self.vuln_text, self.webscan_text]:
            if widget:
                widget.config(state=NORMAL)
                widget.delete(1.0, END)
                widget.config(state=DISABLED)
        
        if self.ping_results:
            self.ping_results.delete(1.0, END)
        if self.trace_results:
            self.trace_results.delete(1.0, END)
        if self.map_label:
            self.map_label.config(text="Map will be generated here")
            self.map_label.unbind("<Button-1>")

if __name__ == "__main__":
    # Check if running in CLI mode
    if len(sys.argv) > 1:
        toolkit = UltimateNetworkToolkit(cli_mode=True)
        toolkit.cli_main()
    else:
        root = Tk()
        app = UltimateNetworkToolkit(root)
        root.mainloop()