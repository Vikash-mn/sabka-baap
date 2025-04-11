#!/usr/bin/env python3
# Ultimate Linux Network Security Scanner - Power Edition
from time import sleep
import logging
from typing import Pattern
import argparse
import aiohttp
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
from datetime import datetime
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
import ipwhois
from typing import Dict
import vt
import dns.resolver
import nmap
import requests
import scapy.all as scapy
import sslyze
from bs4 import BeautifulSoup
from cryptography import x509
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from wappalyzer import Wappalyzer, WebPage


COMMON_CREDS = {
        'mysql': [
            ('root', ''),
            ('root', 'root'),
            ('admin', 'admin'),
            ('mysql', 'mysql'),
            ('user', 'password')
        ],
        'postgresql': [
            ('postgres', 'postgres'),
            ('postgres', ''),
            ('admin', 'admin'),
            ('admin', 'password'),
            ('user', 'postgres')
        ],
        'mongodb': [
            ('admin', ''),
            ('admin', 'admin'),
            ('user', '123456'),
            ('root', 'root')
        ],
        'oracle': [
            ('system', 'manager'),
            ('sys', 'change_on_install'),
            ('scott', 'tiger')
        ]
    }
    
    # Connection timeouts in seconds
CONNECT_TIMEOUT = 3
RETRY_DELAY = 1  # seconds between retries
MAX_RETRIES = 2

# Enhanced Configuration
CONFIG = {
    "api_keys": {
        "virustotal": "81fcb279085331b577c95830aacb4baf90b1eb8dc16c890af5ecc1e36ec73398",
        "shodan": "Y5VLGOqBwOJvHX2oCJrNy5xZq4jerrmr4",
        "censys": None,  # Add your Censys API key
        "binaryedge": None,  # Add your BinaryEdge API key
    },
    "scan": {
        "default_ports": "21,22,80,443,3389,8080,8443",
        "full_ports": "1-65535",
        "web_ports": "80,443,8080,8443,8888,4443,4444,10443",
        "hidden_ports": "3000-4000,5000-6000,7000-8000,9000-10000",
        "database_ports": "1433,1434,1521,1830,3306,3351,5432,5984,6379,7199,7474,7473,7687",
        "scan_threads": 900,  # Increased thread count
        "timeout": 90,  # Increased timeout
        "max_pages": 500,
        "max_depth": 10,
        "max_threads": 50,
    },
    "paths": {
        "output_dir": "/var/log/security_scans",
        "screenshots_dir": "/var/log/security_scans/screenshots",
        "wordlists": {
            'dirs': '/usr/share/wordlists/dirb/common.txt',
            'subdomains': '/usr/share/wordlists/subdomains-top1million-5000.txt',
            'passwords': '/usr/share/wordlists/rockyou.txt',
            'api_endpoints': '/usr/share/wordlists/api_wordlist.txt',
        },
        "tools": {
            'nmap': '/usr/bin/nmap',
            'nikto': '/usr/bin/nikto',
            'nuclei': '/usr/bin/nuclei',
            'gobuster': '/usr/bin/gobuster',
            'ffuf': '/usr/bin/ffuf',
            'sqlmap': '/usr/bin/sqlmap',
        }
    },
    "advanced": {
        "tor_proxy": "socks5://127.0.0.1:9050",
        "user_agents": "/usr/share/wordlists/user-agents.txt",
        "rate_limit_delay": 0.05,
        "aggressive_scan": False,
        "stealth_mode": False,
    }
}

# Constants
DEFAULT_CHANNELS = list(range(1, 14)) + [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
WIFI_SCAN_DURATION = 60  # seconds
MAX_CONCURRENT_SCANS = 5  # Limit concurrent scans to avoid system overload

class UltimateScanner:
    """Enhanced Ultimate Security Scanner with Advanced Features"""

    async def fetch_headers(url: str) -> Dict:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                return dict(response.headers)

    def _check_security_headers(self) -> Dict:
        """Analyze security-related HTTP headers."""
        required_headers = {
            'Strict-Transport-Security': r'max-age=\d+',
            'Content-Security-Policy': r'.+',
            'X-Content-Type-Options': r'nosniff',
            'X-Frame-Options': r'(deny|sameorigin)',
            'Referrer-Policy': r'.+'
        }
    
        headers = self._get_http_headers().get('headers', {})
        results = {}
    
        for header, pattern in required_headers.items():
            value = headers.get(header, 'MISSING')
            results[header] = {
                'present': value != 'MISSING',
                'valid': bool(re.match(pattern, value, re.I)) if value != 'MISSING' else False
            }
    
        return results
    
    def _check_db_auth(self, host: str, port: int, db_type: str) -> bool:
        """
        Check if database requires authentication.
        
        Args:
            host: Database host address
            port: Database port
            db_type: Database type (mysql, postgresql, etc.)
            
        Returns:
            bool: True if authentication is required, False otherwise
        """
        for attempt in range(self.MAX_RETRIES + 1):
            try:
                if db_type == 'mysql':
                    import mysql.connector
                    conn = mysql.connector.connect(
                        host=host,
                        port=port,
                        user='invalid_user',
                        password='invalid_password',
                        connect_timeout=self.CONNECT_TIMEOUT
                    )
                    conn.close()
                    return False
                
                elif db_type == 'postgresql':
                    import psycopg2
                    conn = psycopg2.connect(
                        host=host,
                        port=port,
                        user='invalid_user',
                        password='invalid_password',
                        connect_timeout=self.CONNECT_TIMEOUT
                    )
                    conn.close()
                    return False
                
                elif db_type == 'mongodb':
                    from pymongo import MongoClient
                    from pymongo.errors import OperationFailure
                    client = MongoClient(
                        host=host,
                        port=port,
                        username='invalid_user',
                        password='invalid_password',
                        serverSelectionTimeoutMS=self.CONNECT_TIMEOUT * 1000
                    )
                    # Force a command to check auth
                    client.admin.command('ismaster')
                    return False
                    
            except Exception as e:
                error_msg = str(e).lower()
                if any(auth_word in error_msg 
                       for auth_word in ['authentication', 'auth', 'authenticate', 'login']):
                    return True
                elif attempt < self.MAX_RETRIES:
                    sleep(self.RETRY_DELAY)
                    continue
                else:
                    self.logger.debug(f"Auth check error for {db_type} at {host}:{port}: {e}")
        
        # If we can't determine, assume auth is required
        return True

    def _test_default_db_creds(self, host: str, port: int, db_type: str) -> List[Dict]:
        """
        Test common database credentials against the target database.
        
        Args:
            host: Database host address
            port: Database port
            db_type: Database type (mysql, postgresql, etc.)
            
        Returns:
            List of dictionaries with test results for each credential pair
        """
        results = []
        
        if db_type not in self.COMMON_CREDS:
            self.logger.warning(f"No common credentials defined for database type: {db_type}")
            return results
            
        for user, pwd in self.COMMON_CREDS[db_type]:
            for attempt in range(self.MAX_RETRIES + 1):
                try:
                    success = False
                    conn = None
                    
                    if db_type == 'mysql':
                        import mysql.connector
                        conn = mysql.connector.connect(
                            host=host,
                            port=port,
                            user=user,
                            password=pwd,
                            connect_timeout=self.CONNECT_TIMEOUT
                        )
                        success = conn.is_connected()
                        
                    elif db_type == 'postgresql':
                        import psycopg2
                        conn = psycopg2.connect(
                            host=host,
                            port=port,
                            user=user,
                            password=pwd,
                            connect_timeout=self.CONNECT_TIMEOUT
                        )
                        success = True
                        
                    elif db_type == 'mongodb':
                        from pymongo import MongoClient
                        client = MongoClient(
                            host=host,
                            port=port,
                            username=user,
                            password=pwd,
                            serverSelectionTimeoutMS=self.CONNECT_TIMEOUT * 1000
                        )
                        # Force a command to check auth
                        client.admin.command('ismaster')
                        success = True
                        
                    if success:
                        results.append({
                            'user': user,
                            'password': pwd,
                            'success': True
                        })
                        break
                        
                except Exception as e:
                    if attempt >= self.MAX_RETRIES:
                        self.logger.debug(f"Failed attempt with {user}/{pwd} on {db_type}: {e}")
                    else:
                        sleep(self.RETRY_DELAY)
                        continue
                finally:
                    try:
                        if conn:
                            if db_type in ['mysql', 'postgresql']:
                                conn.close()
                            elif db_type == 'mongodb' and 'client' in locals():
                                client.close()
                    except:
                        pass
        
        return results



    def _find_subdomains(self) -> List[str]:
        """Brute-force subdomains using wordlist."""
        if not os.path.exists(CONFIG['paths']['wordlists']['subdomains']):
            return []

        found = []
        with open(CONFIG['paths']['wordlists']['subdomains']) as f:
            subdomains = [line.strip() for line in f if line.strip()]

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(
                    self._check_subdomain,
                    f"{sub}.{self.domain}"
                ): sub for sub in subdomains
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        return found

    def _check_subdomain(self, subdomain: str) -> Optional[str]:
        """Check if subdomain resolves and responds."""
        try:
            ip = socket.gethostbyname(subdomain)
            response = self.session.head(f"http://{subdomain}", timeout=3)
            if response.status_code < 400:
                return subdomain
        except:
            return None
    def _check_directory_listing(self, url: str) -> bool:
        """Check if directory listing is enabled."""
        test_paths = ['/images/', '/assets/', '/static/']
        for path in test_paths:
            try:
                response = self.session.get(url + path, timeout=5)
                if 'Index of' in response.text and '<a href=' in response.text:
                    return True
            except requests.RequestException:
                continue
        return False

    def _find_sensitive_files(self) -> List[Dict]:
        """Check for common sensitive files."""
        sensitive_files = [
            '/.env', '/.git/config', '/.htaccess',
            '/web.config', '/phpinfo.php', '/server-status'
        ]
        results = []
        for file in sensitive_files:
            try:
                response = self.session.get(self.base_url + file, timeout=3)
                if response.status_code == 200 and len(response.text) > 0:
                    results.append({
                        'url': response.url,
                        'status': response.status_code,
                        'size': len(response.content)
                    })
            except requests.RequestException:
                continue
        return results

    def _check_cors(self) -> Dict:
        """Test for CORS misconfigurations."""
        test_headers = {
            'Origin': 'https://evil.com',
            'Access-Control-Request-Method': 'GET'
        }
        try:
            response = self.session.options(
                self.base_url,
                headers=test_headers,
                timeout=5
            )
            cors_headers = {
                k.lower(): v for k, v in response.headers.items()
                if k.lower().startswith('access-control')
            }
            return {
                'vulnerable': '*' in cors_headers.get('access-control-allow-origin', ''),
                'headers': cors_headers
            }
        except requests.RequestException as e:
            return {'error': str(e)}


    def _query_shodan(self) -> Dict:
        """Query Shodan for target information."""
        if not CONFIG['api_keys']['shodan'] or not self.ip_address:
            return {}

        try:
            from shodan import Shodan
            api = Shodan(CONFIG['api_keys']['shodan'])
            host = api.host(self.ip_address)
            return {
                'ports': host.get('ports', []),
                'vulns': host.get('vulns', []),
                'services': {item['port']: item for item in host.get('data', [])}
            }
        except Exception as e:
            return {'error': str(e)}

    def _query_virustotal(self) -> Dict:
        """Query VirusTotal for domain/IP reputation."""
        if not CONFIG['api_keys']['virustotal'] or not self.domain:
            return {}

        try:
            client = vt.Client(CONFIG['api_keys']['virustotal'])
            url_id = vt.url_id(self.base_url)
            report = client.get_object(f"/urls/{url_id}")
            return {
                'malicious': report.last_analysis_stats['malicious'],
                'engines': {k: v for k, v in report.last_analysis_results.items() if v['category'] == 'malicious'}
            }
        except Exception as e:
            return {'error': str(e)}


    def _detect_cloud_provider(self) -> Optional[str]:
        """Detect cloud hosting provider."""
        if not self.ip_address:
            return None

        try:
            ip_info = ipwhois.IPWhois(self.ip_address)
            rdap = ip_info.lookup_rdap()
            rdap_str = str(rdap).lower()

            if 'amazon' in rdap_str:
                return 'AWS'
            elif 'google' in rdap_str:
                return 'GCP'
            elif 'microsoft' in rdap_str:
                return 'Azure'
        except Exception as e:
            print(f"Error detecting cloud provider via RDAP: {e}")

        # Fallback to DNS checks
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            if any('cloudflare' in str(r).lower() for r in ns_records):
                return 'Cloudflare'
        except Exception as e:
            print(f"Error detecting cloud provider via DNS: {e}")

        return None

    def _detect_cdn(self) -> Optional[str]:
        """Detect Content Delivery Network."""
        common_cdns: Dict[str, Tuple[str, ...]] = {
            'cloudflare': ('cloudflare', 'cf-ray'),
            'akamai': ('akamai', 'akamaighost'),
            'fastly': ('fastly', 'x-served-by'),
            'cloudfront': ('cloudfront', 'x-amz-cf-pop')
        }

        try:
            headers = self._get_http_headers()
            headers_str = str(headers).lower()
            for cdn, indicators in common_cdns.items():
                if any(indicator in headers_str for indicator in indicators):
                    return cdn
        except Exception as e:
            print(f"Error detecting CDN: {e}")

        return None

    def _detect_waf(self) -> Optional[str]:
        """Detect Web Application Firewall."""
        waf_signatures: Dict[str, Tuple[Pattern, str]] = {
            'Cloudflare': (re.compile(r'cloudflare', re.I), 'cf-ray'),
            'Akamai': (re.compile(r'akamai', re.I), 'akamaighost'),
            'Imperva': (re.compile(r'incapsula', re.I), 'x-cdn'),
            'AWS WAF': (re.compile(r'aws', re.I), 'x-aws-request-id')
        }

        try:
            response = self.session.get(self.base_url + "/<>'", timeout=5)
            for waf, (header_pattern, cookie_key) in waf_signatures.items():
                if header_pattern.search(str(response.headers)) or cookie_key in response.cookies:
                    return waf
        except Exception as e:
            print(f"Error detecting WAF: {e}")

        return None



    def _test_xss(self) -> Dict:
        """Test for Cross-Site Scripting (XSS) vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'payloads_used': [],
            'protected_endpoints': []
        }
    
        if not self.base_url:
            return {'error': 'No base URL available for XSS testing'}
    
        try:
            # Basic XSS payloads
            payloads = [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '" onmouseover=alert(1) x="',
                "' onmouseover=alert(1) x='",
                'javascript:alert(1)'
            ]

            # Test forms
            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    test_url = urljoin(self.base_url, form['action']) if form['action'] else self.base_url

                    for field in form['inputs']:
                        if field['type'] in ['text', 'search', 'textarea', 'password']:
                            for payload in payloads:
                                data = {f['name']: payload if f['name'] == field['name'] else 'test' 
                                   for f in form['inputs'] if f['name']}

                                try:
                                    response = self.session.post(
                                        test_url,
                                        data=data,
                                        timeout=10,
                                        allow_redirects=False
                                    )

                                    if payload in response.text:
                                        result['vulnerable_endpoints'].append({
                                            'url': test_url,
                                            'parameter': field['name'],
                                            'payload': payload,
                                            'status_code': response.status_code
                                        })
                                        result['payloads_used'].append(payload)
                                    else:
                                        result['protected_endpoints'].append({
                                            'url': test_url,
                                            'parameter': field['name'],
                                            'payload': payload
                                        })

                                except Exception as e:
                                    continue
                                    
            # Test URL parameters
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    if '?' in page['url']:
                        base, params = page['url'].split('?', 1)
                        for param in params.split('&'):
                            name, value = param.split('=', 1) if '=' in param else (param, '')

                            for payload in payloads:
                                try:
                                    test_url = f"{base}?{name}={payload}"
                                    response = self.session.get(
                                        test_url,
                                        timeout=10,
                                        allow_redirects=False
                                    )

                                    if payload in response.text:
                                        result['vulnerable_endpoints'].append({
                                            'url': test_url,
                                            'parameter': name,
                                            'payload': payload,
                                            'status_code': response.status_code
                                        })
                                        result['payloads_used'].append(payload)

                                except Exception as e:
                                    continue
                                    
            return result

        except Exception as e:
            return {'error': f"XSS test failed: {str(e)}"}
        

    def _test_idor(self) -> Dict:
        """Test for Insecure Direct Object References"""
        result = {
            'vulnerable_endpoints': [],
            'tested_patterns': [],
            'protected_endpoints': []
        }
    
        if not self.base_url:
            return {'error': 'No base URL available for IDOR testing'}
    
        try:
            # Look for numeric IDs in URLs
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    url = page['url']

                    # Find numeric IDs in URL
                    ids = re.findall(r'/(\d+)(?:/|$|\?|\.)', url)
                    for found_id in ids:
                        test_id = int(found_id) + 1
                        test_url = url.replace(f"/{found_id}/", f"/{test_id}/")

                        try:
                            response = self.session.get(
                                test_url,
                                timeout=10,
                                allow_redirects=False
                            )

                            if response.status_code == 200:
                                result['vulnerable_endpoints'].append({
                                    'original_url': url,
                                    'tested_url': test_url,
                                    'parameter': 'numeric_id',
                                    'original_id': found_id,
                                    'tested_id': test_id,
                                    'status_code': response.status_code
                                })
                                result['tested_patterns'].append('numeric_id_increment')
                            else:
                                result['protected_endpoints'].append({
                                    'original_url': url,
                                    'tested_url': test_url,
                                    'status_code': response.status_code
                                })

                        except Exception as e:
                            continue
                            
            return result

        except Exception as e:
            return {'error': f"IDOR test failed: {str(e)}"}

    def _test_ssrf(self) -> Dict:
        """Test for Server-Side Request Forgery vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'test_payloads': [],
            'protected_endpoints': []
        }

        if not self.base_url:
            return {'error': 'No base URL available for SSRF testing'}
    
        try:
            # Common SSRF test endpoints
            test_urls = [
                'http://169.254.169.254/latest/meta-data/',
                'http://localhost/admin',
                'http://internal.service/'
            ]

            payloads = []
            for test_url in test_urls:
                payloads.extend([
                    f"url={test_url}",
                    f"file={test_url}",
                    f"path={test_url}",
                    f"image={test_url}",
                    f"load={test_url}"
                ])

            result['test_payloads'] = payloads

            # Test forms
            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    action_url = urljoin(self.base_url, form['action']) if form['action'] else self.base_url

                    for field in form['inputs']:
                        if field['type'] in ['text', 'url', 'file']:
                            for payload in payloads:
                                param, value = payload.split('=', 1)
                                data = {f['name']: value if f['name'] == field['name'] else 'test' 
                                       for f in form['inputs'] if f['name']}

                                try:
                                    response = self.session.post(
                                        action_url,
                                        data=data,
                                        timeout=10,
                                        allow_redirects=False
                                    )

                                    if any(test_url in response.text for test_url in test_urls):
                                        result['vulnerable_endpoints'].append({
                                            'url': action_url,
                                            'parameter': field['name'],
                                            'payload': payload,
                                            'status_code': response.status_code
                                        })
                                    else:
                                        result['protected_endpoints'].append({
                                            'url': action_url,
                                            'parameter': field['name'],
                                            'payload': payload,
                                            'status_code': response.status_code
                                        })

                                except Exception as e:
                                    continue
                                    
            # Test URL parameters
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    if '?' in page['url']:
                        base, params = page['url'].split('?', 1)

                        for payload in payloads:
                            param, value = payload.split('=', 1)
                            test_url = f"{base}?{param}={value}"

                            try:
                                response = self.session.get(
                                    test_url,
                                    timeout=10,
                                    allow_redirects=False
                                )

                                if any(test_url in response.text for test_url in test_urls):
                                    result['vulnerable_endpoints'].append({
                                        'url': test_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'status_code': response.status_code
                                        })
                                else:
                                    result['protected_endpoints'].append({
                                        'url': test_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'status_code': response.status_code
                                    })
                        
                            except Exception as e:
                                continue
        
            return result
    
        except Exception as e:
            return {'error': f"SSRF test failed: {str(e)}"}

    def _test_rce(self) -> Dict:
        """Test for Remote Code Execution vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'payloads_used': [],
            'protected_endpoints': []
        }

        if not self.base_url:
            return {'error': 'No base URL available for RCE testing'}

        try:
            # Common RCE test payloads
            payloads = [
                ';id;',
                '|id',
                '`id`',
                '$(id)',
                '{{id}}',
                '<?php system("id"); ?>',
                '{{7*7}}'  # Simple template injection test
            ]

            # Test forms
            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    action_url = urljoin(self.base_url, form['action']) if form['action'] else self.base_url

                    for field in form['inputs']:
                        if field['type'] in ['text', 'search', 'textarea']:
                            for payload in payloads:
                                data = {f['name']: payload if f['name'] == field['name'] else 'test' 
                                       for f in form['inputs'] if f['name']}

                                try:
                                    response = self.session.post(
                                        action_url,
                                        data=data,
                                        timeout=10,
                                        allow_redirects=False
                                    )

                                    if 'uid=' in response.text or 'gid=' in response.text:
                                        result['vulnerable_endpoints'].append({
                                            'url': action_url,
                                            'parameter': field['name'],
                                            'payload': payload,
                                            'status_code': response.status_code
                                        })
                                        result['payloads_used'].append(payload)
                                    elif '49' in response.text and payload == '{{7*7}}':
                                        result['vulnerable_endpoints'].append({
                                            'url': action_url,
                                            'parameter': field['name'],
                                            'payload': payload,
                                            'status_code': response.status_code,
                                            'vulnerability': 'template_injection'
                                        })
                                    else:
                                        result['protected_endpoints'].append({
                                            'url': action_url,
                                            'parameter': field['name'],
                                            'payload': payload,
                                            'status_code': response.status_code
                                        })
                            
                                except Exception as e:
                                    continue
        
            # Test URL parameters
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    if '?' in page['url']:
                        base, params = page['url'].split('?', 1)

                        for param in params.split('&'):
                            name, value = param.split('=', 1) if '=' in param else (param, '')

                            for payload in payloads:
                                try:
                                    test_url = f"{base}?{name}={payload}"
                                    response = self.session.get(
                                        test_url,
                                        timeout=10,
                                        allow_redirects=False
                                    )

                                    if 'uid=' in response.text or 'gid=' in response.text:
                                        result['vulnerable_endpoints'].append({
                                            'url': test_url,
                                            'parameter': name,
                                            'payload': payload,
                                            'status_code': response.status_code
                                        })
                                        result['payloads_used'].append(payload)
                                    elif '49' in response.text and payload == '{{7*7}}':
                                        result['vulnerable_endpoints'].append({
                                            'url': test_url,
                                            'parameter': name,
                                            'payload': payload,
                                            'status_code': response.status_code,
                                            'vulnerability': 'template_injection'
                                        })

                                except Exception as e:
                                    continue
                                    
            return result

        except Exception as e:
            return {'error': f"RCE test failed: {str(e)}"}

    def _test_lfi(self) -> Dict:
        """Test for Local File Inclusion vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'tested_files': [],
            'protected_endpoints': []
        }

        if not self.base_url:
            return {'error': 'No base URL available for LFI testing'}

        try:
            # Common LFI test files
            test_files = [
                '/etc/passwd',
                '/etc/hosts',
                '../../../../etc/passwd',
                '....//....//....//....//etc/passwd',
                '%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
            ]

            result['tested_files'] = test_files

            # Test forms
            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    action_url = urljoin(self.base_url, form['action']) if form['action'] else self.base_url

                    for field in form['inputs']:
                        if field['type'] in ['text', 'file']:
                            for test_file in test_files:
                                data = {f['name']: test_file if f['name'] == field['name'] else 'test' 
                                       for f in form['inputs'] if f['name']}

                                try:
                                    response = self.session.post(
                                        action_url,
                                        data=data,
                                        timeout=10,
                                        allow_redirects=False
                                    )

                                    if 'root:x:' in response.text or 'localhost' in response.text:
                                        result['vulnerable_endpoints'].append({
                                            'url': action_url,
                                            'parameter': field['name'],
                                            'payload': test_file,
                                            'status_code': response.status_code
                                        })
                                    else:
                                        result['protected_endpoints'].append({
                                            'url': action_url,
                                            'parameter': field['name'],
                                            'payload': test_file,
                                            'status_code': response.status_code
                                        })

                                except Exception as e:
                                    continue
                                    
            # Test URL parameters
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    if '?' in page['url']:
                        base, params = page['url'].split('?', 1)

                        for param in params.split('&'):
                            name, value = param.split('=', 1) if '=' in param else (param, '')

                            for test_file in test_files:
                                try:
                                    test_url = f"{base}?{name}={test_file}"
                                    response = self.session.get(
                                        test_url,
                                        timeout=10,
                                        allow_redirects=False
                                    )

                                    if 'root:x:' in response.text or 'localhost' in response.text:
                                        result['vulnerable_endpoints'].append({
                                            'url': test_url,
                                              'parameter': name,
                                            'payload': test_file,
                                            'status_code': response.status_code
                                        })

                                except Exception as e:
                                    continue
                                    
            return result

        except Exception as e:
            return {'error': f"LFI test failed: {str(e)}"}

    def _advanced_fuzzing(self) -> Dict:
        """Perform advanced fuzzing of endpoints"""
        result = {
            'vulnerabilities_found': [],
            'tested_endpoints': [],
            'error_responses': []
        }

        if not self.base_url:
            return {'error': 'No base URL available for fuzzing'}

        try:
            # Use ffuf if available
            if os.path.exists(CONFIG['paths']['tools']['ffuf']):
                # Fuzz common parameters
                cmd = [
                    CONFIG['paths']['tools']['ffuf'],
                    '-u', f"{self.base_url}/FUZZ",
                    '-w', CONFIG['paths']['wordlists']['api_endpoints'],
                    '-t', '50',
                    '-p', '0.1',
                    '-o', os.path.join(CONFIG['paths']['output_dir'], 'fuzzing_results.json'),
                    '-of', 'json'
                ]

                output = self._run_subprocess(cmd)
                if output and not output.startswith('Error'):
                    try:
                        with open(os.path.join(CONFIG['paths']['output_dir'], 'fuzzing_results.json')) as f:
                            fuzz_results = json.load(f)
                            for res in fuzz_results.get('results', []):
                                if res['status'] != 404:
                                    result['tested_endpoints'].append({
                                        'url': res['url'],
                                        'status': res['status'],
                                        'length': res['length']
                                    })
                                    if res['status'] >= 500:
                                        result['error_responses'].append({
                                            'url': res['url'],
                                            'status': res['status']
                                        })
                    except:
                        pass
                        
                # Parameter fuzzing
                if 'web_spider' in self.results['results']:
                    for page in self.results['results']['web_spider'].get('pages', []):
                        if '?' in page['url']:
                            base, params = page['url'].split('?', 1)
                            param_names = [p.split('=')[0] for p in params.split('&')]

                            for param in param_names:
                                cmd = [
                                    CONFIG['paths']['tools']['ffuf'],
                                    '-u', f"{base}?{param}=FUZZ",
                                    '-w', CONFIG['paths']['wordlists']['api_endpoints'],
                                    '-t', '50',
                                    '-p', '0.1',
                                    '-fs', '0'  # Filter by size 0 to catch all responses
                                ]

                                output = self._run_subprocess(cmd)
                                if output and not output.startswith('Error'):
                                    for line in output.splitlines():
                                        if 'FUZZ' in line:
                                            parts = line.split()
                                            if len(parts) > 4:
                                                result['tested_endpoints'].append({
                                                    'url': f"{base}?{param}={parts[0]}",
                                                    'status': int(parts[3]),
                                                    'length': int(parts[2])
                                                })
                                                if int(parts[3]) >= 500:
                                                    result['error_responses'].append({
                                                        'url': f"{base}?{param}={parts[0]}",
                                                        'status': int(parts[3])
                                                    })

            return result

        except Exception as e:
            return {'error': f"Advanced fuzzing failed: {str(e)}"}

    def _test_sql_injection(self) -> Dict:
        """Test for SQL injection vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'techniques_tested': ['boolean_based', 'time_based', 'error_based'],
            'payloads_used': [],
            'protected_endpoints': []
        }
    
        if not self.base_url:
            return {'error': 'No base URL available for SQLi testing'}
    
        try:
        # Test login forms
            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    test_url = urljoin(self.base_url, form['action']) if form['action'] else self.base_url
                
                    # Test each input field
                    for field in form['inputs']:
                        if field['type'] in ['text', 'password', 'search']:
                            payloads = [
                                "'",
                                "\"",
                                "' OR '1'='1",
                                "\" OR \"1\"=\"1",
                                "' OR 1=1--",
                                "1 AND SLEEP(5)"
                            ]

                            for payload in payloads:
                                data = {f['name']: payload if f['name'] == field['name'] else 'test' 
                                       for f in form['inputs'] if f['name']}

                                try:
                                    start_time = time.time()
                                    response = self.session.post(
                                        test_url,
                                        data=data,
                                        timeout=10,
                                        allow_redirects=False
                                    )
                                    response_time = time.time() - start_time

                                    # Check for signs of SQLi
                                    vulnerable = False
                                    if response_time > 5:  # Time-based detection
                                        vulnerable = True
                                    elif any(error in response.text.lower() for error in 
                                             ['sql syntax', 'mysql error', 'ora-', 'syntax error']):
                                        vulnerable = True
                                    elif response.status_code != 200:  # Error-based detection
                                        vulnerable = True

                                    if vulnerable:
                                        result['vulnerable_endpoints'].append({
                                            'url': test_url,
                                            'parameter': field['name'],
                                            'payload': payload,
                                            'response_time': response_time,
                                            'status_code': response.status_code,
                                            'response_length': len(response.text)
                                        })
                                        result['payloads_used'].append(payload)
                                    else:
                                        result['protected_endpoints'].append({
                                            'url': test_url,
                                            'parameter': field['name'],
                                            'payload': payload
                                        })

                                except Exception as e:
                                    continue
        
            # Test URL parameters
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    if '?' in page['url']:
                        base, params = page['url'].split('?', 1)
                        for param in params.split('&'):
                            name, value = param.split('=', 1) if '=' in param else (param, '')
                            payloads = [
                                f"{name}='",
                                f"{name}=1' OR '1'='1",
                                f"{name}=1 AND SLEEP(5)"
                            ]

                            for payload in payloads:
                                try:
                                    test_url = f"{base}?{payload}"
                                    start_time = time.time()
                                    response = self.session.get(
                                        test_url,
                                        timeout=10,
                                        allow_redirects=False
                                    )
                                    response_time = time.time() - start_time

                                    # Check for signs of SQLi
                                    vulnerable = False
                                    if response_time > 5:
                                        vulnerable = True
                                    elif any(error in response.text.lower() for error in 
                                             ['sql syntax', 'mysql error', 'ora-', 'syntax error']):
                                        vulnerable = True
                                    elif response.status_code != 200:
                                        vulnerable = True

                                    if vulnerable:
                                        result['vulnerable_endpoints'].append({
                                            'url': test_url,
                                            'parameter': name,
                                            'payload': payload,
                                            'response_time': response_time,
                                            'status_code': response.status_code,
                                            'response_length': len(response.text)
                                        })
                                        result['payloads_used'].append(payload)

                                except Exception as e:
                                    continue
                                    
            return result
    
        except Exception as e:
            return {'error': f"SQL injection test failed: {str(e)}"}


    def __init__(self, target: str):
        self.target = target
        self.domain = None
        self.ip_address = None
        self.base_url = None
        self.results = {
            'metadata': {
                'target': target,
                'start_time': datetime.utcnow().isoformat(),
                'tool_version': '4.0-Power',
                'config': CONFIG
            },
            'results': {}
        }
        self.session = self._init_http_session()
        self.selenium_driver = self._init_selenium()
        self.lock = threading.Lock()
        
    def _init_http_session(self) -> requests.Session:
        """Initialize advanced HTTP session with retries and proxies"""
        session = requests.Session()
        
        # Configure retry strategy
        retry = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[408, 429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Configure headers
        session.headers.update({
            'User-Agent': UserAgent().random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Configure proxies if Tor is available
        if self._check_tor():
            session.proxies = {
                'http': CONFIG['advanced']['tor_proxy'],
                'https': CONFIG['advanced']['tor_proxy']
            }
        
        return session
    
    def _init_selenium(self) -> Optional[webdriver.Chrome]:
        """Initialize headless Chrome with advanced options"""
        try:
            options = Options()
            
            # Basic options
            options.add_argument('--headless')
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--window-size=1920,1080')
            
            # Security options
            options.add_argument('--disable-extensions')
            options.add_argument('--disable-popup-blocking')
            options.add_argument('--disable-notifications')
            options.add_argument('--ignore-certificate-errors')
            
            # Performance options
            options.add_argument('--disable-software-rasterizer')
            options.add_argument('--disable-background-networking')
            options.add_argument('--disable-default-apps')
            options.add_argument('--disable-sync')
            
            # Find Chrome binary
            chrome_paths = [
                '/usr/bin/google-chrome',
                '/usr/bin/chromium',
                '/usr/bin/chromium-browser',
                '/usr/local/bin/chrome',
                '/opt/google/chrome/chrome'
            ]
            
            for path in chrome_paths:
                if os.path.exists(path):
                    options.binary_location = path
                    break
            
            # Set up proxy if Tor is available
            if self._check_tor():
                options.add_argument(f'--proxy-server={CONFIG["advanced"]["tor_proxy"]}')
            
            # Configure ChromeDriver
            driver = webdriver.Chrome(
                options=options,
                service_args=['--verbose', '--log-path=chromedriver.log']
            )
            
            # Set timeouts
            driver.set_page_load_timeout(30)
            driver.set_script_timeout(20)
            
            return driver
        except Exception as e:
            print(f"[-] Selenium initialization failed: {str(e)}")
            return None
    
    def _check_tor(self) -> bool:
        """Check if Tor proxy is available"""
        try:
            test_ip = requests.get(
                'https://api.ipify.org',
                proxies={'http': CONFIG['advanced']['tor_proxy'], 'https': CONFIG['advanced']['tor_proxy']},
                timeout=10
            ).text
            return test_ip != requests.get('https://api.ipify.org', timeout=10).text
        except:
            return False
    
    def run_scan(self, scan_type: str = "full", **kwargs) -> Dict:
        """Execute comprehensive security scan"""
        start_time = time.time()
        
        # Create output directories
        os.makedirs(CONFIG['paths']['output_dir'], exist_ok=True)
        os.makedirs(CONFIG['paths']['screenshots_dir'], exist_ok=True)
        
        # Resolve target information
        self._resolve_target()
        
        # Prepare scan tasks based on type
        scan_tasks = self._prepare_scan_tasks(scan_type, kwargs.get('aggressive', False))
        
        # Execute scans with thread pool and rate limiting
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(CONFIG['scan']['max_threads'], MAX_CONCURRENT_SCANS)
        ) as executor:
            futures = {}
            
            for name, task in scan_tasks.items():
                futures[executor.submit(task)] = name
                time.sleep(CONFIG['advanced']['rate_limit_delay'])  # Rate limiting
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    with self.lock:
                        self.results['results'][name] = result
                except Exception as e:
                    with self.lock:
                        self.results['results'][name] = {'error': str(e)}
        
        # Post-processing
        self._post_processing()
        
        # Calculate execution time
        self.results['metadata']['execution_time'] = time.time() - start_time
        self.results['metadata']['end_time'] = datetime.utcnow().isoformat()
        
        # Clean up
        if self.selenium_driver:
            self.selenium_driver.quit()
        
        return self.results
    def is_valid_ip(self, address: str) -> bool:
        """Check if a string is a valid IPv4 or IPv6 address.
    
        Args:
            address: The IP address string to validate
        
        Returns:
            bool: True if valid IP, False otherwise
        """
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    def _resolve_target(self):
        """Resolve target to IP, domain, and base URL"""
        if self.is_valid_ip(self.target):  # Changed to call the method with self.
            self.ip_address = self.target
            try:
                self.domain = socket.getfqdn(self.ip_address)
            except:
                self.domain = self.ip_address
        else:
            # Handle URL or domain
            if not self.target.startswith(('http://', 'https://')):
                self.target = f'https://{self.target}'
            
            parsed = urlparse(self.target)
            self.domain = parsed.hostname
            self.base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            try:
                self.ip_address = socket.gethostbyname(self.domain)
            except socket.gaierror:
                self.ip_address = None
    
    def _prepare_scan_tasks(self, scan_type: str, aggressive: bool = False) -> Dict:
        """Prepare scan tasks based on scan type"""
        tasks = {}
        
        # Common tasks for all scan types
        common_tasks = {
            'target_info': self._get_target_info,
            'dns_records': self._get_dns_records,
            'whois': self._get_whois_info,
            'ssl_tls': self._get_ssl_info,
            'http_headers': self._get_http_headers,
            'tech_stack': self._detect_tech_stack,
        }
        
        # Network scan tasks
        network_tasks = {
            'port_scan': lambda: self._scan_ports(CONFIG['scan']['default_ports']),
            'os_detection': self._detect_os,
            'service_detection': self._detect_services,
            'vulnerability_scan': self._scan_vulnerabilities,
            'network_traffic': self._capture_network_traffic,
        }
        
        # Web application scan tasks
        web_tasks = {
            'web_spider': self._spider_website,
            'content_analysis': self._analyze_content,
            'form_analysis': self._analyze_forms,
            'api_analysis': self._analyze_apis,
            'auth_analysis': self._analyze_auth,
            'security_headers': self._check_security_headers,
            'cors_analysis': self._check_cors,
            'sensitive_files': self._find_sensitive_files,
            'subdomains': self._find_subdomains,
            'directory_bruteforce': self._bruteforce_directories,
        }
        
        # Aggressive scan tasks
        aggressive_tasks = {
            'full_port_scan': lambda: self._scan_ports(CONFIG['scan']['full_ports']),
            'hidden_services': lambda: self._scan_ports(CONFIG['scan']['hidden_ports']),
            'sql_injection': self._test_sql_injection,
            'xss_test': self._test_xss,
            'idor_test': self._test_idor,
            'ssrf_test': self._test_ssrf,
            'rce_test': self._test_rce,
            'lfi_test': self._test_lfi,
            'advanced_fuzzing': self._advanced_fuzzing,
        }
        
        # Build task list based on scan type
        tasks.update(common_tasks)
        
        if scan_type in ["network", "full"]:
            tasks.update(network_tasks)
        
        if scan_type in ["web", "full"] and self.base_url:
            tasks.update(web_tasks)
        
        if aggressive:
            tasks.update(aggressive_tasks)
        
        return tasks
    
    def _get_target_info(self) -> Dict:
        """Get comprehensive target information"""
        result = {
            'target': self.target,
            'domain': self.domain,
            'ip_address': self.ip_address,
            'base_url': self.base_url,
            'is_up': self._is_host_up(),
            'cloud_provider': self._detect_cloud_provider(),
            'cdn': self._detect_cdn(),
            'waf': self._detect_waf(),
        }
        
        # Additional API lookups if available
        if CONFIG['api_keys']['shodan'] and self.ip_address:
            result['shodan'] = self._query_shodan()
        
        if CONFIG['api_keys']['virustotal'] and self.domain:
            result['virustotal'] = self._query_virustotal()
        
        return result
    
    def _is_host_up(self) -> bool:
        """Check if target is responsive"""
        try:
            if self.ip_address:
                # ICMP ping
                subprocess.run(
                    ['ping', '-c', '1', '-W', '1', self.ip_address],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                return True
            elif self.base_url:
                # HTTP request
                response = self.session.head(self.base_url, timeout=5)
                return response.status_code < 400
        except:
            return False
    
    def _get_dns_records(self) -> Dict:
        """Get comprehensive DNS records"""
        result = {}
        records = [
            'A', 'AAAA', 'MX', 'NS', 'TXT', 
            'SOA', 'CNAME', 'PTR', 'SRV', 
            'SPF', 'DKIM', 'DMARC'
        ]
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        for record in records:
            try:
                answers = resolver.resolve(self.domain, record)
                result[record] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                continue
        
        # Additional DNS checks
        result['dnssec'] = self._check_dnssec()
        result['zone_transfer'] = self._test_zone_transfer()
        
        return result
    
    def _check_dnssec(self) -> bool:
        """Check if DNSSEC is enabled"""
        try:
            cmd = f"dig +dnssec {self.domain} SOA | grep -q 'RRSIG' && echo 'Yes' || echo 'No'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return "Yes" in result.stdout
        except:
            return False
    
    def _test_zone_transfer(self) -> List[str]:
        """Test for DNS zone transfer vulnerability"""
        vulnerable = []
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            for ns in ns_records:
                try:
                    axfr = dns.query.xfr(str(ns), self.domain, timeout=5)
                    records = list(axfr)
                    if records:
                        vulnerable.append(str(ns))
                except:
                    continue
        except:
            pass
        return vulnerable
    
    def _get_whois_info(self) -> Dict:
        """Get WHOIS information"""
        result = {}
        try:
            cmd = f"whois {self.domain}" if self.domain else f"whois {self.ip_address}"
            whois_data = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
            
            # Parse common whois fields
            patterns = {
                'registrar': r'Registrar:\s*(.+)',
                'creation_date': r'Creation Date:\s*(.+)',
                'expiration_date': r'Expiration Date:\s*(.+)',
                'updated_date': r'Updated Date:\s*(.+)',
                'name_servers': r'Name Server:\s*(.+)',
                'org': r'Organization:\s*(.+)',
                'country': r'Country:\s*(.+)',
            }
            
            for key, pattern in patterns.items():
                match = re.search(pattern, whois_data, re.IGNORECASE)
                if match:
                    result[key] = match.group(1).strip()
            
            result['raw'] = whois_data[:2000] + '...' if len(whois_data) > 2000 else whois_data
        except:
            result['error'] = "WHOIS lookup failed"
        
        return result
    
    def _scan_ports(self, ports: str) -> Dict:
        """Perform comprehensive port scanning with Nmap"""
        result = {}
        
        try:
            nm = nmap.PortScanner()
            
            # Configure scan arguments based on stealth mode
            if CONFIG['advanced']['stealth_mode']:
                scan_args = '-sS -T2 -n --open'
            else:
                scan_args = '-sV -T4 -A --script=banner,vulners,ssl-enum-ciphers'
            
            target = self.ip_address if self.ip_address else self.domain
            print(f"[*] Scanning ports {ports} on {target}")
            
            nm.scan(
                hosts=target,
                ports=ports,
                arguments=scan_args,
                sudo=True
            )
            
            for host in nm.all_hosts():
                result[host] = {
                    'hostnames': nm[host].hostnames(),
                    'status': nm[host].state(),
                    'protocols': {}
                }
                
                for proto in nm[host].all_protocols():
                    result[host]['protocols'][proto] = {}
                    
                    for port, data in nm[host][proto].items():
                        if data['state'] == 'open':
                            service = {
                                'name': data.get('name', 'unknown'),
                                'product': data.get('product', ''),
                                'version': data.get('version', ''),
                                'extrainfo': data.get('extrainfo', ''),
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
                            
                            result[host]['protocols'][proto][port] = service
            
            # Perform additional service-specific scans
            self._scan_web_services(result)
            self._scan_database_services(result)
            
        except Exception as e:
            result['error'] = f"Port scan failed: {str(e)}"
        
        return result
    
    def _scan_web_services(self, scan_result: Dict):
        """Perform deeper analysis of web services"""
        for host, data in scan_result.items():
            for proto, ports in data.get('protocols', {}).items():
                for port, service in ports.items():
                    if service['name'] in ['http', 'https', 'http-proxy', 'http-alt']:
                        url = f"{'https' if service['name'] == 'https' else 'http'}://{host}:{port}"
                        
                        # Add web-specific checks
                        service['web_checks'] = {
                            'headers': self._get_http_headers(url),
                            'tech_stack': self._detect_tech_stack(url),
                            'ssl_tls': self._get_ssl_info(url) if service['name'] == 'https' else None,
                            'directory_listing': self._check_directory_listing(url),
                        }
    
    def _scan_database_services(self, scan_result: Dict):
        """Perform deeper analysis of database services"""
        for host, data in scan_result.items():
            for proto, ports in data.get('protocols', {}).items():
                for port, service in ports.items():
                    if service['name'] in ['mysql', 'postgresql', 'mongodb', 'redis', 'oracle']:
                        # Add database-specific checks
                        service['db_checks'] = {
                            'auth_required': self._check_db_auth(host, port, service['name']),
                            'default_creds': self._test_default_db_creds(host, port, service['name']),
                        }
    
    def _get_http_headers(self, url: str = None) -> Dict:
        """Get HTTP headers with advanced analysis"""
        target_url = url if url else self.base_url
        if not target_url:
            return {'error': 'No URL available for headers check'}
        
        result = {}
        
        try:
            response = self.session.get(
                target_url,
                allow_redirects=True,
                timeout=10
            )
            
            result = {
                'status_code': response.status_code,
                'final_url': response.url,
                'redirect_chain': [{'url': r.url, 'status': r.status_code} for r in response.history],
                'headers': dict(response.headers),
                'cookies': dict(response.cookies),
                'server': response.headers.get('Server', ''),
                'x_powered_by': response.headers.get('X-Powered-By', ''),
                'content_type': response.headers.get('Content-Type', ''),
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds(),
                'http_version': 'HTTP/2' if response.raw.version == 20 else 'HTTP/1.1',
            }
            
            # Check for security headers
            security_headers = [
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Feature-Policy',
                'Permissions-Policy',
                'Expect-CT',
                'Public-Key-Pins',
            ]
            
            result['security_headers'] = {
                h: response.headers.get(h, 'MISSING') for h in security_headers
            }
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _detect_tech_stack(self, url: str = None) -> Dict:
        """Detect web technologies with version fingerprinting"""
        target_url = url if url else self.base_url
        if not target_url:
            return {'error': 'No URL available for tech detection'}
        
        result = {}
        
        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(target_url)
            technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
            
            # Enhanced version detection
            for tech, data in technologies.items():
                if 'versions' in data and data['versions']:
                    data['latest_version'] = max(data['versions'])
                    data['version_count'] = len(data['versions'])
                else:
                    # Try to extract version from headers or HTML
                    version = self._extract_version_from_headers(tech, target_url)
                    if version:
                        data['versions'] = [version]
                        data['latest_version'] = version
                        data['version_count'] = 1
            
            result = technologies
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _get_ssl_info(self, url: str = None) -> Dict:
        """Comprehensive SSL/TLS assessment"""
        target_url = url if url else self.base_url
        if not target_url:
            return {'error': 'No URL available for SSL check'}
        
        result = {}
        hostname = urlparse(target_url).hostname
        
        try:
            # Basic SSL info
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
            except Exception as e:
                result['sslyze_error'] = str(e)
            
            # Check for SSL misconfigurations
            result['vulnerabilities'] = self._check_ssl_vulnerabilities(hostname)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _spider_website(self) -> Dict:
        """Advanced website spidering with Selenium"""
        if not self.selenium_driver or not self.base_url:
            return {'error': 'Selenium not available or no base URL'}
        
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
        
        try:
            self.selenium_driver.get(self.base_url)
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
            for tag in ['img', 'script', 'link', 'iframe', 'video', 'audio', 'source']:
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
            
            # Get all forms
            forms = self.selenium_driver.find_elements(By.TAG_NAME, 'form')
            for form in forms:
                try:
                    form_info = {
                        'action': form.get_attribute('action'),
                        'method': form.get_attribute('method'),
                        'inputs': []
                    }
                    
                    inputs = form.find_elements(By.TAG_NAME, 'input')
                    for input_field in inputs:
                        form_info['inputs'].append({
                            'name': input_field.get_attribute('name'),
                            'type': input_field.get_attribute('type'),
                            'value': input_field.get_attribute('value'),
                        })
                    
                    result['forms'].append(form_info)
                    result['statistics']['forms_found'] += 1
                except:
                    continue
            
            # Get current page info
            current_page = {
                'url': self.selenium_driver.current_url,
                'title': self.selenium_driver.title,
                'source': self.selenium_driver.page_source[:1000] + '...' if len(self.selenium_driver.page_source) > 1000 else self.selenium_driver.page_source,
                'screenshot': os.path.join(CONFIG['paths']['screenshots_dir'], f"{self.domain}_home.png"),
            }
            self.selenium_driver.save_screenshot(current_page['screenshot'])
            result['pages'].append(current_page)
            
            # Limited recursive spidering
            self._recursive_spider(self.base_url, result, depth=1)
            
            result['statistics']['total_pages'] = len(result['pages'])
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _recursive_spider(self, url: str, result: Dict, depth: int):
        """Recursively spider the website"""
        if depth > CONFIG['scan']['max_depth'] or len(result['pages']) >= CONFIG['scan']['max_pages']:
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
            
            # Process new links (limited to 10 per page)
            for link in new_links[:10]:
                try:
                    self.selenium_driver.get(link)
                    time.sleep(1)
                    
                    page_info = {
                        'url': self.selenium_driver.current_url,
                        'title': self.selenium_driver.title,
                        'source': self.selenium_driver.page_source[:500] + '...',
                        'screenshot': os.path.join(CONFIG['paths']['screenshots_dir'], f"{hashlib.md5(link.encode()).hexdigest()}.png"),
                    }
                    
                    self.selenium_driver.save_screenshot(page_info['screenshot'])
                    result['pages'].append(page_info)
                    
                    # Recurse
                    self._recursive_spider(link, result, depth + 1)
                except:
                    continue
                    
        except Exception as e:
            print(f"[-] Error during spidering: {str(e)}")
    
    def _scan_vulnerabilities(self) -> Dict:
        """Run multiple vulnerability scanners"""
        result = {
            'nikto': {},
            'nuclei': {},
            'zap': {},
            'sqlmap': {},
            'manual_checks': {},
        }
        
        try:
            # Nikto scan
            if os.path.exists(CONFIG['paths']['tools']['nikto']):
                nikto_result = self._run_subprocess([
                    CONFIG['paths']['tools']['nikto'],
                    '-h', self.base_url if self.base_url else self.ip_address,
                    '-Format', 'json',
                    '-Tuning', 'x4567890abc',
                    '-timeout', '10'
                ])
                
                if nikto_result and not nikto_result.startswith('Error'):
                    result['nikto'] = json.loads(nikto_result)
                else:
                    result['nikto']['error'] = nikto_result
            
            # Nuclei scan
            if os.path.exists(CONFIG['paths']['tools']['nuclei']):
                nuclei_result = self._run_subprocess([
                    CONFIG['paths']['tools']['nuclei'],
                    '-u', self.base_url if self.base_url else self.ip_address,
                    '-json',
                    '-severity', 'low,medium,high,critical',
                    '-templates', '/usr/local/nuclei-templates',
                    '-timeout', '10'
                ])
                
                if nuclei_result and not nuclei_result.startswith('Error'):
                    result['nuclei'] = [json.loads(line) for line in nuclei_result.splitlines() if line.strip()]
                else:
                    result['nuclei']['error'] = nuclei_result
            
            # SQLMap scan (if forms found)
            if self.results['results'].get('web_spider', {}).get('forms'):
                if os.path.exists(CONFIG['paths']['tools']['sqlmap']):
                    sqlmap_result = self._run_subprocess([
                        CONFIG['paths']['tools']['sqlmap'],
                        '-u', self.base_url,
                        '--batch',
                        '--crawl=1',
                        '--level=3',
                        '--risk=2',
                        '--output-dir', CONFIG['paths']['output_dir']
                    ])
                    result['sqlmap']['output'] = sqlmap_result
            
            # Manual checks
            result['manual_checks'] = {
                'admin_interfaces': self._check_admin_interfaces(),
                'debug_endpoints': self._check_debug_endpoints(),
                'exposed_database_interfaces': self._check_database_interfaces(),
                'backup_files': self._check_backup_files(),
                'git_exposure': self._check_git_exposure(),
            }
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _run_subprocess(self, command: List[str]) -> str:
        """Execute subprocess command with security checks"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=CONFIG['scan']['timeout'],
                check=True,
                shell=False
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Error: Command timed out"
        except subprocess.CalledProcessError as e:
            return f"Error: {e.stderr}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def _post_processing(self):
        """Perform post-processing on scan results"""
        # Analyze relationships between findings
        self._analyze_relationships()
        
        # Generate risk assessment
        self._generate_risk_assessment()
        
        # Calculate hashes of important findings
        self._calculate_hashes()
        
        # Generate executive summary
        self._generate_executive_summary()
    
    def _analyze_relationships(self):
        """Analyze relationships between different findings"""
        # Link vulnerabilities with outdated technologies
        tech = self.results['results'].get('tech_stack', {})
        vulns = self.results['results'].get('vulnerability_scan', {}).get('nuclei', [])
        
        if isinstance(tech, dict) and vulns:
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
                                v for v in vulns
                                if isinstance(v, dict) and 
                                name.lower() in v.get('templateID', '').lower()
                            ]
                        })
            
            if outdated:
                self.results['results']['outdated_technologies'] = outdated
        
        # Link open ports with found services
        port_scan = self.results['results'].get('port_scan', {})
        if port_scan:
            self.results['results']['service_map'] = {}
            for host, data in port_scan.items():
                if 'protocols' in data:
                    for proto, ports in data['protocols'].items():
                        for port, service in ports.items():
                            if service['state'] == 'open':
                                self.results['results']['service_map'][f"{host}:{port}"] = {
                                    'service': service['name'],
                                    'product': service.get('product', ''),
                                    'version': service.get('version', ''),
                                    'vulnerabilities': service.get('vulnerabilities', [])
                                }
    
    def _generate_risk_assessment(self):
        """Generate risk assessment based on findings"""
        risks = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        # Check for critical vulnerabilities
        vulns = self.results['results'].get('vulnerability_scan', {})
        if vulns.get('nuclei'):
            for vuln in vulns['nuclei']:
                if isinstance(vuln, dict):
                    severity = vuln.get('info', {}).get('severity', 'info').lower()
                    risks[severity].append({
                        'type': 'vulnerability',
                        'source': 'nuclei',
                        'details': vuln
                    })
        
        # Check for outdated technologies
        outdated = self.results['results'].get('outdated_technologies', [])
        for tech in outdated:
            if tech['vulnerabilities']:
                risks['high'].append({
                    'type': 'outdated_technology',
                    'technology': tech['technology'],
                    'current_version': tech['current'],
                    'latest_version': tech['latest'],
                    'vulnerabilities': tech['vulnerabilities']
                })
        
        # Check for missing security headers
        headers = self.results['results'].get('http_headers', {}).get('security_headers', {})
        missing_headers = [h for h, v in headers.items() if v == 'MISSING']
        if missing_headers:
            risks['medium'].append({
                'type': 'missing_security_headers',
                'headers': missing_headers
            })
        
        # Check for sensitive files exposure
        sensitive_files = self.results['results'].get('sensitive_files', [])
        if sensitive_files:
            risks['high'].append({
                'type': 'sensitive_files_exposed',
                'files': sensitive_files
            })
        
        # Check for default credentials
        default_creds = self.results['results'].get('auth_analysis', {}).get('default_credentials', [])
        if default_creds:
            risks['critical'].append({
                'type': 'default_credentials',
                'services': default_creds
            })
        
        self.results['risk_assessment'] = risks
    
    def _calculate_hashes(self):
        """Calculate hashes of important findings"""
        hashes = {}
        
        # Hash all pages found during spidering
        if 'web_spider' in self.results['results']:
            hashes['pages'] = []
            for page in self.results['results']['web_spider'].get('pages', []):
                if 'source' in page:
                    hashes['pages'].append({
                        'url': page.get('url'),
                        'sha256': hashlib.sha256(page['source'].encode()).hexdigest()
                    })
        
        # Hash all resources
        if 'web_spider' in self.results['results']:
            hashes['resources'] = []
            for resource in self.results['results']['web_spider'].get('resources', []):
                if 'url' in resource:
                    hashes['resources'].append({
                        'url': resource['url'],
                        'type': resource.get('type'),
                        'sha256': hashlib.sha256(resource['url'].encode()).hexdigest()
                    })
        
        self.results['hashes'] = hashes
    
    def _generate_executive_summary(self):
        """Generate executive summary of findings"""
        summary = {
            'scan_overview': {
                'target': self.target,
                'start_time': self.results['metadata']['start_time'],
                'end_time': self.results['metadata']['end_time'],
                'duration': self.results['metadata']['execution_time'],
                'scan_type': 'full' if 'vulnerability_scan' in self.results['results'] else 'web' if 'web_spider' in self.results['results'] else 'network'
            },
            'findings_summary': {
                'total_vulnerabilities': 0,
                'critical_vulnerabilities': len(self.results['risk_assessment'].get('critical', [])),
                'high_vulnerabilities': len(self.results['risk_assessment'].get('high', [])),
                'medium_vulnerabilities': len(self.results['risk_assessment'].get('medium', [])),
                'low_vulnerabilities': len(self.results['risk_assessment'].get('low', [])),
                'informational_findings': len(self.results['risk_assessment'].get('info', [])),
                'open_ports': 0,
                'services_identified': 0,
                'web_pages_found': len(self.results['results'].get('web_spider', {}).get('pages', [])),
                'forms_found': len(self.results['results'].get('web_spider', {}).get('forms', [])),
            },
            'recommendations': []
        }
        
        # Count open ports
        if 'port_scan' in self.results['results']:
            for host, data in self.results['results']['port_scan'].items():
                if 'protocols' in data:
                    for proto, ports in data['protocols'].items():
                        summary['findings_summary']['open_ports'] += len(ports)
                        summary['findings_summary']['services_identified'] += len([
                            p for p in ports.values() 
                            if p.get('product') or p.get('version')
                        ])
        
        # Total vulnerabilities
        summary['findings_summary']['total_vulnerabilities'] = (
            summary['findings_summary']['critical_vulnerabilities'] +
            summary['findings_summary']['high_vulnerabilities'] +
            summary['findings_summary']['medium_vulnerabilities'] +
            summary['findings_summary']['low_vulnerabilities']
        )
        
        # Generate recommendations
        if summary['findings_summary']['critical_vulnerabilities'] > 0:
            summary['recommendations'].append(
                "Immediate remediation required for critical vulnerabilities"
            )
        
        if summary['findings_summary']['high_vulnerabilities'] > 0:
            summary['recommendations'].append(
                "Prioritize remediation of high severity vulnerabilities"
            )
        
        if self.results['results'].get('outdated_technologies'):
            summary['recommendations'].append(
                "Update outdated software components to latest versions"
            )
        
        if 'missing_security_headers' in [r['type'] for r in self.results['risk_assessment'].get('medium', [])]:
            summary['recommendations'].append(
                "Implement missing security headers for enhanced protection"
            )
        
        self.results['executive_summary'] = summary
    
    # Additional advanced methods would be added here...
    # (Implementation of _test_sql_injection, _test_xss, _advanced_fuzzing, etc.)

def cli_main():
    """Enhanced command line interface"""
    parser = argparse.ArgumentParser(
        description="Ultimate Linux Network Security Scanner - Power Edition",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Target specification
    parser.add_argument(
        'target',
        help="Target to scan (IP, domain, or URL)"
    )
    
    # Scan options
    parser.add_argument(
        '-t', '--type',
        choices=['quick', 'full', 'web', 'network', 'vulnerability'],
        default='full',
        help="Type of scan to perform"
    )
    
    parser.add_argument(
        '-o', '--output',
        help="Output file for JSON results"
    )
    
    parser.add_argument(
        '--aggressive',
        action='store_true',
        help="Enable aggressive scanning techniques"
    )
    
    parser.add_argument(
        '--stealth',
        action='store_true',
        help="Enable stealth mode (slower but less detectable)"
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help="Increase verbosity level"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Update config based on arguments
    CONFIG['advanced']['aggressive_scan'] = args.aggressive
    CONFIG['advanced']['stealth_mode'] = args.stealth
    
    # Initialize scanner
    scanner = UltimateScanner(args.target)
    
    # Run scan
    print(f"[*] Starting {args.type} scan of {args.target}")
    try:
        results = scanner.run_scan(args.type, aggressive=args.aggressive)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"[+] Results saved to {args.output}")
        
        # Print executive summary
        summary = results.get('executive_summary', {})
        print("\n[+] Scan Summary:")
        print(f"  - Target: {summary.get('scan_overview', {}).get('target')}")
        print(f"  - Duration: {summary.get('scan_overview', {}).get('duration', 0):.2f} seconds")
        print(f"  - Open ports: {summary.get('findings_summary', {}).get('open_ports', 0)}")
        print(f"  - Critical vulnerabilities: {summary.get('findings_summary', {}).get('critical_vulnerabilities', 0)}")
        print(f"  - Web pages found: {summary.get('findings_summary', {}).get('web_pages_found', 0)}")
        
        print("\n[+] Top Recommendations:")
        for rec in summary.get('recommendations', [])[:3]:
            print(f"  - {rec}")
        
        print("\n[+] Scan completed successfully")
        
    except Exception as e:
        print(f"[-] Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    cli_main()
