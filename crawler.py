#!/usr/bin/env python3
"""
HTMLCrawler - Web Security Scanner
Component #1: URL enumeration, directory traversal, and XSS/CSRF vulnerability detection

This script crawls a target web server, discovers directories and pages,
then performs static code analysis to identify XSS and CSRF vulnerabilities.
"""

import requests
import re
import argparse
import json
import urllib3
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from datetime import datetime
from collections import deque
import concurrent.futures
import sys
import os
from third_party_scanner import ThirdPartyScanner


# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VulnerabilityScanner:
    """Static code analyzer for XSS and CSRF vulnerabilities with dynamic pattern loading."""

    def __init__(self, patterns_file=None):
        """
        Initialize scanner with patterns from file or defaults.
        
        Args:
            patterns_file: Path to JSON file containing patterns
        """
        self.vulnerabilities = []
        self.xss_patterns = {}
        self.csrf_patterns = {}
        self.sqli_patterns = {}
        self._seen_sqli = set()
        
        if patterns_file and os.path.exists(patterns_file):
            self.load_patterns_from_file(patterns_file)
        else:
            # Load default patterns from patterns.json if exists
            default_patterns = os.path.join(os.path.dirname(__file__), 'patterns.json')
            if os.path.exists(default_patterns):
                self.load_patterns_from_file(default_patterns)
            else:
                print("[!] Warning: No patterns file found. Scanner will not detect vulnerabilities.")

    def load_patterns_from_file(self, filepath):
        """Load vulnerability patterns from JSON file."""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            self.xss_patterns = data.get('xss_patterns', {})
            self.csrf_patterns = data.get('csrf_patterns', {})
            self.sqli_patterns = data.get('sqli_patterns', {})
            
            print(f"[+] Loaded {len(self.xss_patterns)} XSS, {len(self.csrf_patterns)} CSRF, {len(self.sqli_patterns)} SQLi patterns from {filepath}")
        except Exception as e:
            print(f"[!] Error loading patterns from {filepath}: {e}")
            sys.exit(1)

    def add_pattern(self, vuln_type, name, pattern_data):
        """
        Add a new vulnerability pattern dynamically.
        
        Args:
            vuln_type: 'xss' or 'csrf'
            name: Unique identifier for the pattern
            pattern_data: Dict with 'pattern', 'severity', 'description', optional 'flags'
        """
        if vuln_type.lower() == 'xss':
            self.xss_patterns[name] = pattern_data
        elif vuln_type.lower() == 'csrf':
            self.csrf_patterns[name] = pattern_data
        else:
            raise ValueError(f"Unknown vulnerability type: {vuln_type}")
        
        print(f"[+] Added {vuln_type.upper()} pattern: {name}")

    def remove_pattern(self, vuln_type, name):
        """Remove a vulnerability pattern."""
        if vuln_type.lower() == 'xss' and name in self.xss_patterns:
            del self.xss_patterns[name]
            print(f"[+] Removed XSS pattern: {name}")
        elif vuln_type.lower() == 'csrf' and name in self.csrf_patterns:
            del self.csrf_patterns[name]
            print(f"[+] Removed CSRF pattern: {name}")
        else:
            print(f"[!] Pattern not found: {name}")

    def update_pattern(self, vuln_type, name, pattern_data):
        """Update an existing vulnerability pattern."""
        if vuln_type.lower() == 'xss' and name in self.xss_patterns:
            self.xss_patterns[name].update(pattern_data)
            print(f"[+] Updated XSS pattern: {name}")
        elif vuln_type.lower() == 'csrf' and name in self.csrf_patterns:
            self.csrf_patterns[name].update(pattern_data)
            print(f"[+] Updated CSRF pattern: {name}")
        else:
            print(f"[!] Pattern not found: {name}")

    def list_patterns(self):
        """List all loaded patterns."""
        print("\n=== XSS PATTERNS ===")
        for name, info in self.xss_patterns.items():
            print(f"  - {name}: {info['severity']} - {info['description']}")
        
        print("\n=== CSRF PATTERNS ===")
        for name, info in self.csrf_patterns.items():
            print(f"  - {name}: {info['severity']} - {info['description']}")

    def export_patterns(self, filepath):
        """Export current patterns to JSON file."""
        data = {
            'xss_patterns': self.xss_patterns,
            'csrf_patterns': self.csrf_patterns
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Patterns exported to {filepath}")

    def _parse_flags(self, flags_list):
        """Convert string flags to re module flags."""
        if not flags_list:
            return re.IGNORECASE
        
        flag_map = {
            'IGNORECASE': re.IGNORECASE,
            'DOTALL': re.DOTALL,
            'MULTILINE': re.MULTILINE,
            'VERBOSE': re.VERBOSE
        }
        
        result = 0
        for flag in flags_list:
            result |= flag_map.get(flag.upper(), 0)
        
        return result if result else re.IGNORECASE

    def analyze_html(self, html_content, url, response_text=None):
        """Analyze HTML content for XSS, CSRF, and SQLi vulnerabilities."""
        findings = []

        # Check XSS patterns
        for vuln_name, vuln_info in self.xss_patterns.items():
            flags = self._parse_flags(vuln_info.get('flags'))
            try:
                matches = re.finditer(vuln_info['pattern'], html_content, flags)
                for match in matches:
                    line_num = html_content[:match.start()].count('\n') + 1
                    findings.append({
                        'type': 'XSS',
                        'name': vuln_name,
                        'severity': vuln_info['severity'],
                        'description': vuln_info['description'],
                        'url': url,
                        'line': line_num,
                        'code_snippet': match.group(0)[:100]
                    })
            except re.error as e:
                print(f"[!] Invalid regex pattern in {vuln_name}: {e}")

        # Check CSRF patterns
        for vuln_name, vuln_info in self.csrf_patterns.items():
            flags = self._parse_flags(vuln_info.get('flags'))
            try:
                matches = re.finditer(vuln_info['pattern'], html_content, flags)
                for match in matches:
                    line_num = html_content[:match.start()].count('\n') + 1
                    findings.append({
                        'type': 'CSRF',
                        'name': vuln_name,
                        'severity': vuln_info['severity'],
                        'description': vuln_info['description'],
                        'url': url,
                        'line': line_num,
                        'code_snippet': match.group(0)[:100]
                    })
            except re.error as e:
                print(f"[!] Invalid regex pattern in {vuln_name}: {e}")

        # Check SQLi patterns (deduped)
        for vuln_name, vuln_info in self.sqli_patterns.items():
            flags = self._parse_flags(vuln_info.get('flags'))
            try:
                seen_snippets = set()

                matches = re.finditer(vuln_info['pattern'], html_content, flags)
                for match in matches:
                    snippet = match.group(0)[:100]

                    if snippet in seen_snippets:
                        continue
                    seen_snippets.add(snippet)

                    line_num = html_content[:match.start()].count('\n') + 1
                    findings.append({
                        'type': 'SQLI',
                        'name': vuln_name,
                        'severity': vuln_info['severity'],
                        'description': vuln_info['description'],
                        'url': url,
                        'line': line_num,
                        'code_snippet': snippet
                    })
            except re.error as e:
                print(f"[!] Invalid regex pattern in {vuln_name}: {e}")

        # Additional form analysis using BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        findings.extend(self._analyze_forms(soup, url))
        findings.extend(self._analyze_scripts(soup, url))

        # Passive SQLi surface + DB error detection
        # Pass the raw response_text (if available) so DB errors in JS/comments are caught
        findings.extend(self.detect_sqli_surface(html_content, url, response_text))

        return findings

    def _sqli_dedupe_key(self, url: str, rule_name: str) -> str:
        p = urlparse(url)
        keys = ",".join(sorted(parse_qs(p.query).keys()))
        # scheme+host+path + param names (NOT values) + rule name
        return f"{p.scheme}://{p.netloc}{p.path}?{keys}|{rule_name}"

    # ------------------------------------------------------------------
    # Passive SQLi surface detection
    # ------------------------------------------------------------------
    # SQLi cannot be found by scanning static HTML output — the flaw lives
    # in the server-side code.  What we CAN do passively is identify every
    # input surface (URL query params, form fields) that accepts user input
    # and flag it as a potential injection point.  We also check the HTTP
    # response for database error strings that prove the app is leaking raw
    # SQL errors back to the browser (a HIGH-confidence indicator).
    # ------------------------------------------------------------------

    # Regex patterns that match common database error messages in responses
    _DB_ERROR_PATTERNS = [
        # MySQL / MariaDB
        (r"you have an error in your sql syntax", "MySQL syntax error exposed"),
        (r"warning:\s+mysqli?::", "MySQL warning exposed"),
        (r"supplied argument is not a valid mysql", "MySQL invalid argument exposed"),
        (r"mysql_fetch_array\(\)", "MySQL function name exposed"),
        (r"com\.mysql\.jdbc\.exceptions", "Java MySQL exception exposed"),
        # MSSQL
        (r"unclosed quotation mark after the character string", "MSSQL unclosed quote error"),
        (r"incorrect syntax near", "MSSQL syntax error exposed"),
        (r"\[Microsoft\]\[ODBC SQL Server Driver\]", "MSSQL ODBC error exposed"),
        (r"\[SQL Server\]", "SQL Server error tag exposed"),
        # Oracle
        (r"ora-\d{5}", "Oracle ORA- error exposed"),
        (r"oracle error", "Oracle error exposed"),
        # PostgreSQL
        (r"pg_query\(\):", "PostgreSQL query error exposed"),
        (r"pg_exec\(\):", "PostgreSQL exec error exposed"),
        (r"postgresql.*error", "PostgreSQL error exposed"),
        # SQLite
        (r"sqlite_[a-z]+\(\)", "SQLite function error exposed"),
        (r"sqlite3\.operationalerror", "SQLite3 operational error exposed"),
        # Generic ODBC / JDBC
        (r"odbc driver.*sql", "ODBC SQL error exposed"),
        (r"jdbc.*sql.*exception", "JDBC SQL exception exposed"),
        # Generic
        (r"sql syntax.*mysql", "Generic SQL syntax error"),
        (r"division by zero in sql", "SQL division by zero"),
    ]

    # Input field name patterns that strongly suggest database lookups
    _DB_PARAM_NAMES = re.compile(
        r'\b(id|user_?id|product_?id|item_?id|order_?id|cat(?:egory)?_?id|'
        r'user(?:name)?|login|email|search|q|query|keyword|name|'
        r'page|sort|order|filter|category|type|key|ref)\b',
        re.IGNORECASE
    )

    def detect_sqli_surface(self, html_content: str, url: str, response_text: str = None) -> list:
        """
        Passive SQLi detection via three complementary signals:

        1. URL query parameters that look like DB identifiers (e.g. ?id=1)
        2. HTML form fields whose names suggest DB lookups
        3. Database error strings leaked into the HTTP response body
        """
        findings = []
        soup = BeautifulSoup(html_content, 'html.parser')

        # ── 1. URL query parameter inspection ────────────────────────────
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param_name in params:
            if self._DB_PARAM_NAMES.search(param_name):
                dedup_key = self._sqli_dedupe_key(url, f"url_param:{param_name}")
                if dedup_key not in self._seen_sqli:
                    self._seen_sqli.add(dedup_key)
                    findings.append({
                        'type': 'SQLI',
                        'name': 'sqli_suspect_url_parameter',
                        'severity': 'MEDIUM',
                        'description': (
                            f'URL parameter "{param_name}" is a common SQL injection vector. '
                            f'Verify server-side input is parameterised.'
                        ),
                        'url': url,
                        'line': 0,
                        'code_snippet': f'GET param: {param_name}={params[param_name][0][:40]}'
                    })

        # ── 2. Form field inspection ──────────────────────────────────────
        for form in soup.find_all('form'):
            action = form.get('action', url)
            full_action = urljoin(url, action) if action else url
            method = form.get('method', 'get').upper()
            for field in form.find_all(['input', 'textarea', 'select']):
                field_name = field.get('name', '')
                field_type = field.get('type', 'text').lower()
                # Skip hidden/submit/button/checkbox/radio – not free-text
                if field_type in ('hidden', 'submit', 'button', 'checkbox', 'radio', 'image', 'reset'):
                    continue
                if field_name and self._DB_PARAM_NAMES.search(field_name):
                    dedup_key = self._sqli_dedupe_key(
                        full_action, f"form_field:{field_name}"
                    )
                    if dedup_key not in self._seen_sqli:
                        self._seen_sqli.add(dedup_key)
                        findings.append({
                            'type': 'SQLI',
                            'name': 'sqli_suspect_form_field',
                            'severity': 'MEDIUM',
                            'description': (
                                f'Form field "{field_name}" ({method} → {full_action}) '
                                f'is a common SQL injection vector. '
                                f'Verify server-side input is parameterised.'
                            ),
                            'url': url,
                            'line': 0,
                            'code_snippet': f'{method} field: {field_name}'
                        })

        # ── 3. Database error string detection (HIGH confidence) ─────────
        # Scan the raw response text (not just the parsed HTML) so we catch
        # errors that appear in JS strings, HTML comments, or plain text.
        body_to_scan = response_text if response_text else html_content
        for pattern, description in self._DB_ERROR_PATTERNS:
            match = re.search(pattern, body_to_scan, re.IGNORECASE)
            if match:
                dedup_key = self._sqli_dedupe_key(url, f"db_error:{pattern[:20]}")
                if dedup_key not in self._seen_sqli:
                    self._seen_sqli.add(dedup_key)
                    findings.append({
                        'type': 'SQLI',
                        'name': 'sqli_database_error_in_response',
                        'severity': 'HIGH',
                        'description': (
                            f'{description} — raw database error returned to browser. '
                            f'This is a strong indicator of SQL injection vulnerability.'
                        ),
                        'url': url,
                        'line': 0,
                        'code_snippet': match.group(0)[:120]
                    })
                break  # one error per page is enough

        return findings

    def _analyze_forms(self, soup, url):
        """Detailed form analysis for CSRF vulnerabilities."""
        findings = []
        forms = soup.find_all('form')

        for form in forms:
            method = form.get('method', 'get').lower()

            if method == 'post':
                # Check for CSRF token
                has_csrf = False
                for input_field in form.find_all('input'):
                    name = input_field.get('name', '').lower()
                    if any(token in name for token in ['csrf', 'token', '_token', 'authenticity', 'nonce']):
                        has_csrf = True
                        break

                if not has_csrf:
                    findings.append({
                        'type': 'CSRF',
                        'name': 'form_missing_csrf_token',
                        'severity': 'HIGH',
                        'description': f'POST form missing CSRF token protection',
                        'url': url,
                        'line': 0,
                        'code_snippet': str(form)[:100]
                    })

            # Check for external form action
            action = form.get('action', '')
            if action and action.startswith(('http://', 'https://')):
                parsed = urlparse(action)
                if parsed.netloc != urlparse(url).netloc:
                    findings.append({
                        'type': 'CSRF',
                        'name': 'form_external_action',
                        'severity': 'MEDIUM',
                        'description': f'Form submits to external domain: {parsed.netloc}',
                        'url': url,
                        'line': 0,
                        'code_snippet': str(form)[:100]
                    })

        return findings

    def _analyze_scripts(self, soup, url):
        """Analyze inline scripts for XSS vulnerabilities."""
        findings = []
        scripts = soup.find_all('script', src=False)

        for script in scripts:
            if script.string:
                script_content = script.string

                # Check for dangerous JavaScript patterns
                dangerous_patterns = [
                    (r'\.innerHTML\s*=', 'innerHTML manipulation'),
                    (r'document\.write\s*\(', 'document.write usage'),
                    (r'\beval\s*\(', 'eval() usage'),
                    (r'\.outerHTML\s*=', 'outerHTML manipulation')
                ]

                for pattern, desc in dangerous_patterns:
                    if re.search(pattern, script_content):
                        findings.append({
                            'type': 'XSS',
                            'name': f'inline_script_{desc.replace(" ", "_")}',
                            'severity': 'MEDIUM',
                            'description': f'Inline script contains {desc}',
                            'url': url,
                            'line': 0,
                            'code_snippet': script_content[:100]
                        })

        return findings


class HTMLCrawler:
    """Web crawler for discovering URLs and analyzing vulnerabilities."""

    def __init__(self, target_url, max_depth=3, threads=10, timeout=10, patterns_file=None, wordlists_file=None):
        """
        Initialize the crawler.

        Args:
            target_url: Starting URL for the crawl
            max_depth: Maximum depth to crawl
            threads: Number of threads for concurrent requests
            timeout: Request timeout in seconds
            patterns_file: Path to custom patterns file
            wordlists_file: Path to custom wordlists file
        """
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.threads = threads
        self.timeout = timeout

        self.visited_urls = set()
        self.discovered_urls = set()
        self.all_vulnerabilities = []

        # Initialize scanner with patterns
        self.scanner = VulnerabilityScanner(patterns_file)
        self.third_party_scanner = ThirdPartyScanner(self.base_domain)

        # Load wordlists
        self.common_dirs = []
        self.common_files = []
        self._load_wordlists(wordlists_file)

    def _load_wordlists(self, wordlists_file=None):
        """Load directory and file wordlists from JSON file."""
        if wordlists_file and os.path.exists(wordlists_file):
            filepath = wordlists_file
        else:
            # Try default wordlists.json
            filepath = os.path.join(os.path.dirname(__file__), 'wordlists.json')
        
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                
                self.common_dirs = data.get('common_dirs', [])
                self.common_files = data.get('common_files', [])
                
                print(f"[+] Loaded {len(self.common_dirs)} directories and {len(self.common_files)} files from {filepath}")
            except Exception as e:
                print(f"[!] Error loading wordlists from {filepath}: {e}")
                print("[!] Using minimal default wordlists")
                self._set_minimal_defaults()
        else:
            print("[!] No wordlists file found. Using minimal default wordlists")
            self._set_minimal_defaults()
    
    def _set_minimal_defaults(self):
        """Set minimal default wordlists if no file is available."""
        self.common_dirs = ['admin', 'api', 'login', 'dashboard']
        self.common_files = ['index.html', 'robots.txt', '.env']

    def fetch_url(self, url, method='GET', data=None):
        """Fetch URL with error handling."""
        try:
            if method == 'GET':
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
            else:
                response = requests.post(
                    url,
                    data=data,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
            return response
        except requests.exceptions.RequestException as e:
            return None

    def check_security_headers(self, response, url):
        findings = []

        required_headers = {
            'Content-Security-Policy': 'Missing Content-Security-Policy header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'Strict-Transport-Security': 'Missing Strict-Transport-Security header',
            'Referrer-Policy': 'Missing Referrer-Policy header'
        }

        headers = response.headers

        for header, description in required_headers.items():
            if header not in headers:
                findings.append({
                    'type': 'SECURITY_HEADER',
                    'name': header,
                    'severity': 'MEDIUM',
                    'description': description,
                    'url': url,
                    'line': 0,
                    'code_snippet': 'Header not present'
                })

        return findings

    def check_cookie_security(self, response, url):
        findings = []

        for cookie in response.cookies:
            cookie_name = cookie.name

            # Secure flag
            if not cookie.secure:
                findings.append({
                    'type': 'COOKIE_SECURITY',
                    'name': 'Missing Secure flag',
                    'severity': 'MEDIUM',
                    'description': f'Cookie "{cookie_name}" is missing Secure flag',
                    'url': url,
                    'line': 0,
                    'code_snippet': f'Cookie: {cookie_name}'
                })

            # HttpOnly flag
            if not cookie.has_nonstandard_attr('HttpOnly') and 'httponly' not in cookie._rest:
                findings.append({
                    'type': 'COOKIE_SECURITY',
                    'name': 'Missing HttpOnly flag',
                    'severity': 'MEDIUM',
                    'description': f'Cookie "{cookie_name}" is missing HttpOnly flag',
                    'url': url,
                    'line': 0,
                    'code_snippet': f'Cookie: {cookie_name}'
                })

            # SameSite flag
            if 'samesite' not in {k.lower() for k in cookie._rest.keys()}:
                findings.append({
                    'type': 'COOKIE_SECURITY',
                    'name': 'Missing SameSite attribute',
                    'severity': 'LOW',
                    'description': f'Cookie "{cookie_name}" is missing SameSite attribute',
                    'url': url,
                    'line': 0,
                    'code_snippet': f'Cookie: {cookie_name}'
                })

        return findings

    def normalize_url(self, url):
        """Normalize and resolve relative URLs."""
        if not url:
            return None

        # Handle relative URLs
        if url.startswith('/'):
            return urljoin(self.target_url, url)
        elif url.startswith(('http://', 'https://')):
            return url
        else:
            return urljoin(self.target_url, url)

    def is_same_domain(self, url):
        """Check if URL belongs to target domain."""
        if not url:
            return False
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ''

    def enumerate_directories(self):
        """Enumerate common directories."""
        print("\n[*] Phase 1: Directory Enumeration")
        found_dirs = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_dir = {
                executor.submit(self.fetch_url, f"{self.target_url}/{dir_name}"): dir_name
                for dir_name in self.common_dirs
            }

            for future in concurrent.futures.as_completed(future_to_dir):
                dir_name = future_to_dir[future]
                try:
                    response = future.result()
                    if response and response.status_code in [200, 301, 302, 403]:
                        url = f"{self.target_url}/{dir_name}"
                        found_dirs.append((url, response.status_code))
                        self.discovered_urls.add(url)
                        status_indicator = "✓" if response.status_code == 200 else "⚠"
                        print(f"  [{status_indicator}] Found: {url} (Status: {response.status_code})")
                except Exception as e:
                    pass

        return found_dirs

    def enumerate_files(self, base_paths=None):
        """Enumerate common files in base paths."""
        print("\n[*] Phase 1.5: File Enumeration")

        if base_paths is None:
            base_paths = [self.target_url]

        found_files = []

        for base in base_paths:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_file = {
                    executor.submit(self.fetch_url, f"{base}/{filename}"): (base, filename)
                    for filename in self.common_files
                }

                for future in concurrent.futures.as_completed(future_to_file):
                    base, filename = future_to_file[future]
                    try:
                        response = future.result()
                        if response and response.status_code == 200:
                            url = f"{base}/{filename}"
                            content_length = len(response.content)
                            result = (url, content_length)
                            found_files.append(result)
                            self.discovered_urls.add(result[0])
                            print(f"  [+] Found file: {result[0]} (Size: {result[1]} bytes)")
                    except Exception as e:
                        pass

        return found_files

    def crawl_page(self, url, depth=0):
        """Crawl a single page and extract links."""
        if depth > self.max_depth or url in self.visited_urls:
            return []

        self.visited_urls.add(url)
        response = self.fetch_url(url)

        if not response or response.status_code != 200:
            return []

        content_type = response.headers.get('Content-Type', '')
        if 'text/html' not in content_type.lower():
            return []

        print(f"  [*] Crawling: {url} (Depth: {depth})")

        # Check cookie security flags
        cookie_findings = self.check_cookie_security(response, url)
        self.all_vulnerabilities.extend(cookie_findings)

        # Check security headers
        header_findings = self.check_security_headers(response, url)
        self.all_vulnerabilities.extend(header_findings)

        # Analyze page for vulnerabilities
        vulnerabilities = self.scanner.analyze_html(response.text, url, response_text=response.text)
        self.all_vulnerabilities.extend(vulnerabilities)

        # Analyze page for third-party libraries and insecure dependencies
        third_party = self.third_party_scanner.analyze(response.text, url)
        self.all_vulnerabilities.extend(third_party)

        # Extract links
        soup = BeautifulSoup(response.text, 'html.parser')
        links = []

        # Get links from anchor tags
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = self.normalize_url(href)
            if self.is_same_domain(full_url) and full_url not in self.visited_urls:
                links.append(full_url)
                self.discovered_urls.add(full_url)

        # Get links from forms
        for form in soup.find_all('form', action=True):
            action = form['action']
            full_url = self.normalize_url(action)
            if self.is_same_domain(full_url):
                self.discovered_urls.add(full_url)

        # Get links from scripts
        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = self.normalize_url(src)
            if self.is_same_domain(full_url):
                self.discovered_urls.add(full_url)

        return links

    def crawl(self):
        """Main crawling function using BFS."""
        print(f"\n[*] Starting crawl from {self.target_url}")
        queue = deque([(self.target_url, 0)])

        while queue:
            url, depth = queue.popleft()
            links = self.crawl_page(url, depth)

            for link in links:
                if link not in self.visited_urls:
                    queue.append((link, depth + 1))

    def generate_report(self, output_file=None):
        """Generate vulnerability report."""
        report = {
            'scan_info': {
                'target': self.target_url,
                'scan_time': datetime.now().isoformat(),
                'pages_scanned': len(self.visited_urls),
                'urls_discovered': len(self.discovered_urls)
            },
            'summary': {
                'total_vulnerabilities': len(self.all_vulnerabilities),
                'critical': len([v for v in self.all_vulnerabilities if v['severity'] == 'CRITICAL']),
                'high': len([v for v in self.all_vulnerabilities if v['severity'] == 'HIGH']),
                'medium': len([v for v in self.all_vulnerabilities if v['severity'] == 'MEDIUM']),
                'low': len([v for v in self.all_vulnerabilities if v['severity'] == 'LOW']),
                'xss_count': len([v for v in self.all_vulnerabilities if v['type'] == 'XSS']),
                'csrf_count': len([v for v in self.all_vulnerabilities if v['type'] == 'CSRF']),
                'sqli_count': len([v for v in self.all_vulnerabilities if v['type'] == 'SQLI']),
                'cookie_issues': len([v for v in self.all_vulnerabilities if v['type'] == 'COOKIE_SECURITY'])
            },
            'discovered_urls': list(self.discovered_urls),
            'vulnerabilities': self.all_vulnerabilities
        }

        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to {output_file}")

        return report

    def print_summary(self, report):
        """Print scan summary to console."""
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Target: {report['scan_info']['target']}")
        print(f"Pages Scanned: {report['scan_info']['pages_scanned']}")
        print(f"URLs Discovered: {report['scan_info']['urls_discovered']}")
        print(f"\nVulnerabilities Found: {report['summary']['total_vulnerabilities']}")
        print(f"  - CRITICAL: {report['summary']['critical']}")
        print(f"  - HIGH: {report['summary']['high']}")
        print(f"  - MEDIUM: {report['summary']['medium']}")
        print(f"  - LOW: {report['summary']['low']}")
        print(f"\nBy Type:")
        print(f"  - XSS: {report['summary']['xss_count']}")
        print(f"  - CSRF: {report['summary']['csrf_count']}")
        print(f"  - SQLI: {report['summary']['sqli_count']}")

        print("\n" + "=" * 60)
        print("OTHER FINDINGS (Third-Party & Configuration)")
        print("=" * 60)

        shown = False

        for v in self.all_vulnerabilities:
            if v['type'] in [
                'THIRD_PARTY_LIBRARY',
                'EXTERNAL_SERVICE',
                'INSECURE_DEPENDENCY',
                'SECURITY_HEADER',
                'COOKIE_SECURITY'
            ]:
                shown = True
                print(f"\n[{v['type']}] {v['severity']}")
                print(f"  Description: {v['description']}")
                print(f"  URL: {v['url']}")
                print(f"  Evidence: {v['code_snippet']}")

        if not shown:
            print("No third-party or configuration issues detected.")

        print("\n" + "=" * 60)
        print("OTHER FINDINGS (Third-Party & Configuration)")
        print("=" * 60)

        shown = False

        for v in self.all_vulnerabilities:
            if v['type'] in [
                'THIRD_PARTY_LIBRARY',
                'EXTERNAL_SERVICE',
                'INSECURE_DEPENDENCY',
                'SECURITY_HEADER',
                'COOKIE_SECURITY'
            ]:
                shown = True
                print(f"\n[{v['type']}] {v['severity']}")
                print(f"  Description: {v['description']}")
                print(f"  URL: {v['url']}")
                print(f"  Evidence: {v['code_snippet']}")

        if not shown:
            print("No third-party or configuration issues detected.")

        if self.all_vulnerabilities:
            print("\n" + "-"*60)
            print("VULNERABILITY DETAILS")
            print("-"*60)

            for vuln in self.all_vulnerabilities:
                print(f"\n[{vuln['severity']}] {vuln['type']} - {vuln['name']}")
                print(f"  URL: {vuln['url']}")
                print(f"  Line: {vuln['line']}")
                print(f"  Description: {vuln['description']}")
                print(f"  Code: {vuln['code_snippet'][:80]}...")


def main():
    parser = argparse.ArgumentParser(
        description='HTMLCrawler - Web Security Scanner for XSS and CSRF vulnerabilities'
    )
    parser.add_argument(
        'target',
        nargs='?',
        help='Target URL to scan (e.g., http://192.168.1.100:3000)'
    )
    parser.add_argument(
        '-d', '--depth',
        type=int,
        default=3,
        help='Maximum crawl depth (default: 3)'
    )
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=10,
        help='Number of threads for directory enumeration (default: 10)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file for JSON report'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    parser.add_argument(
        '--no-enum',
        action='store_true',
        help='Skip directory enumeration'
    )
    parser.add_argument(
        '-p', '--patterns',
        help='Path to custom patterns JSON file'
    )
    parser.add_argument(
        '-w', '--wordlists',
        help='Path to custom wordlists JSON file (directories and files to enumerate)'
    )
    parser.add_argument(
        '--list-patterns',
        action='store_true',
        help='List all loaded patterns and exit'
    )
    parser.add_argument(
        '--export-patterns',
        help='Export current patterns to specified file and exit'
    )
    parser.add_argument(
        '--list-wordlists',
        action='store_true',
        help='List all loaded wordlists and exit'
    )
    parser.add_argument(
        '--export-wordlists',
        help='Export current wordlists to specified file and exit'
    )

    args = parser.parse_args()

    # Handle wordlist listing/export
    if args.list_wordlists or args.export_wordlists:
        # Need to create a temporary crawler to load wordlists
        temp_crawler = HTMLCrawler(
            'http://temp.com',
            wordlists_file=args.wordlists
        )
        
        if args.list_wordlists:
            print("\n=== COMMON DIRECTORIES ===")
            for i, dir_name in enumerate(temp_crawler.common_dirs, 1):
                print(f"  {i}. {dir_name}")
            
            print("\n=== COMMON FILES ===")
            for i, file_name in enumerate(temp_crawler.common_files, 1):
                print(f"  {i}. {file_name}")
        
        if args.export_wordlists:
            wordlists_data = {
                'common_dirs': temp_crawler.common_dirs,
                'common_files': temp_crawler.common_files
            }
            with open(args.export_wordlists, 'w') as f:
                json.dump(wordlists_data, f, indent=2)
            print(f"[+] Wordlists exported to {args.export_wordlists}")
        
        sys.exit(0)

    # Handle pattern listing/export
    if args.list_patterns or args.export_patterns:
        scanner = VulnerabilityScanner(args.patterns)
        if args.list_patterns:
            scanner.list_patterns()
        if args.export_patterns:
            scanner.export_patterns(args.export_patterns)
        sys.exit(0)

    # Validate URL
    if not args.target.startswith(('http://', 'https://')):
        args.target = 'http://' + args.target

    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║           HTMLCrawler - Web Security Scanner              ║
    ║         XSS & CSRF Vulnerability Detection Tool           ║
    ║              Dynamic Pattern Loading System               ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    crawler = HTMLCrawler(
        args.target,
        max_depth=args.depth,
        threads=args.threads,
        timeout=args.timeout,
        patterns_file=args.patterns,
        wordlists_file=args.wordlists
    )

    # Phase 1: Directory Enumeration
    if not args.no_enum:
        found_dirs = crawler.enumerate_directories()
        base_paths = [d[0] for d in found_dirs if d[1] == 200]
        crawler.enumerate_files(base_paths if base_paths else None)

    # Phase 2: Crawl and Analyze
    crawler.crawl()

    # Phase 3: Generate Report
    output_file = args.output or f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report = crawler.generate_report(output_file)
    crawler.print_summary(report)

    print(f"\n[+] Scan complete! Report saved to: {output_file}")

    # Return exit code based on findings
    if report['summary']['critical'] > 0:
        sys.exit(2)
    elif report['summary']['high'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()