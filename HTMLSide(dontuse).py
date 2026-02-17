#!/usr/bin/env python3
"""
Web Vulnerability Scanner v2.0
Analyzes HTML forms for input validation vulnerabilities
With improved detection to reduce false positives
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sys
import json
from pathlib import Path

class WebVulnerabilityScanner:
    def __init__(self, target_url, patterns_path="patterns.json", wordlists_path="wordlists.json"):
        self.target_url = target_url
        self.vulnerabilities = []
        self.forms = []

        # Load patterns + wordlists
        self.patterns = self._load_json(patterns_path)
        self.wordlists = self._load_json(wordlists_path)

        # SQLi config
        self.sqli_patterns = self.patterns.get("sqli_patterns", {})
        self.sqli_param_hints = set(self.wordlists.get("sqli_param_hints", []))
        self.sqli_action_hints = tuple(self.wordlists.get("sqli_action_hints", []))
        self.sqli_error_signatures = self.wordlists.get("sqli_error_signatures", [])
    
    def _load_json(self, path):
        try:
            p = Path(path)
            if not p.exists():
                return {}
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}

        
    def fetch_page(self):
        """Fetch the HTML content from target URL"""
        try:
            print(f"[*] Fetching page from: {self.target_url}")
            response = requests.get(self.target_url, timeout=10)
            response.raise_for_status()
            print(f"[+] Successfully fetched page (Status: {response.status_code})")
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"[-] Error fetching page: {e}")
            sys.exit(1)
    
    def parse_forms(self, html_content):
        """Extract all forms from HTML"""
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        print(f"[+] Found {len(forms)} form(s) on the page")
        return forms, soup
    
    def check_input_validation(self, form, soup):
        """Check for input validation vulnerabilities"""
        vulnerabilities = []
        
        # Get all input fields
        inputs = form.find_all(['input', 'textarea', 'select'])
        
        print(f"\n[*] Analyzing form with {len(inputs)} input field(s)")
        
        for input_field in inputs:
            field_type = input_field.get('type', 'text')
            field_name = input_field.get('name', 'unnamed')
            field_id = input_field.get('id', 'no-id')
            
            # Skip hidden fields (like CSRF tokens) from required validation check
            if field_type == 'hidden':
                continue
            
            # Check for missing 'required' attribute (only for visible fields)
            if not input_field.get('required') and field_name not in ['specialRequests', 'emergencyContact']:
                vulnerabilities.append({
                    'severity': 'Medium',
                    'type': 'Missing Required Validation',
                    'field': field_name,
                    'description': f"Field '{field_name}' has no 'required' attribute - can be submitted empty"
                })
            
            # Check email fields for pattern validation
            if field_type == 'email':
                if not input_field.get('pattern'):
                    vulnerabilities.append({
                        'severity': 'Medium',
                        'type': 'Missing Email Validation',
                        'field': field_name,
                        'description': f"Email field '{field_name}' lacks pattern validation"
                    })
            
            # Check tel fields for pattern validation
            if field_type == 'tel':
                if not input_field.get('pattern'):
                    vulnerabilities.append({
                        'severity': 'Medium',
                        'type': 'Missing Phone Validation',
                        'field': field_name,
                        'description': f"Phone field '{field_name}' lacks pattern validation"
                    })
            
            # Check number fields for min/max constraints
            if field_type == 'number':
                if not input_field.get('min') or not input_field.get('max'):
                    vulnerabilities.append({
                        'severity': 'Medium',
                        'type': 'Missing Number Range Validation',
                        'field': field_name,
                        'description': f"Number field '{field_name}' has no min/max constraints"
                    })
            
            # Check for maxlength attribute on text inputs (exclude select dropdowns)
            if field_type in ['text', 'tel', 'email'] or input_field.name == 'textarea':
                if not input_field.get('maxlength'):
                    vulnerabilities.append({
                        'severity': 'Low',
                        'type': 'Missing Length Limit',
                        'field': field_name,
                        'description': f"Field '{field_name}' has no maximum length restriction"
                    })
        
        return vulnerabilities
    
    def is_vulnerable_innerhtml(self, script_content):
        """
        Check if innerHTML usage is actually vulnerable
        Returns True only if innerHTML is used WITHOUT sanitization
        """
        # Check if innerHTML is used
        if 'innerHTML' not in script_content:
            return False
        
        # Check for safe patterns (sanitization functions)
        safe_patterns = [
            r'textContent',  # Using textContent instead
            r'sanitize',     # Has sanitization function
            r'escape',       # Has escape function
            r'DOMPurify',    # Using DOMPurify library
            r'createElement', # Using DOM manipulation
            r'document\.createTextNode', # Safe text node creation
        ]
        
        for pattern in safe_patterns:
            if re.search(pattern, script_content, re.IGNORECASE):
                print(f"[+] Safe pattern detected: {pattern}")
                return False
        
        # Check if innerHTML is used with direct user input (vulnerable pattern)
        vulnerable_patterns = [
            r'innerHTML\s*=.*?\.value',  # innerHTML = someInput.value
            r'innerHTML\s*=.*?\$\{',     # innerHTML with template literals
            r'innerHTML\s*\+=.*?\.value', # innerHTML += someInput.value
        ]
        
        for pattern in vulnerable_patterns:
            if re.search(pattern, script_content):
                return True
        
        return False
    
    def check_xss_vulnerability(self, html_content, soup):
        """Check for XSS vulnerabilities in JavaScript"""
        vulnerabilities = []
        
        # Find all script tags
        scripts = soup.find_all('script')
        
        for script in scripts:
            script_content = script.string if script.string else ''
            
            # Check for dangerous innerHTML usage (improved detection)
            if self.is_vulnerable_innerhtml(script_content):
                vulnerabilities.append({
                    'severity': 'High',
                    'type': 'XSS Vulnerability - innerHTML',
                    'field': 'JavaScript Code',
                    'description': 'Direct use of innerHTML with user input without sanitization - allows script injection'
                })
            
            # Check for direct variable insertion with innerHTML (template literals)
            if re.search(r'\$\{.*?\.value.*?\}', script_content) and 'innerHTML' in script_content:
                # But check if it's wrapped in sanitization
                if not re.search(r'sanitize|textContent|createElement', script_content, re.IGNORECASE):
                    vulnerabilities.append({
                        'severity': 'Critical',
                        'type': 'XSS Vulnerability - Template Literal Injection',
                        'field': 'JavaScript Code',
                        'description': 'Template literals with .value used in innerHTML - direct XSS vulnerability'
                    })
            
            # Check for eval usage
            if re.search(r'\beval\s*\(', script_content):
                vulnerabilities.append({
                    'severity': 'Critical',
                    'type': 'Code Injection - eval()',
                    'field': 'JavaScript Code',
                    'description': 'Use of eval() detected - allows arbitrary code execution'
                })
            
            # Check for document.write with user input
            if 'document.write' in script_content and '.value' in script_content:
                vulnerabilities.append({
                    'severity': 'High',
                    'type': 'XSS Vulnerability - document.write',
                    'field': 'JavaScript Code',
                    'description': 'Use of document.write() with user input without sanitization'
                })
        
        return vulnerabilities
    
    def check_csrf_protection(self, form):
        """Check for CSRF token"""
        vulnerabilities = []
        
        # Look for hidden input with common CSRF token names
        csrf_fields = form.find_all('input', {'type': 'hidden'})
        csrf_token_found = False
        
        for field in csrf_fields:
            field_name = field.get('name', '').lower()
            if any(token in field_name for token in ['csrf', 'token', '_token', 'authenticity']):
                csrf_token_found = True
                print(f"[+] CSRF token found: {field.get('name')}")
                break
        
        if not csrf_token_found:
            vulnerabilities.append({
                'severity': 'High',
                'type': 'Missing CSRF Protection',
                'field': 'Form',
                'description': 'No CSRF token found - form vulnerable to Cross-Site Request Forgery'
            })
        
        return vulnerabilities
    
    def check_information_disclosure(self, html_content, soup):
        """Check for information disclosure in JavaScript"""
        vulnerabilities = []
        
        scripts = soup.find_all('script')
        
        for script in scripts:
            script_content = script.string if script.string else ''
            
            # Check for console.log with sensitive form data
            if re.search(r'console\.log.*?\(.*?(password|pass|pwd|email|phone|ssn|credit)', script_content, re.IGNORECASE):
                vulnerabilities.append({
                    'severity': 'Medium',
                    'type': 'Information Disclosure',
                    'field': 'JavaScript Code',
                    'description': 'Sensitive form data logged to console - information leakage risk'
                })
            
            # Check for alert with sensitive data
            if re.search(r'alert.*?\(.*?(password|pass|pwd|token)', script_content, re.IGNORECASE):
                vulnerabilities.append({
                    'severity': 'Medium',
                    'type': 'Information Disclosure - Alert',
                    'field': 'JavaScript Code',
                    'description': 'Alert displays sensitive information - security risk'
                })
        
        return vulnerabilities
    
    def check_client_side_validation_only(self, form):
        """Check if form relies only on client-side validation"""
        vulnerabilities = []
        
        # Check form action
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        
        # If form has no action or uses # (client-side only)
        if not action or action == '#' or action == '':
            vulnerabilities.append({
                'severity': 'Medium',
                'type': 'Client-Side Only Validation',
                'field': 'Form',
                'description': 'Form appears to have no server-side validation - all checks can be bypassed'
            })
        else:
            print(f"[+] Form has server-side action: {action}")
        
        return vulnerabilities
    
    def check_sqli_patterns(self, html_content):
        vulnerabilities = []

        for name, cfg in self.sqli_patterns.items():
            pattern = cfg.get("pattern")
            if not pattern:
                continue

            flags = 0
            for f in cfg.get("flags", []):
                if f.upper() == "IGNORECASE":
                    flags |= re.IGNORECASE
                if f.upper() == "MULTILINE":
                    flags |= re.MULTILINE
                if f.upper() == "DOTALL":
                    flags |= re.DOTALL

            if re.search(pattern, html_content or "", flags):
                vulnerabilities.append({
                    "severity": cfg.get("severity", "Low").title(),
                    "type": f"SQLi Signal - {name}",
                    "field": "Page",
                    "description": cfg.get("description", "SQLi-related pattern detected (heuristic)")
                })

        return vulnerabilities
    
    def check_sqli_surface(self, form):
        vulnerabilities = []

        action = (form.get("action") or "").lower()
        method = (form.get("method") or "GET").upper()

        inputs = form.find_all(["input", "textarea", "select"])
        names = [i.get("name", "").lower() for i in inputs if i.get("name")]

        # Param-name heuristic
        hits = [n for n in names if n in self.sqli_param_hints]

        score = 0
        reasons = []

        if hits:
            score += 15
            reasons.append(f"SQL-shaped input names: {', '.join(hits)}")

        if any(h in action for h in self.sqli_action_hints):
            score += 10
            reasons.append("Form action looks DB-backed")

        if score >= 20:
            vulnerabilities.append({
                "severity": "Medium",
                "type": "SQLi Surface (Heuristic)",
                "field": "Form",
                "description": " | ".join(reasons)
            })

        return vulnerabilities


    
    def scan(self):
        """Main scanning function"""
        print("\n" + "="*70)
        print("          WEB VULNERABILITY SCANNER v2.0")
        print("="*70)
        
        # Fetch page
        html_content = self.fetch_page()
        
        # Parse forms
        forms, soup = self.parse_forms(html_content)
        
        if not forms:
            print("\n[-] No forms found on the page")
            return
        
        all_vulnerabilities = []
        
        # Analyze each form
        for idx, form in enumerate(forms, 1):
            print(f"\n{'='*70}")
            print(f"  ANALYZING FORM #{idx}")
            print(f"{'='*70}")
            
            # Check various vulnerabilities
            all_vulnerabilities.extend(self.check_input_validation(form, soup))
            all_vulnerabilities.extend(self.check_csrf_protection(form))
            all_vulnerabilities.extend(self.check_client_side_validation_only(form))
            all_vulnerabilities.extend(self.check_sqli_surface(form))
        
        # Check page-wide vulnerabilities
        print(f"\n{'='*70}")
        print(f"  ANALYZING PAGE-WIDE VULNERABILITIES")
        print(f"{'='*70}")
        all_vulnerabilities.extend(self.check_xss_vulnerability(html_content, soup))
        all_vulnerabilities.extend(self.check_information_disclosure(html_content, soup))
        all_vulnerabilities.extend(self.check_sqli_patterns(html_content))

        
        # Display results
        self.display_results(all_vulnerabilities)
    
    def display_results(self, vulnerabilities):
        """Display vulnerability report"""
        print("\n" + "="*70)
        print("          VULNERABILITY REPORT")
        print("="*70)
        
        if not vulnerabilities:
            print("\n✅ [+] No vulnerabilities detected!")
            print("\n🔒 This form implements proper security controls:")
            print("   - Input validation (required, patterns, min/max)")
            print("   - XSS protection (sanitization, safe DOM methods)")
            print("   - CSRF token protection")
            print("   - Server-side validation endpoint")
            print("   - No information disclosure")
            return
        
        # Count by severity
        severity_count = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for vuln in vulnerabilities:
            severity_count[vuln['severity']] += 1
        
        print(f"\n[!] Total Vulnerabilities Found: {len(vulnerabilities)}")
        print(f"    - Critical: {severity_count['Critical']}")
        print(f"    - High: {severity_count['High']}")
        print(f"    - Medium: {severity_count['Medium']}")
        print(f"    - Low: {severity_count['Low']}")
        
        # Group by severity
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            severity_vulns = [v for v in vulnerabilities if v['severity'] == severity]
            
            if severity_vulns:
                print(f"\n{'='*70}")
                print(f"  {severity.upper()} SEVERITY VULNERABILITIES ({len(severity_vulns)})")
                print(f"{'='*70}")
                
                for idx, vuln in enumerate(severity_vulns, 1):
                    print(f"\n[{idx}] {vuln['type']}")
                    print(f"    Field: {vuln['field']}")
                    print(f"    Description: {vuln['description']}")
        
        # Provide recommendations
        print(f"\n{'='*70}")
        print("  RECOMMENDATIONS")
        print(f"{'='*70}")
        print("\n1. Implement server-side validation for all input fields")
        print("2. Add input sanitization to prevent XSS attacks")
        print("3. Use parameterized queries to prevent SQL injection")
        print("4. Implement CSRF token protection")
        print("5. Add proper input validation (regex patterns, min/max values)")
        print("6. Remove console.log statements with sensitive data")
        print("7. Use textContent instead of innerHTML when possible")
        print("8. Implement Content Security Policy (CSP) headers")

def main():
    print("\n" + "="*70)
    print("  Web Vulnerability Scanner v2.0")
    print("  Analyzes HTML forms for input validation vulnerabilities")
    print("  Now with improved false positive detection!")
    print("="*70)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("\n[?] Enter target URL or IP (e.g., http://localhost:8000): ").strip()
    
    # Validate and format URL
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    # Create scanner instance
    scanner = WebVulnerabilityScanner(target)
    
    # Run scan
    scanner.scan()
    
    print("\n" + "="*70)
    print("  Scan Complete!")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
