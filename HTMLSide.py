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

class WebVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.forms = []
        
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
        
        # Check page-wide vulnerabilities
        print(f"\n{'='*70}")
        print(f"  ANALYZING PAGE-WIDE VULNERABILITIES")
        print(f"{'='*70}")
        all_vulnerabilities.extend(self.check_xss_vulnerability(html_content, soup))
        all_vulnerabilities.extend(self.check_information_disclosure(html_content, soup))
        
        # Display results
        self.display_results(all_vulnerabilities)
    
    def get_specific_recommendations(self, vulnerabilities):
        """Generate specific, actionable recommendations based on detected vulnerabilities."""
        REMEDIATION_MAP = {
            'XSS Vulnerability - innerHTML': {
                'title': 'Fix Unsafe innerHTML Usage',
                'steps': [
                    "Replace `element.innerHTML = userInput` with `element.textContent = userInput`",
                    "If HTML rendering is needed, sanitize first:\n         element.innerHTML = DOMPurify.sanitize(userInput);  // https://github.com/cure53/DOMPurify",
                ],
                'example': (
                    "// VULNERABLE:\n"
                    "         output.innerHTML = document.getElementById('name').value;\n\n"
                    "         // SAFE (plain text):\n"
                    "         output.textContent = document.getElementById('name').value;\n\n"
                    "         // SAFE (HTML allowed):\n"
                    "         output.innerHTML = DOMPurify.sanitize(document.getElementById('name').value);"
                )
            },
            'XSS Vulnerability - Template Literal Injection': {
                'title': 'Fix Template Literal XSS in innerHTML',
                'steps': [
                    "Never interpolate user values directly into innerHTML template literals",
                    "Build DOM nodes with createElement + textContent instead of HTML strings",
                ],
                'example': (
                    "// VULNERABLE:\n"
                    "         container.innerHTML = `<p>Hello ${nameInput.value}</p>`;\n\n"
                    "         // SAFE:\n"
                    "         const p = document.createElement('p');\n"
                    "         p.textContent = `Hello ${nameInput.value}`;\n"
                    "         container.appendChild(p);"
                )
            },
            'Code Injection - eval()': {
                'title': 'Remove eval() — High Risk of Arbitrary Code Execution',
                'steps': [
                    "Delete all eval() calls — there is almost never a valid use case",
                    "For math expressions, use a safe parser such as mathjs (https://mathjs.org)",
                    "Add Content-Security-Policy header without 'unsafe-eval' to block it at browser level",
                ],
                'example': (
                    "// VULNERABLE:\n"
                    "         eval('result = ' + userInput);\n\n"
                    "         // SAFE (math):\n"
                    "         import { evaluate } from 'mathjs';\n"
                    "         const result = evaluate(userInput);"
                )
            },
            'XSS Vulnerability - document.write': {
                'title': 'Replace document.write() with Safe DOM Methods',
                'steps': [
                    "Remove all document.write() calls",
                    "Use createElement / textContent / appendChild to inject content safely",
                ],
                'example': (
                    "// VULNERABLE:\n"
                    "         document.write('<p>' + userInput + '</p>');\n\n"
                    "         // SAFE:\n"
                    "         const p = document.createElement('p');\n"
                    "         p.textContent = userInput;\n"
                    "         document.body.appendChild(p);"
                )
            },
            'Missing CSRF Protection': {
                'title': 'Add CSRF Token to Every POST Form',
                'steps': [
                    "Generate a cryptographically random token server-side per session",
                    "Embed it as a hidden field: <input type=\"hidden\" name=\"csrf_token\" value=\"{{ token }}\">",
                    "Reject any POST request where the submitted token does not match the session token",
                    "Set session cookie with SameSite=Strict or Lax as an additional defence layer",
                ],
                'example': (
                    "<!-- VULNERABLE: -->\n"
                    "         <form method=\"POST\" action=\"/submit\"> ... </form>\n\n"
                    "         <!-- SAFE: -->\n"
                    "         <form method=\"POST\" action=\"/submit\">\n"
                    "           <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\">\n"
                    "           ...\n"
                    "         </form>"
                )
            },
            'Client-Side Only Validation': {
                'title': 'Add a Real Server-Side Validation Endpoint',
                'steps': [
                    "Set a real server URL in the form action attribute (not '#' or empty)",
                    "Re-validate and sanitize ALL fields on the server — JS checks can be disabled",
                    "Return structured error responses from the server (do not rely solely on JS alerts)",
                ],
                'example': (
                    "<!-- VULNERABLE: -->\n"
                    "         <form action=\"#\" onsubmit=\"return validate()\">\n\n"
                    "         <!-- SAFE: -->\n"
                    "         <form action=\"/api/submit\" method=\"POST\">\n"
                    "           <!-- server validates independently of any client-side JS -->"
                )
            },
            'Missing Required Validation': {
                'title': 'Mark Mandatory Fields as Required',
                'steps': [
                    "Add the `required` attribute to every field that must not be empty",
                    "Also enforce presence server-side — the HTML attribute can be stripped by attackers",
                ],
                'example': (
                    "<!-- VULNERABLE: -->\n"
                    "         <input type=\"text\" name=\"username\">\n\n"
                    "         <!-- SAFE: -->\n"
                    "         <input type=\"text\" name=\"username\" required>"
                )
            },
            'Missing Email Validation': {
                'title': 'Enforce Email Format Validation',
                'steps': [
                    "Add a pattern attribute with an email regex to the input element",
                    "Validate email format server-side using a trusted library",
                ],
                'example': (
                    "<!-- VULNERABLE: -->\n"
                    "         <input type=\"email\" name=\"email\">\n\n"
                    "         <!-- SAFE: -->\n"
                    "         <input type=\"email\" name=\"email\" required\n"
                    "                pattern=\"[a-z0-9._%+\\-]+@[a-z0-9.\\-]+\\.[a-z]{2,}\">"
                )
            },
            'Missing Phone Validation': {
                'title': 'Add Phone Number Pattern Constraint',
                'steps': [
                    "Add a pattern attribute matching your expected phone number format",
                    "Include a title attribute so the browser can show the user a helpful error",
                    "Strip or reject unexpected characters on the server before storing the value",
                ],
                'example': (
                    "<!-- VULNERABLE: -->\n"
                    "         <input type=\"tel\" name=\"phone\">\n\n"
                    "         <!-- SAFE: -->\n"
                    "         <input type=\"tel\" name=\"phone\" required\n"
                    "                pattern=\"[0-9]{8,15}\" title=\"8 to 15 digit phone number\">"
                )
            },
            'Missing Number Range Validation': {
                'title': 'Constrain Number Fields with min and max',
                'steps': [
                    "Add min and max attributes to the number input",
                    "Re-enforce the range server-side — HTML attributes are client-only",
                ],
                'example': (
                    "<!-- VULNERABLE: -->\n"
                    "         <input type=\"number\" name=\"age\">\n\n"
                    "         <!-- SAFE: -->\n"
                    "         <input type=\"number\" name=\"age\" min=\"1\" max=\"120\" required>"
                )
            },
            'Missing Length Limit': {
                'title': 'Restrict Maximum Input Length',
                'steps': [
                    "Add the maxlength attribute to all text, email, and tel inputs",
                    "Enforce the same limit server-side before storing data to the database",
                ],
                'example': (
                    "<!-- VULNERABLE: -->\n"
                    "         <input type=\"text\" name=\"username\">\n\n"
                    "         <!-- SAFE: -->\n"
                    "         <input type=\"text\" name=\"username\" maxlength=\"50\" required>"
                )
            },
            'Information Disclosure': {
                'title': 'Remove Sensitive Data from console.log / alert',
                'steps': [
                    "Remove all console.log / console.debug calls that print passwords, tokens, or PII",
                    "Use a build tool (e.g. terser --drop-console) to strip logs automatically in production",
                    "Never log sensitive form values client-side — use server-side structured logging instead",
                ],
                'example': (
                    "// VULNERABLE:\n"
                    "         console.log('Password:', passwordField.value);\n\n"
                    "         // SAFE:\n"
                    "         // Remove the log, or guard it:\n"
                    "         if (process.env.NODE_ENV !== 'production') console.log('Form submitted');"
                )
            },
            'Information Disclosure - Alert': {
                'title': 'Do Not Display Sensitive Values in alert()',
                'steps': [
                    "Replace alert() calls that expose token/password values with a generic user message",
                    "Log diagnostic details server-side where users cannot access them",
                ],
                'example': (
                    "// VULNERABLE:\n"
                    "         alert('Your token: ' + token);\n\n"
                    "         // SAFE:\n"
                    "         alert('Action completed successfully.');"
                )
            },
        }

        recommendations = []
        seen_titles = set()

        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            field = vuln['field']

            entry = REMEDIATION_MAP.get(vuln_type)
            if not entry:
                for key, val in REMEDIATION_MAP.items():
                    if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
                        entry = val
                        break

            if entry:
                title = entry['title']
                if title in seen_titles:
                    continue
                seen_titles.add(title)
                recommendations.append({
                    'title': title,
                    'affected_field': field,
                    'steps': entry['steps'],
                    'example': entry['example'],
                })
            else:
                title = f"Fix: {vuln_type}"
                if title not in seen_titles:
                    seen_titles.add(title)
                    recommendations.append({
                        'title': title,
                        'affected_field': field,
                        'steps': [
                            f"Review '{field}' for: {vuln['description']}",
                            "Validate and sanitize all user-supplied input before use",
                        ],
                        'example': None,
                    })

        return recommendations


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
        
        # Provide specific, actionable recommendations based on actual findings
        recommendations = self.get_specific_recommendations(vulnerabilities)

        print(f"\n{'='*70}")
        print("  REMEDIATION RECOMMENDATIONS")
        print(f"{'='*70}")
        print(f"  {len(recommendations)} specific fix(es) required based on the findings above\n")

        for idx, rec in enumerate(recommendations, 1):
            print(f"  [{idx}] {rec['title']}")
            print(f"       Affected: {rec['affected_field']}")
            print(f"       Steps:")
            for step_num, step in enumerate(rec['steps'], 1):
                print(f"         {step_num}. {step}")
            if rec['example']:
                print(f"       Example:")
                for line in rec['example'].splitlines():
                    print(f"         {line}")
            print()

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
