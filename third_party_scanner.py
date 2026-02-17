import re
import os
from urllib.parse import urlparse


class ThirdPartyScanner:
    """Static detector for third-party libraries, external services, and insecure dependencies."""

    def __init__(self, base_domain):
        self.base_domain = base_domain.lower()

    def analyze(self, html_content, page_url):
        findings = []
        findings.extend(self._detect_js_css_libraries(html_content, page_url))
        findings.extend(self._detect_external_services(html_content, page_url))
        findings.extend(self._detect_insecure_dependencies(html_content, page_url))
        return findings

    def _detect_js_css_libraries(self, html, page_url):
        results = []

        patterns = [
            r'<script[^>]+src=["\']([^"\']+)["\']',
            r'<link[^>]+href=["\']([^"\']+)["\']'
        ]

        known_libs = [
            'jquery',
            'bootstrap',
            'axios',
            'react',
            'vue',
            'angular'
        ]

        for pattern in patterns:
            for src in re.findall(pattern, html, re.IGNORECASE):
                lib_name = 'unknown'
                for lib in known_libs:
                    if lib in src.lower():
                        lib_name = lib
                        break

                results.append({
                    'type': 'THIRD_PARTY_LIBRARY',
                    'name': lib_name,
                    'version': 'unknown',
                    'severity': 'LOW',
                    'description': 'Third-party frontend library detected',
                    'url': page_url,
                    'line': 0,
                    'code_snippet': src[:100]
                })

        return results

    def _detect_external_services(self, html, page_url):
        results = []

        urls = re.findall(r'https?://[^\s"\'<>]+', html)

        for endpoint in urls:
            parsed = urlparse(endpoint)
            domain = parsed.netloc.lower()

            if domain and self.base_domain not in domain:
                results.append({
                    'type': 'EXTERNAL_SERVICE',
                    'name': domain,
                    'severity': 'LOW',
                    'description': 'External third-party service detected',
                    'url': page_url,
                    'line': 0,
                    'code_snippet': endpoint[:100]
                })

        return results

    def _detect_insecure_dependencies(self, html, page_url):
        results = []
        is_https_page = page_url.startswith("https://")

        http_resources = re.findall(r'(http://[^\s"\'<>]+)', html)

        for resource in http_resources:
            results.append({
                'type': 'INSECURE_DEPENDENCY',
                'name': 'http_resource',
                'severity': 'MEDIUM' if is_https_page else 'LOW',
                'description': 'Insecure external resource loaded over HTTP',
                'url': page_url,
                'line': 0,
                'code_snippet': resource[:100]
            })

        return results
