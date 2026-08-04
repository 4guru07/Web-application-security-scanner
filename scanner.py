import socket
import ssl
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
import urllib3

# Suppress SSL warnings for auditing legacy/untrusted sites safely
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PassiveScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.hostname
        self.port = self.parsed_url.port or (443 if self.parsed_url.scheme == 'https' else 80)
        self.findings = []
        self.header_audits = []
        self.ssl_info = {}
        self.response = None
        self.connection_failed = False

    def run_full_scan(self):
        start_time = time.time()
        
        # Standard Browser User-Agent and Chrome Sec-Fetch Request Headers
        req_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Sec-Ch-Ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Upgrade-Insecure-Requests': '1'
        }

        # 1. Fetch target response safely with HTTP/HTTPS fallback
        try:
            self.response = requests.get(self.target_url, headers=req_headers, timeout=12, allow_redirects=True, verify=False)
        except Exception as primary_error:
            # Fallback: If HTTPS failed, attempt plain HTTP connection
            if self.target_url.startswith('https://'):
                fallback_url = 'http://' + self.target_url[8:]
                try:
                    self.response = requests.get(fallback_url, headers=req_headers, timeout=12, allow_redirects=True)
                    self.target_url = fallback_url
                    self.parsed_url = urlparse(fallback_url)
                    self.hostname = self.parsed_url.hostname
                    self.port = 80
                except Exception:
                    pass

        if not self.response:
            self.connection_failed = True
            self.findings.append({
                'title': 'Target Connectivity Failure',
                'category': 'Connectivity',
                'severity': 'High',
                'description': 'Failed to establish HTTP/HTTPS connection to target server. Target is down, unreachable, or actively blocking requests.',
                'recommendation': 'Verify target URL, web server status, DNS resolution, and firewall / WAF bot blocking rules.',
                'details': f'Target URL: {self.target_url}'
            })
            duration = round(time.time() - start_time, 2)
            return self._format_results(duration, 0, "Unreachable")

        # Update parsed target URL if redirects occurred
        if self.response.url:
            self.target_url = self.response.url
            self.parsed_url = urlparse(self.response.url)
            self.hostname = self.parsed_url.hostname
            self.port = self.parsed_url.port or (443 if self.parsed_url.scheme == 'https' else 80)

        # 2. HTTP Security Header Audit (Severity aligned with Pentest-Tools Industry Benchmark)
        self._audit_security_headers()

        # 3. SSL/TLS Audit
        self._audit_ssl()

        # 4. Cookie Security Flag Audit
        self._audit_cookies()

        # 5. Form & CSRF Configuration Check
        self._audit_forms_and_csrf()

        # 6. Robots.txt Compliance Check
        self._audit_robots_txt()

        duration = round(time.time() - start_time, 2)
        score, grade = self._calculate_score()
        return self._format_results(duration, score, grade)

    def _audit_security_headers(self):
        headers = self.response.headers if self.response else {}

        # Severity definitions aligned with Pentest-Tools & OWASP Light Scanner Standard
        security_headers_spec = {
            'Content-Security-Policy': {
                'severity': 'Medium',
                'desc': 'Content-Security-Policy (CSP) header is missing. CSP helps prevent XSS and data injection attacks.',
                'rec': 'Configure a strong CSP header restricting trusted content sources.'
            },
            'Strict-Transport-Security': {
                'severity': 'Medium',
                'desc': 'HTTP Strict Transport Security (HSTS) header is missing. HSTS enforces encrypted HTTPS connections.',
                'rec': 'Enable HSTS with max-age set to at least 31536000 seconds.'
            },
            'X-Frame-Options': {
                'severity': 'Low',
                'desc': 'X-Frame-Options header is missing. Pages can be embedded in frames, exposing users to Clickjacking.',
                'rec': 'Set X-Frame-Options to DENY or SAMEORIGIN.'
            },
            'X-Content-Type-Options': {
                'severity': 'Low',
                'desc': 'X-Content-Type-Options header is missing. Browsers may MIME-sniff response types.',
                'rec': 'Set X-Content-Type-Options to nosniff.'
            },
            'Referrer-Policy': {
                'severity': 'Low',
                'desc': 'Referrer-Policy header is missing or improperly configured.',
                'rec': 'Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.'
            },
            'Permissions-Policy': {
                'severity': 'Low',
                'desc': 'Permissions-Policy header is missing. Browser features like camera/location are not restricted.',
                'rec': 'Explicitly define permitted browser APIs via Permissions-Policy.'
            }
        }

        for header, spec in security_headers_spec.items():
            val = headers.get(header)
            if val:
                self.header_audits.append({
                    'header_name': header,
                    'status': 'Present',
                    'header_value': val[:200],
                    'recommendation': 'Header correctly implemented.'
                })
            else:
                self.header_audits.append({
                    'header_name': header,
                    'status': 'Missing',
                    'header_value': None,
                    'recommendation': spec['rec']
                })
                self.findings.append({
                    'title': f'Missing Security Header: {header}',
                    'category': 'HTTP Security Headers',
                    'severity': spec['severity'],
                    'description': spec['desc'],
                    'recommendation': spec['rec'],
                    'details': f'Header `{header}` was not returned in HTTP server response.'
                })

    def _audit_ssl(self):
        is_https = self.parsed_url.scheme == 'https'
        ssl_audit_data = {
            'is_https': is_https,
            'certificate_valid': False,
            'issuer': 'N/A',
            'expiry_date': 'N/A',
            'details': ''
        }

        if not is_https:
            self.findings.append({
                'title': 'Unencrypted HTTP Transport',
                'category': 'Transport Security',
                'severity': 'High',
                'description': 'Target site operates over plain HTTP. Data in transit is vulnerable to eavesdropping and MITM attacks.',
                'recommendation': 'Migrate web traffic to HTTPS using TLS certificates.',
                'details': f'URL scheme is plain HTTP ({self.target_url})'
            })
            ssl_audit_data['details'] = 'Site is operating over plain unencrypted HTTP.'
            self.ssl_info = ssl_audit_data
            return

        # HTTPS SSL Socket Validation
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port), timeout=6) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    issuer = issuer_dict.get('organizationName') or issuer_dict.get('commonName', 'Unknown Authority')
                    not_after = cert.get('notAfter')

                    ssl_audit_data['certificate_valid'] = True
                    ssl_audit_data['issuer'] = str(issuer)
                    ssl_audit_data['expiry_date'] = str(not_after)
                    ssl_audit_data['details'] = f'TLS Certificate issued by {issuer}, valid until {not_after}.'
        except Exception as e:
            ssl_audit_data['certificate_valid'] = False
            ssl_audit_data['details'] = f'SSL Handshake / Certificate Error: {str(e)}'
            self.findings.append({
                'title': 'Invalid or Misconfigured SSL/TLS Certificate',
                'category': 'Transport Security',
                'severity': 'High',
                'description': f'Failed to validate SSL/TLS certificate: {str(e)}',
                'recommendation': 'Ensure target has a valid, non-expired TLS certificate from a trusted Certificate Authority.',
                'details': str(e)
            })

        self.ssl_info = ssl_audit_data

    def _audit_cookies(self):
        if not self.response:
            return

        cookies = self.response.cookies
        for cookie in cookies:
            cookie_name = cookie.name
            is_httponly = cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly') or getattr(cookie, 'httponly', False)
            is_secure = cookie.secure

            if not is_httponly:
                self.findings.append({
                    'title': f'Cookie Missing HttpOnly Flag: {cookie_name}',
                    'category': 'Cookie Security',
                    'severity': 'Low',
                    'description': f'Cookie `{cookie_name}` is accessible via client-side JavaScript, exposing it to potential theft via Cross-Site Scripting (XSS).',
                    'recommendation': 'Set the HttpOnly flag on sensitive cookies.',
                    'details': f'Cookie Name: {cookie_name}'
                })

            if not is_secure and self.parsed_url.scheme == 'https':
                self.findings.append({
                    'title': f'Cookie Missing Secure Flag: {cookie_name}',
                    'category': 'Cookie Security',
                    'severity': 'Low',
                    'description': f'Cookie `{cookie_name}` is transmitted over unencrypted HTTP requests.',
                    'recommendation': 'Set the Secure flag on all cookies when operating over HTTPS.',
                    'details': f'Cookie Name: {cookie_name}'
                })

    def _audit_forms_and_csrf(self):
        if not self.response or 'text/html' not in self.response.headers.get('Content-Type', ''):
            return

        soup = BeautifulSoup(self.response.text, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            return

        for idx, form in enumerate(forms, 1):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            # Check for anti-CSRF token input
            csrf_token_found = False
            for inp in inputs:
                name_attr = inp.get('name', '').lower()
                id_attr = inp.get('id', '').lower()
                if any(k in name_attr or k in id_attr for k in ['csrf', 'token', 'xsrf', '_token']):
                    csrf_token_found = True
                    break

            if method == 'post' and not csrf_token_found:
                self.findings.append({
                    'title': f'Form #{idx} Missing Anti-CSRF Token Indicator',
                    'category': 'Form Security',
                    'severity': 'Medium',
                    'description': f'Form #{idx} uses POST method but lacks a recognized anti-CSRF token parameter.',
                    'recommendation': 'Implement anti-CSRF tokens for all state-changing HTML forms.',
                    'details': f'Form Action: {action or "(self)"}, Method: POST'
                })

            # Insecure Form Action URL
            full_action_url = urljoin(self.target_url, action)
            if full_action_url.startswith('http://') and self.parsed_url.scheme == 'https':
                self.findings.append({
                    'title': f'Form #{idx} Submits to Unencrypted HTTP Destination',
                    'category': 'Form Security',
                    'severity': 'High',
                    'description': f'Form #{idx} target URL ({full_action_url}) uses insecure HTTP transmission.',
                    'recommendation': 'Ensure all form submission targets use HTTPS.',
                    'details': f'Action URL: {full_action_url}'
                })

    def _audit_robots_txt(self):
        robots_url = urljoin(self.target_url, '/robots.txt')
        try:
            res = requests.get(robots_url, timeout=5, verify=False)
            if res.status_code == 200:
                lines = res.text.splitlines()
                disallowed_paths = [line.split(':')[1].strip() for line in lines if line.lower().startswith('disallow:')]
                
                if disallowed_paths:
                    sensitive_keywords = ['admin', 'backup', 'db', 'private', 'config', 'api', 'v1', 'secret']
                    found_exposed = [p for p in disallowed_paths if any(k in p.lower() for k in sensitive_keywords)]
                    
                    if found_exposed:
                        self.findings.append({
                            'title': 'Sensitive Path Disclosed in robots.txt',
                            'category': 'Information Disclosure',
                            'severity': 'Low',
                            'description': f'Robots.txt discloses sensitive pathways: {", ".join(found_exposed[:5])}',
                            'recommendation': 'Avoid relying on robots.txt to restrict access to sensitive routes. Use proper authentication.',
                            'details': f'Disallowed routes identified: {", ".join(disallowed_paths[:10])}'
                        })
        except Exception:
            pass

    def _calculate_score(self):
        if self.connection_failed:
            return 0, "Unreachable"

        # Initial baseline 100
        score = 100
        for f in self.findings:
            sev = f['severity']
            if sev == 'High':
                score -= 15
            elif sev == 'Medium':
                score -= 5
            elif sev == 'Low':
                score -= 2

        score = max(0, min(100, score))

        if score >= 90:
            grade = "Excellent"
        elif score >= 70:
            grade = "Good"
        elif score >= 50:
            grade = "Moderate"
        else:
            grade = "Poor"

        return score, grade

    def _format_results(self, duration, score, grade):
        high_c = sum(1 for f in self.findings if f['severity'] == 'High')
        med_c = sum(1 for f in self.findings if f['severity'] == 'Medium')
        low_c = sum(1 for f in self.findings if f['severity'] == 'Low')

        return {
            'target_url': self.target_url,
            'domain': self.hostname or self.target_url,
            'scan_duration': duration,
            'risk_score': score,
            'risk_grade': grade,
            'total_vulnerabilities': len(self.findings),
            'high_count': high_c,
            'medium_count': med_c,
            'low_count': low_c,
            'findings': self.findings,
            'header_audits': self.header_audits,
            'ssl_info': self.ssl_info
        }
