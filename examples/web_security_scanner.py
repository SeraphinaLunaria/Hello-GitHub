#!/usr/bin/env python3
"""
Web Security Scanner
Educational tool for testing web application security
WARNING: Only scan websites you own or have permission to test!
"""

import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import time


class WebSecurityScanner:
    """Scan websites for common security vulnerabilities"""

    def __init__(self, target_url, timeout=5):
        self.target_url = target_url
        self.timeout = timeout
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security-Scanner-Educational/1.0'
        })

    def check_security_headers(self):
        """Check for important security headers"""
        print("\n[*] Checking Security Headers...")

        security_headers = {
            'Strict-Transport-Security': {
                'present': False,
                'severity': 'HIGH',
                'description': 'Enforces HTTPS connections'
            },
            'X-Content-Type-Options': {
                'present': False,
                'severity': 'MEDIUM',
                'description': 'Prevents MIME sniffing'
            },
            'X-Frame-Options': {
                'present': False,
                'severity': 'MEDIUM',
                'description': 'Prevents clickjacking'
            },
            'X-XSS-Protection': {
                'present': False,
                'severity': 'LOW',
                'description': 'Enables XSS filter'
            },
            'Content-Security-Policy': {
                'present': False,
                'severity': 'HIGH',
                'description': 'Prevents XSS and injection attacks'
            },
            'Referrer-Policy': {
                'present': False,
                'severity': 'LOW',
                'description': 'Controls referrer information'
            },
            'Permissions-Policy': {
                'present': False,
                'severity': 'MEDIUM',
                'description': 'Controls browser features'
            }
        }

        try:
            response = self.session.get(self.target_url, timeout=self.timeout)

            for header, info in security_headers.items():
                if header in response.headers:
                    info['present'] = True
                    info['value'] = response.headers[header]
                    print(f"  ✓ {header}: Present")
                else:
                    print(f"  ✗ {header}: Missing [{info['severity']}]")
                    self.vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'severity': info['severity'],
                        'header': header,
                        'description': info['description']
                    })

            return security_headers

        except Exception as e:
            print(f"  ✗ Error checking headers: {e}")
            return None

    def check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        print("\n[*] Checking SSL/TLS Configuration...")

        try:
            # Check if HTTPS is used
            if not self.target_url.startswith('https://'):
                print(f"  ✗ Site does not use HTTPS [HIGH]")
                self.vulnerabilities.append({
                    'type': 'No HTTPS',
                    'severity': 'HIGH',
                    'description': 'Site does not enforce encrypted connections'
                })
                return False

            # Make request to check certificate
            response = self.session.get(self.target_url, timeout=self.timeout)

            print(f"  ✓ HTTPS enabled")
            print(f"  ✓ Certificate valid")

            # Try to access via HTTP
            http_url = self.target_url.replace('https://', 'http://')
            try:
                http_response = requests.get(http_url, timeout=self.timeout, allow_redirects=False)
                if http_response.status_code != 301 and http_response.status_code != 302:
                    print(f"  ⚠️ HTTP not redirecting to HTTPS [MEDIUM]")
                    self.vulnerabilities.append({
                        'type': 'No HTTP to HTTPS Redirect',
                        'severity': 'MEDIUM',
                        'description': 'HTTP requests are not redirected to HTTPS'
                    })
                else:
                    print(f"  ✓ HTTP redirects to HTTPS")
            except:
                pass

            return True

        except requests.exceptions.SSLError as e:
            print(f"  ✗ SSL Certificate Error [HIGH]")
            self.vulnerabilities.append({
                'type': 'SSL Certificate Error',
                'severity': 'HIGH',
                'description': str(e)
            })
            return False
        except Exception as e:
            print(f"  ✗ Error checking SSL/TLS: {e}")
            return False

    def check_information_disclosure(self):
        """Check for information disclosure"""
        print("\n[*] Checking for Information Disclosure...")

        try:
            response = self.session.get(self.target_url, timeout=self.timeout)

            # Check Server header
            if 'Server' in response.headers:
                server = response.headers['Server']
                print(f"  ⚠️ Server header exposed: {server} [LOW]")
                self.vulnerabilities.append({
                    'type': 'Server Version Disclosure',
                    'severity': 'LOW',
                    'description': f'Server header reveals: {server}'
                })

            # Check X-Powered-By header
            if 'X-Powered-By' in response.headers:
                powered_by = response.headers['X-Powered-By']
                print(f"  ⚠️ X-Powered-By header exposed: {powered_by} [LOW]")
                self.vulnerabilities.append({
                    'type': 'Technology Disclosure',
                    'severity': 'LOW',
                    'description': f'X-Powered-By reveals: {powered_by}'
                })

            # Check for common debug endpoints
            debug_paths = ['/debug', '/.env', '/config', '/admin', '/.git/HEAD']
            for path in debug_paths:
                url = urljoin(self.target_url, path)
                try:
                    resp = self.session.get(url, timeout=self.timeout)
                    if resp.status_code == 200:
                        print(f"  ⚠️ Debug/sensitive path accessible: {path} [HIGH]")
                        self.vulnerabilities.append({
                            'type': 'Sensitive Path Accessible',
                            'severity': 'HIGH',
                            'description': f'Path {path} is accessible',
                            'url': url
                        })
                except:
                    pass

            print(f"  ✓ Basic information disclosure checks completed")

        except Exception as e:
            print(f"  ✗ Error checking information disclosure: {e}")

    def check_common_vulnerabilities(self):
        """Check for common web vulnerabilities"""
        print("\n[*] Checking Common Vulnerabilities...")

        try:
            # Test for SQL injection vulnerability (basic check)
            sql_payloads = ["'", "1' OR '1'='1", "admin'--", "' OR 1=1--"]

            for payload in sql_payloads[:2]:  # Limited testing
                test_url = f"{self.target_url}?id={payload}"
                try:
                    response = self.session.get(test_url, timeout=self.timeout)

                    # Look for SQL error messages
                    sql_errors = [
                        'sql syntax',
                        'mysql',
                        'postgresql',
                        'ORA-',
                        'syntax error'
                    ]

                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            print(f"  ⚠️ Possible SQL Injection vulnerability [CRITICAL]")
                            self.vulnerabilities.append({
                                'type': 'Possible SQL Injection',
                                'severity': 'CRITICAL',
                                'description': f'SQL error message detected with payload: {payload}',
                                'url': test_url
                            })
                            break
                except:
                    pass

            # Test for XSS vulnerability (basic check)
            xss_payload = "<script>alert('XSS')</script>"
            test_url = f"{self.target_url}?search={xss_payload}"

            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if xss_payload in response.text:
                    print(f"  ⚠️ Possible XSS vulnerability [HIGH]")
                    self.vulnerabilities.append({
                        'type': 'Possible XSS',
                        'severity': 'HIGH',
                        'description': 'Unescaped user input detected',
                        'url': test_url
                    })
            except:
                pass

            print(f"  ✓ Common vulnerability checks completed")

        except Exception as e:
            print(f"  ✗ Error checking common vulnerabilities: {e}")

    def check_cookies(self):
        """Check cookie security"""
        print("\n[*] Checking Cookie Security...")

        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            cookies = response.cookies

            if not cookies:
                print(f"  ℹ️ No cookies set")
                return

            for cookie in cookies:
                issues = []

                if not cookie.secure:
                    issues.append("missing Secure flag")

                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("missing HttpOnly flag")

                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append("missing SameSite attribute")

                if issues:
                    print(f"  ⚠️ Cookie '{cookie.name}': {', '.join(issues)} [MEDIUM]")
                    self.vulnerabilities.append({
                        'type': 'Insecure Cookie',
                        'severity': 'MEDIUM',
                        'description': f"Cookie '{cookie.name}' has issues: {', '.join(issues)}"
                    })
                else:
                    print(f"  ✓ Cookie '{cookie.name}': Properly secured")

        except Exception as e:
            print(f"  ✗ Error checking cookies: {e}")

    def check_forms(self):
        """Check forms for security issues"""
        print("\n[*] Checking Forms...")

        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                print(f"  ℹ️ No forms found")
                return

            for i, form in enumerate(forms, 1):
                action = form.get('action', 'Not specified')
                method = form.get('method', 'GET').upper()

                print(f"\n  Form #{i}:")
                print(f"    Action: {action}")
                print(f"    Method: {method}")

                # Check if form uses HTTPS
                if action.startswith('http://'):
                    print(f"    ⚠️ Form submits over HTTP [HIGH]")
                    self.vulnerabilities.append({
                        'type': 'Insecure Form Submission',
                        'severity': 'HIGH',
                        'description': f'Form submits to HTTP URL: {action}'
                    })

                # Check for password fields without HTTPS
                password_fields = form.find_all('input', {'type': 'password'})
                if password_fields and not self.target_url.startswith('https://'):
                    print(f"    ⚠️ Password field on non-HTTPS page [CRITICAL]")
                    self.vulnerabilities.append({
                        'type': 'Password Field Over HTTP',
                        'severity': 'CRITICAL',
                        'description': 'Password input field on non-HTTPS page'
                    })

                # Check for CSRF protection
                csrf_tokens = form.find_all('input', {'name': re.compile(r'csrf|token', re.I)})
                if not csrf_tokens and method == 'POST':
                    print(f"    ⚠️ No CSRF token found [MEDIUM]")
                    self.vulnerabilities.append({
                        'type': 'Missing CSRF Protection',
                        'severity': 'MEDIUM',
                        'description': 'POST form without apparent CSRF token'
                    })
                else:
                    print(f"    ✓ CSRF token present")

        except Exception as e:
            print(f"  ✗ Error checking forms: {e}")

    def generate_report(self):
        """Generate security scan report"""
        print("\n" + "="*70)
        print("SECURITY SCAN REPORT")
        print("="*70)

        print(f"\nTarget: {self.target_url}")
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\nTotal Vulnerabilities Found: {len(self.vulnerabilities)}")

        # Count by severity
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }

        for vuln in self.vulnerabilities:
            severity_counts[vuln['severity']] += 1

        print(f"\nSeverity Breakdown:")
        print(f"  Critical: {severity_counts['CRITICAL']}")
        print(f"  High:     {severity_counts['HIGH']}")
        print(f"  Medium:   {severity_counts['MEDIUM']}")
        print(f"  Low:      {severity_counts['LOW']}")

        # List vulnerabilities by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            vulns = [v for v in self.vulnerabilities if v['severity'] == severity]
            if vulns:
                print(f"\n--- {severity} Severity Issues ---")
                for i, vuln in enumerate(vulns, 1):
                    print(f"\n  {i}. {vuln['type']}")
                    print(f"     Description: {vuln['description']}")
                    if 'url' in vuln:
                        print(f"     URL: {vuln['url']}")

        # Overall risk score
        risk_score = (
            severity_counts['CRITICAL'] * 10 +
            severity_counts['HIGH'] * 5 +
            severity_counts['MEDIUM'] * 2 +
            severity_counts['LOW'] * 1
        )

        print(f"\n--- Overall Security Rating ---")
        if risk_score == 0:
            print(f"  ✓ EXCELLENT - No vulnerabilities detected")
        elif risk_score <= 5:
            print(f"  ✓ GOOD - Minor issues found")
        elif risk_score <= 15:
            print(f"  ⚠️ FAIR - Some security improvements needed")
        elif risk_score <= 30:
            print(f"  ⚠️ POOR - Significant security issues found")
        else:
            print(f"  ✗ CRITICAL - Severe security issues require immediate attention")

        print(f"  Risk Score: {risk_score}/100")

        print("\n" + "="*70)

    def scan(self):
        """Run complete security scan"""
        print("\n" + "="*70)
        print("WEB SECURITY SCANNER")
        print("="*70)
        print(f"\nTarget: {self.target_url}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\n⚠️ WARNING: Only scan websites you own or have permission to test!")
        print("="*70)

        # Run all checks
        self.check_ssl_tls()
        time.sleep(0.5)

        self.check_security_headers()
        time.sleep(0.5)

        self.check_cookies()
        time.sleep(0.5)

        self.check_information_disclosure()
        time.sleep(0.5)

        self.check_forms()
        time.sleep(0.5)

        self.check_common_vulnerabilities()

        # Generate report
        self.generate_report()


def main():
    """Main function"""
    print("="*70)
    print("WEB SECURITY SCANNER")
    print("="*70)
    print("\n⚠️ IMPORTANT LEGAL NOTICE:")
    print("This tool is for educational purposes only.")
    print("Only scan websites you own or have explicit permission to test.")
    print("Unauthorized scanning may be illegal in your jurisdiction.")
    print("\nDo you agree to use this tool responsibly? (yes/no): ", end='')

    agreement = input().strip().lower()

    if agreement != 'yes':
        print("\nYou must agree to use this tool responsibly. Exiting.")
        return

    print("\n" + "="*70)

    target_url = input("\nEnter target URL (e.g., https://example.com): ").strip()

    if not target_url:
        print("Error: URL is required")
        return

    # Add https:// if not present
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    # Create scanner and run scan
    scanner = WebSecurityScanner(target_url)
    scanner.scan()


if __name__ == "__main__":
    main()
