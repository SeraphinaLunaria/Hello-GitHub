#!/usr/bin/env python3
"""
DNS Security Checker
Check DNS configurations and detect potential DNS-related security issues
Educational tool for understanding DNS security
"""

import socket
import dns.resolver
import dns.reversename
import dns.query
import dns.zone
from datetime import datetime
import time


class DNSSecurityChecker:
    """Check DNS security and configuration"""

    def __init__(self):
        self.findings = []
        self.resolver = dns.resolver.Resolver()

    def add_finding(self, severity, description, recommendation=""):
        """Add a security finding"""
        self.findings.append({
            'severity': severity,
            'description': description,
            'recommendation': recommendation,
            'timestamp': datetime.now().isoformat()
        })

    def check_dns_resolution(self, domain):
        """Check if domain resolves and get A records"""
        print(f"\n[*] Checking DNS resolution for {domain}...")

        try:
            answers = self.resolver.resolve(domain, 'A')

            print(f"  ✓ Domain resolves successfully")
            print(f"  IP Addresses:")
            for rdata in answers:
                print(f"    • {rdata.address}")

            return [rdata.address for rdata in answers]

        except dns.resolver.NXDOMAIN:
            print(f"  ✗ Domain does not exist")
            self.add_finding(
                'HIGH',
                f"Domain {domain} does not exist (NXDOMAIN)",
                "Verify domain name spelling"
            )
            return None

        except dns.resolver.NoAnswer:
            print(f"  ✗ No A records found")
            return None

        except Exception as e:
            print(f"  ✗ Error: {e}")
            return None

    def check_dnssec(self, domain):
        """Check if DNSSEC is enabled"""
        print(f"\n[*] Checking DNSSEC for {domain}...")

        try:
            # Query for DNSKEY records
            answers = self.resolver.resolve(domain, 'DNSKEY')

            if answers:
                print(f"  ✓ DNSSEC is enabled")
                print(f"  Found {len(answers)} DNSKEY record(s)")
                return True
            else:
                print(f"  ✗ DNSSEC is not enabled")
                self.add_finding(
                    'MEDIUM',
                    f"DNSSEC not enabled for {domain}",
                    "Enable DNSSEC to prevent DNS spoofing"
                )
                return False

        except dns.resolver.NoAnswer:
            print(f"  ✗ DNSSEC is not enabled")
            self.add_finding(
                'MEDIUM',
                f"DNSSEC not enabled for {domain}",
                "Enable DNSSEC to prevent DNS spoofing"
            )
            return False

        except Exception as e:
            print(f"  ℹ️ Could not determine DNSSEC status: {e}")
            return False

    def check_spf_record(self, domain):
        """Check for SPF record"""
        print(f"\n[*] Checking SPF record for {domain}...")

        try:
            answers = self.resolver.resolve(domain, 'TXT')

            spf_records = [str(rdata) for rdata in answers if 'spf' in str(rdata).lower()]

            if spf_records:
                print(f"  ✓ SPF record found")
                for record in spf_records:
                    print(f"    {record}")
                return True
            else:
                print(f"  ✗ No SPF record found")
                self.add_finding(
                    'MEDIUM',
                    f"No SPF record for {domain}",
                    "Add SPF record to prevent email spoofing"
                )
                return False

        except dns.resolver.NoAnswer:
            print(f"  ✗ No TXT records found")
            self.add_finding(
                'MEDIUM',
                f"No SPF record for {domain}",
                "Add SPF record to prevent email spoofing"
            )
            return False

        except Exception as e:
            print(f"  ✗ Error: {e}")
            return False

    def check_dmarc_record(self, domain):
        """Check for DMARC record"""
        print(f"\n[*] Checking DMARC record for {domain}...")

        dmarc_domain = f"_dmarc.{domain}"

        try:
            answers = self.resolver.resolve(dmarc_domain, 'TXT')

            dmarc_records = [str(rdata) for rdata in answers if 'dmarc' in str(rdata).lower()]

            if dmarc_records:
                print(f"  ✓ DMARC record found")
                for record in dmarc_records:
                    print(f"    {record}")
                return True
            else:
                print(f"  ✗ No DMARC record found")
                self.add_finding(
                    'MEDIUM',
                    f"No DMARC record for {domain}",
                    "Add DMARC record for email authentication"
                )
                return False

        except dns.resolver.NXDOMAIN:
            print(f"  ✗ No DMARC record found")
            self.add_finding(
                'MEDIUM',
                f"No DMARC record for {domain}",
                "Add DMARC record for email authentication"
            )
            return False

        except Exception as e:
            print(f"  ✗ Error: {e}")
            return False

    def check_dkim_record(self, domain, selector='default'):
        """Check for DKIM record"""
        print(f"\n[*] Checking DKIM record for {domain} (selector: {selector})...")

        dkim_domain = f"{selector}._domainkey.{domain}"

        try:
            answers = self.resolver.resolve(dkim_domain, 'TXT')

            dkim_records = [str(rdata) for rdata in answers]

            if dkim_records:
                print(f"  ✓ DKIM record found")
                for record in dkim_records[:1]:  # Show first record
                    print(f"    {record[:80]}...")
                return True
            else:
                print(f"  ⚠️ No DKIM record found for selector '{selector}'")
                return False

        except dns.resolver.NXDOMAIN:
            print(f"  ⚠️ No DKIM record found for selector '{selector}'")
            print(f"  ℹ️ Try different selectors (e.g., 'google', 'k1', 's1')")
            return False

        except Exception as e:
            print(f"  ⚠️ Could not check DKIM: {e}")
            return False

    def check_mx_records(self, domain):
        """Check MX records"""
        print(f"\n[*] Checking MX records for {domain}...")

        try:
            answers = self.resolver.resolve(domain, 'MX')

            if answers:
                print(f"  ✓ MX records found")
                mx_records = []
                for rdata in answers:
                    print(f"    Priority {rdata.preference}: {rdata.exchange}")
                    mx_records.append((rdata.preference, str(rdata.exchange)))

                # Check if MX points to localhost or RFC1918
                for priority, mx in mx_records:
                    if 'localhost' in mx.lower() or '127.0.0.1' in mx:
                        self.add_finding(
                            'HIGH',
                            f"MX record points to localhost: {mx}",
                            "Configure proper mail server"
                        )

                return mx_records
            else:
                print(f"  ⚠️ No MX records found")
                return None

        except dns.resolver.NoAnswer:
            print(f"  ⚠️ No MX records found")
            return None

        except Exception as e:
            print(f"  ✗ Error: {e}")
            return None

    def check_nameservers(self, domain):
        """Check NS records"""
        print(f"\n[*] Checking nameservers for {domain}...")

        try:
            answers = self.resolver.resolve(domain, 'NS')

            if answers:
                print(f"  ✓ Nameservers found")
                nameservers = []
                for rdata in answers:
                    ns = str(rdata.target)
                    print(f"    • {ns}")
                    nameservers.append(ns)

                # Check if less than 2 nameservers
                if len(nameservers) < 2:
                    self.add_finding(
                        'MEDIUM',
                        f"Only {len(nameservers)} nameserver(s) configured",
                        "Configure at least 2 nameservers for redundancy"
                    )

                return nameservers

        except Exception as e:
            print(f"  ✗ Error: {e}")
            return None

    def check_caa_records(self, domain):
        """Check CAA records"""
        print(f"\n[*] Checking CAA records for {domain}...")

        try:
            answers = self.resolver.resolve(domain, 'CAA')

            if answers:
                print(f"  ✓ CAA records found")
                for rdata in answers:
                    print(f"    {rdata}")
                return True
            else:
                print(f"  ⚠️ No CAA records found")
                self.add_finding(
                    'LOW',
                    f"No CAA records for {domain}",
                    "Add CAA records to control certificate issuance"
                )
                return False

        except dns.resolver.NoAnswer:
            print(f"  ⚠️ No CAA records found")
            self.add_finding(
                'LOW',
                f"No CAA records for {domain}",
                "Add CAA records to control certificate issuance"
            )
            return False

        except Exception as e:
            print(f"  ℹ️ Could not check CAA records: {e}")
            return False

    def check_reverse_dns(self, ip_address):
        """Check reverse DNS"""
        print(f"\n[*] Checking reverse DNS for {ip_address}...")

        try:
            addr = dns.reversename.from_address(ip_address)
            answers = self.resolver.resolve(addr, 'PTR')

            if answers:
                print(f"  ✓ Reverse DNS found")
                for rdata in answers:
                    print(f"    {rdata}")
                return True
            else:
                print(f"  ✗ No reverse DNS found")
                return False

        except Exception as e:
            print(f"  ✗ No reverse DNS found")
            return False

    def check_dns_propagation(self, domain, nameservers=None):
        """Check DNS propagation across nameservers"""
        print(f"\n[*] Checking DNS propagation for {domain}...")

        if not nameservers:
            # Use public DNS servers
            nameservers = [
                ('Google', '8.8.8.8'),
                ('Cloudflare', '1.1.1.1'),
                ('Quad9', '9.9.9.9'),
            ]

        results = {}

        for name, ns in nameservers:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ns]

            try:
                answers = resolver.resolve(domain, 'A')
                ips = [str(rdata) for rdata in answers]
                results[name] = ips
                print(f"  {name} ({ns}): {', '.join(ips)}")

            except Exception as e:
                results[name] = None
                print(f"  {name} ({ns}): Error - {e}")

        # Check consistency
        unique_results = set(tuple(sorted(v)) for v in results.values() if v)

        if len(unique_results) > 1:
            print(f"\n  ⚠️ Inconsistent DNS propagation detected")
            self.add_finding(
                'MEDIUM',
                f"DNS propagation inconsistent for {domain}",
                "Wait for DNS propagation to complete (24-48 hours)"
            )
        else:
            print(f"\n  ✓ DNS propagation is consistent")

    def generate_report(self, domain):
        """Generate security report"""
        print("\n" + "="*70)
        print("DNS SECURITY REPORT")
        print("="*70)

        print(f"\nDomain: {domain}")
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\nTotal Findings: {len(self.findings)}")

        # Count by severity
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.findings:
            severity_counts[finding['severity']] += 1

        print(f"\nSeverity Breakdown:")
        print(f"  High:   {severity_counts['HIGH']}")
        print(f"  Medium: {severity_counts['MEDIUM']}")
        print(f"  Low:    {severity_counts['LOW']}")

        if self.findings:
            print(f"\n--- Findings ---")
            for i, finding in enumerate(self.findings, 1):
                print(f"\n{i}. [{finding['severity']}] {finding['description']}")
                if finding['recommendation']:
                    print(f"   Recommendation: {finding['recommendation']}")

        # Calculate security score
        score = 100 - (severity_counts['HIGH'] * 20 + severity_counts['MEDIUM'] * 10 + severity_counts['LOW'] * 5)
        score = max(0, score)

        print(f"\n--- Security Score ---")
        print(f"Score: {score}/100")

        if score >= 90:
            print(f"Rating: ✓ EXCELLENT")
        elif score >= 75:
            print(f"Rating: ✓ GOOD")
        elif score >= 60:
            print(f"Rating: ⚠️ FAIR")
        else:
            print(f"Rating: ✗ POOR")

        print("\n" + "="*70)

    def full_scan(self, domain):
        """Run full DNS security scan"""
        print("\n" + "="*70)
        print("DNS SECURITY CHECKER")
        print("="*70)
        print(f"\nTarget: {domain}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)

        # Run all checks
        ip_addresses = self.check_dns_resolution(domain)
        time.sleep(0.5)

        self.check_nameservers(domain)
        time.sleep(0.5)

        self.check_dnssec(domain)
        time.sleep(0.5)

        self.check_spf_record(domain)
        time.sleep(0.5)

        self.check_dmarc_record(domain)
        time.sleep(0.5)

        self.check_dkim_record(domain)
        time.sleep(0.5)

        self.check_mx_records(domain)
        time.sleep(0.5)

        self.check_caa_records(domain)
        time.sleep(0.5)

        if ip_addresses:
            self.check_reverse_dns(ip_addresses[0])
            time.sleep(0.5)

        self.check_dns_propagation(domain)

        # Generate report
        self.generate_report(domain)


def main():
    """Main function"""
    print("="*70)
    print("DNS SECURITY CHECKER")
    print("="*70)
    print("\nCheck DNS configuration and security settings")
    print("Educational tool for understanding DNS security\n")

    checker = DNSSecurityChecker()

    domain = input("Enter domain to check (e.g., example.com): ").strip()

    if not domain:
        print("Error: Domain is required")
        return

    # Remove protocol if present
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]

    checker.full_scan(domain)


if __name__ == "__main__":
    main()
