#!/usr/bin/env python3
"""
System Security Audit Tool
Perform basic security checks on Linux/Unix systems
Educational tool for understanding system security
"""

import os
import pwd
import grp
import subprocess
import platform
from datetime import datetime
from pathlib import Path


class SystemSecurityAuditor:
    """Audit system security configuration"""

    def __init__(self):
        self.findings = []
        self.is_linux = platform.system() == 'Linux'
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False

    def add_finding(self, category, severity, description, recommendation=""):
        """Add security finding"""
        self.findings.append({
            'category': category,
            'severity': severity,
            'description': description,
            'recommendation': recommendation
        })

    def check_user_accounts(self):
        """Check for security issues with user accounts"""
        print("\n[*] Checking User Accounts...")

        try:
            # Check for users with UID 0 (root privileges)
            root_users = []
            for user in pwd.getpwall():
                if user.pw_uid == 0 and user.pw_name != 'root':
                    root_users.append(user.pw_name)

            if root_users:
                print(f"  ⚠️ Found non-root users with UID 0: {', '.join(root_users)}")
                self.add_finding(
                    'User Accounts',
                    'HIGH',
                    f"Non-root users with UID 0: {', '.join(root_users)}",
                    "Remove root privileges from these accounts"
                )
            else:
                print(f"  ✓ No unauthorized root-level accounts")

            # Check for users without passwords (if accessible)
            if os.path.exists('/etc/shadow') and self.is_root:
                try:
                    with open('/etc/shadow', 'r') as f:
                        for line in f:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                username = parts[0]
                                password_field = parts[1]

                                # Empty or locked password
                                if password_field in ['', '!', '*']:
                                    # Skip system accounts
                                    try:
                                        user = pwd.getpwnam(username)
                                        if user.pw_uid >= 1000:  # Regular user
                                            print(f"  ⚠️ User '{username}' has no password set")
                                            self.add_finding(
                                                'User Accounts',
                                                'HIGH',
                                                f"User '{username}' has no password",
                                                "Set a strong password for this account"
                                            )
                                    except KeyError:
                                        pass
                except PermissionError:
                    print(f"  ℹ️ Cannot read /etc/shadow (need root)")

            print(f"  ✓ User account checks completed")

        except Exception as e:
            print(f"  ✗ Error checking user accounts: {e}")

    def check_file_permissions(self):
        """Check critical file permissions"""
        print("\n[*] Checking File Permissions...")

        critical_files = {
            '/etc/passwd': 0o644,
            '/etc/shadow': 0o640,
            '/etc/group': 0o644,
            '/etc/gshadow': 0o640,
            '/etc/ssh/sshd_config': 0o600,
        }

        for filepath, expected_mode in critical_files.items():
            if os.path.exists(filepath):
                stat_info = os.stat(filepath)
                actual_mode = stat_info.st_mode & 0o777

                if actual_mode != expected_mode:
                    print(f"  ⚠️ {filepath}: incorrect permissions "
                          f"({oct(actual_mode)} should be {oct(expected_mode)})")
                    self.add_finding(
                        'File Permissions',
                        'HIGH',
                        f"{filepath} has incorrect permissions: {oct(actual_mode)}",
                        f"Change permissions to {oct(expected_mode)}"
                    )
                else:
                    print(f"  ✓ {filepath}: correct permissions")
            else:
                print(f"  ℹ️ {filepath}: not found")

        # Check for world-writable files in critical directories
        if self.is_root:
            print("\n  Checking for world-writable files...")
            critical_dirs = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin']

            for directory in critical_dirs:
                if os.path.exists(directory):
                    try:
                        for root, dirs, files in os.walk(directory):
                            for filename in files[:10]:  # Limit to first 10
                                filepath = os.path.join(root, filename)
                                try:
                                    stat_info = os.stat(filepath)
                                    if stat_info.st_mode & 0o002:  # World writable
                                        print(f"  ⚠️ World-writable file: {filepath}")
                                        self.add_finding(
                                            'File Permissions',
                                            'HIGH',
                                            f"World-writable file in critical directory: {filepath}",
                                            "Remove world-write permission"
                                        )
                                except (OSError, PermissionError):
                                    pass
                            break  # Only check top level
                    except PermissionError:
                        pass

        print(f"  ✓ File permission checks completed")

    def check_ssh_configuration(self):
        """Check SSH server configuration"""
        print("\n[*] Checking SSH Configuration...")

        ssh_config_file = '/etc/ssh/sshd_config'

        if not os.path.exists(ssh_config_file):
            print(f"  ℹ️ SSH not configured or config file not found")
            return

        try:
            with open(ssh_config_file, 'r') as f:
                config = f.read()

            # Check for root login
            if 'PermitRootLogin yes' in config:
                print(f"  ⚠️ Root login is permitted")
                self.add_finding(
                    'SSH Configuration',
                    'HIGH',
                    "SSH allows root login",
                    "Set 'PermitRootLogin no' in sshd_config"
                )
            else:
                print(f"  ✓ Root login properly restricted")

            # Check for password authentication
            if 'PasswordAuthentication yes' in config:
                print(f"  ⚠️ Password authentication is enabled")
                self.add_finding(
                    'SSH Configuration',
                    'MEDIUM',
                    "SSH allows password authentication",
                    "Consider using key-based authentication only"
                )

            # Check for empty passwords
            if 'PermitEmptyPasswords yes' in config:
                print(f"  ⚠️ Empty passwords are permitted!")
                self.add_finding(
                    'SSH Configuration',
                    'CRITICAL',
                    "SSH allows empty passwords",
                    "Set 'PermitEmptyPasswords no' in sshd_config"
                )

            # Check SSH protocol version
            if 'Protocol 1' in config:
                print(f"  ⚠️ SSH Protocol 1 is enabled (insecure)")
                self.add_finding(
                    'SSH Configuration',
                    'HIGH',
                    "SSH Protocol 1 is enabled",
                    "Use only Protocol 2"
                )

            print(f"  ✓ SSH configuration checks completed")

        except PermissionError:
            print(f"  ℹ️ Cannot read SSH config (need root)")
        except Exception as e:
            print(f"  ✗ Error checking SSH config: {e}")

    def check_firewall_status(self):
        """Check firewall status"""
        print("\n[*] Checking Firewall Status...")

        try:
            # Check ufw (Ubuntu/Debian)
            if os.path.exists('/usr/sbin/ufw'):
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                if 'Status: active' in result.stdout:
                    print(f"  ✓ UFW firewall is active")
                else:
                    print(f"  ⚠️ UFW firewall is inactive")
                    self.add_finding(
                        'Firewall',
                        'HIGH',
                        "UFW firewall is not active",
                        "Enable firewall with 'sudo ufw enable'"
                    )

            # Check iptables
            elif os.path.exists('/usr/sbin/iptables'):
                if self.is_root:
                    result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        if len(lines) <= 10:  # Few rules = likely not configured
                            print(f"  ⚠️ iptables has minimal rules configured")
                            self.add_finding(
                                'Firewall',
                                'MEDIUM',
                                "iptables appears to be minimally configured",
                                "Configure appropriate firewall rules"
                            )
                        else:
                            print(f"  ✓ iptables is configured")
                else:
                    print(f"  ℹ️ Need root to check iptables")

            else:
                print(f"  ⚠️ No firewall found")
                self.add_finding(
                    'Firewall',
                    'HIGH',
                    "No firewall appears to be installed",
                    "Install and configure a firewall (ufw, iptables, etc.)"
                )

        except Exception as e:
            print(f"  ✗ Error checking firewall: {e}")

    def check_installed_packages(self):
        """Check for security updates and unnecessary packages"""
        print("\n[*] Checking Package Security...")

        try:
            # Check for security updates (Debian/Ubuntu)
            if os.path.exists('/usr/bin/apt'):
                print(f"  Checking for security updates...")
                result = subprocess.run(
                    ['apt', 'list', '--upgradable'],
                    capture_output=True,
                    text=True
                )

                upgrade_count = result.stdout.count('\n') - 1
                if upgrade_count > 0:
                    print(f"  ⚠️ {upgrade_count} package updates available")
                    self.add_finding(
                        'Package Management',
                        'MEDIUM',
                        f"{upgrade_count} package updates available",
                        "Run 'sudo apt update && sudo apt upgrade'"
                    )
                else:
                    print(f"  ✓ System is up to date")

            # Check for unattended-upgrades
            if os.path.exists('/etc/apt/apt.conf.d/50unattended-upgrades'):
                print(f"  ✓ Automatic security updates configured")
            else:
                print(f"  ⚠️ Automatic security updates not configured")
                self.add_finding(
                    'Package Management',
                    'MEDIUM',
                    "Automatic security updates not enabled",
                    "Install and configure unattended-upgrades"
                )

            print(f"  ✓ Package security checks completed")

        except Exception as e:
            print(f"  ✗ Error checking packages: {e}")

    def check_running_services(self):
        """Check running services"""
        print("\n[*] Checking Running Services...")

        try:
            # Check for unnecessary services
            unnecessary_services = ['telnet', 'ftp', 'rsh']

            for service in unnecessary_services:
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True,
                    text=True
                )

                if result.stdout.strip() == 'active':
                    print(f"  ⚠️ Insecure service '{service}' is running")
                    self.add_finding(
                        'Running Services',
                        'HIGH',
                        f"Insecure service '{service}' is active",
                        f"Disable service: 'sudo systemctl stop {service}'"
                    )

            print(f"  ✓ Service checks completed")

        except Exception as e:
            print(f"  ✗ Error checking services: {e}")

    def check_system_logs(self):
        """Check system logs for security issues"""
        print("\n[*] Checking System Logs...")

        log_files = [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/syslog'
        ]

        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    print(f"  Analyzing {log_file}...")

                    # Count failed login attempts
                    with open(log_file, 'r') as f:
                        content = f.read()
                        failed_count = content.count('Failed password')

                        if failed_count > 10:
                            print(f"  ⚠️ {failed_count} failed login attempts detected")
                            self.add_finding(
                                'System Logs',
                                'MEDIUM',
                                f"{failed_count} failed login attempts in {log_file}",
                                "Review logs and consider implementing fail2ban"
                            )

                    break  # Only check first available log

                except PermissionError:
                    print(f"  ℹ️ Cannot read {log_file} (need root)")
                except Exception as e:
                    print(f"  ✗ Error reading {log_file}: {e}")

        print(f"  ✓ Log analysis completed")

    def generate_report(self):
        """Generate security audit report"""
        print("\n" + "="*70)
        print("SYSTEM SECURITY AUDIT REPORT")
        print("="*70)

        print(f"\nSystem: {platform.system()} {platform.release()}")
        print(f"Hostname: {platform.node()}")
        print(f"Audit Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Running as: {'root' if self.is_root else 'non-root user'}")

        if not self.is_root:
            print("\n⚠️ NOTE: Running without root privileges - some checks are limited")

        print(f"\nTotal Findings: {len(self.findings)}")

        # Count by severity
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }

        for finding in self.findings:
            severity_counts[finding['severity']] += 1

        print(f"\nSeverity Breakdown:")
        print(f"  Critical: {severity_counts['CRITICAL']}")
        print(f"  High:     {severity_counts['HIGH']}")
        print(f"  Medium:   {severity_counts['MEDIUM']}")
        print(f"  Low:      {severity_counts['LOW']}")

        # List findings by category and severity
        categories = set(f['category'] for f in self.findings)

        for category in sorted(categories):
            category_findings = [f for f in self.findings if f['category'] == category]

            print(f"\n--- {category} ---")
            for finding in sorted(category_findings, key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x['severity'])):
                print(f"\n  [{finding['severity']}] {finding['description']}")
                if finding['recommendation']:
                    print(f"  Recommendation: {finding['recommendation']}")

        # Overall security score
        risk_score = (
            severity_counts['CRITICAL'] * 10 +
            severity_counts['HIGH'] * 5 +
            severity_counts['MEDIUM'] * 2 +
            severity_counts['LOW'] * 1
        )

        print(f"\n--- Overall Security Rating ---")
        if risk_score == 0:
            print(f"  ✓ EXCELLENT - No security issues detected")
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

    def run_audit(self):
        """Run complete security audit"""
        print("\n" + "="*70)
        print("SYSTEM SECURITY AUDIT")
        print("="*70)
        print(f"\nStarted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)

        if not self.is_linux:
            print("\n⚠️ This tool is designed for Linux/Unix systems")
            print(f"Current system: {platform.system()}")
            print("Some checks may not work correctly\n")

        # Run all checks
        self.check_user_accounts()
        self.check_file_permissions()
        self.check_ssh_configuration()
        self.check_firewall_status()
        self.check_installed_packages()
        self.check_running_services()
        self.check_system_logs()

        # Generate report
        self.generate_report()


def main():
    """Main function"""
    print("="*70)
    print("SYSTEM SECURITY AUDIT TOOL")
    print("="*70)
    print("\nThis tool performs basic security checks on your system.")
    print("For complete audit, run with root/sudo privileges.")

    print("\n⚠️ NOTE: This is a basic audit tool for educational purposes.")
    print("For production systems, use professional security tools.\n")

    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("⚠️ Running without root privileges - some checks will be limited")
        print("For full audit, run: sudo python3 system_security_audit.py\n")

    input("Press Enter to start audit...")

    auditor = SystemSecurityAuditor()
    auditor.run_audit()


if __name__ == "__main__":
    main()
