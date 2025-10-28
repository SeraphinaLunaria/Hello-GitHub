# Python Cybersecurity Tools Guide

Complete guide to using all the security tools in this repository.

---

## Table of Contents

1. [Password Validator](#1-password-validator)
2. [IP Blocklist Manager](#2-ip-blocklist-manager)
3. [File Integrity Checker](#3-file-integrity-checker)
4. [Network Packet Analyzer](#4-network-packet-analyzer)
5. [Web Security Scanner](#5-web-security-scanner)
6. [Secure Messaging System](#6-secure-messaging-system)
7. [System Security Audit](#7-system-security-audit)
8. [Malware Detection Tool](#8-malware-detection-tool)
9. [DNS Security Checker](#9-dns-security-checker)

---

## 1. Password Validator

**File:** `examples/password_validator.py`

### Description
Advanced password strength checker that validates passwords against security best practices and calculates entropy scores.

### Features
- Length validation
- Complexity requirements checking
- Common password detection
- Sequential/repeated character detection
- Entropy calculation
- Overall strength scoring

### Usage
```bash
python3 examples/password_validator.py
```

### Example
```
Enter password to test: MyP@ssw0rd123!

PASSWORD STRENGTH ANALYSIS
========================================
Password: M************! (Length: 15)

--- Checks ---
✓ Length:       Length requirement met
✓ Complexity:   Complexity requirements met
✓ Common:       Not in common passwords list
✓ Patterns:     No common patterns detected

--- Entropy ---
Entropy: 72.45 bits
✓ Strong - Good security

--- Overall Score ---
Score: 100/100
✓ STRONG - Good password
```

### Requirements
- Python 3.7+
- No external dependencies

---

## 2. IP Blocklist Manager

**File:** `examples/ip_blocklist.py`

### Description
Manage a blocklist of IP addresses and network ranges for security purposes. Track blocked IPs with metadata.

### Features
- Add/remove individual IP addresses
- Add/remove network ranges (CIDR notation)
- Check if IP is blocked
- Track blocking reasons and timestamps
- Persistent storage (JSON)
- Statistics and reporting

### Usage
```bash
python3 examples/ip_blocklist.py
```

### Example Commands
```python
# In interactive mode:
# Add single IP
1. Add IP
Enter IP address: 192.168.1.100
Reason: Brute force attempt

# Add network range
2. Add Network
Enter network: 10.0.0.0/24
Reason: Suspicious traffic source

# Check if IP is blocked
5. Check IP
Enter IP: 192.168.1.100
✗ IP 192.168.1.100 is BLOCKED
```

### Requirements
- Python 3.7+
- ipaddress (standard library)

---

## 3. File Integrity Checker

**File:** `examples/file_integrity_checker.py`

### Description
Monitor files for unauthorized changes using cryptographic hashes (SHA-256). Essential for detecting file tampering.

### Features
- Calculate and store file hashes
- Monitor single files or directories
- Detect unauthorized modifications
- Update baselines after authorized changes
- Persistent database
- Detailed integrity reports

### Usage
```bash
python3 examples/file_integrity_checker.py
```

### Example Workflow
```
1. Add file
Enter file path: /etc/passwd
✓ Added /etc/passwd to monitoring

3. Check all files
Checking all monitored files...
✓ All files are intact

5. Update baseline (after authorized change)
Enter file path: /etc/passwd
✓ Updated baseline for /etc/passwd
```

### Requirements
- Python 3.7+
- hashlib (standard library)

---

## 4. Network Packet Analyzer

**File:** `examples/network_packet_analyzer.py`

### Description
Capture and analyze network packets for security monitoring. Detect port scans, suspicious activity, and unusual traffic patterns.

### Features
- Raw packet capture
- Protocol analysis (TCP, UDP, ICMP)
- Port scan detection
- SYN flood detection
- XMAS/NULL scan detection
- Real-time alerts
- Traffic statistics

### Usage
```bash
# Requires root/administrator privileges
sudo python3 examples/network_packet_analyzer.py
```

### Example Output
```
NETWORK PACKET ANALYZER
======================================
Packet #1 - 14:23:45.123
======================================

[Ethernet Frame]
  Source MAC:      aa:bb:cc:dd:ee:ff
  Destination MAC: 11:22:33:44:55:66

[IPv4 Packet]
  Source IP:       192.168.1.100
  Destination IP:  10.0.0.1
  Protocol:        TCP
  TTL:             64

[TCP Segment]
  Source Port:     54321
  Destination Port: 22
  Flags:           SYN

[SECURITY ALERTS]
  ⚠️ Potential SYN scan detected
```

### Requirements
- Python 3.7+
- Root/Administrator privileges
- Linux: socket module (standard library)

**Note:** This tool requires elevated privileges to capture network packets.

---

## 5. Web Security Scanner

**File:** `examples/web_security_scanner.py`

### Description
Comprehensive web application security scanner. Check websites for common vulnerabilities and security misconfigurations.

### Features
- SSL/TLS configuration check
- Security headers analysis
- Cookie security assessment
- Form security review
- Information disclosure detection
- Basic vulnerability scanning (SQL injection, XSS)
- Detailed security report with recommendations

### Usage
```bash
python3 examples/web_security_scanner.py
```

**⚠️ WARNING:** Only scan websites you own or have explicit permission to test!

### Example Scan
```
Enter target URL: https://example.com

WEB SECURITY SCANNER
======================================

[*] Checking SSL/TLS Configuration...
  ✓ HTTPS enabled
  ✓ Certificate valid
  ✓ HTTP redirects to HTTPS

[*] Checking Security Headers...
  ✓ Strict-Transport-Security: Present
  ✗ Content-Security-Policy: Missing [HIGH]
  ✓ X-Frame-Options: Present

[*] Checking Cookie Security...
  ⚠️ Cookie 'session': missing HttpOnly flag [MEDIUM]

SECURITY SCAN REPORT
======================================
Total Vulnerabilities: 5
  Critical: 0
  High:     2
  Medium:   2
  Low:      1

Security Score: 65/100
⚠️ FAIR - Some security improvements needed
```

### Requirements
- Python 3.7+
- requests: `pip install requests`
- beautifulsoup4: `pip install beautifulsoup4`

---

## 6. Secure Messaging System

**File:** `examples/secure_messaging.py`

### Description
End-to-end encrypted messaging system demonstrating hybrid encryption (RSA + AES) and digital signatures.

### Features
- RSA key pair generation (2048-bit)
- Hybrid encryption (RSA for key exchange, AES for messages)
- Digital signatures for authentication
- Public key import/export
- Interactive and demo modes
- Message encryption/decryption

### Usage
```bash
python3 examples/secure_messaging.py
```

### Example: Demo Mode
```
SECURE MESSAGING SYSTEM DEMO
======================================

[Phase 1: Key Generation]
Alice generates her key pair...
✓ Key pair generated successfully

[Phase 2: Key Exchange]
Alice imports Bob's public key...
✓ Peer public key loaded

[Phase 3: Secure Communication]
Alice's original message: 'Hi Bob! This is a secret message.'
Alice encrypts the message...
Encrypted message (first 100 chars): eyJlbmNyeXB0ZWRfa2V5IjogIk...

[Phase 4: Message Reception]
Bob decrypts the message...
Decrypted message: 'Hi Bob! This is a secret message.'

Bob verifies the signature...
✓ Signature verified! Message is authentic.
```

### Requirements
- Python 3.7+
- cryptography: `pip install cryptography`

---

## 7. System Security Audit

**File:** `examples/system_security_audit.py`

### Description
Comprehensive system security auditing tool for Linux/Unix systems. Identify security misconfigurations and vulnerabilities.

### Features
- User account security checks
- File permission auditing
- SSH configuration review
- Firewall status verification
- Package security updates check
- Running services analysis
- System log analysis
- Risk-based scoring

### Usage
```bash
# For full audit (recommended):
sudo python3 examples/system_security_audit.py

# Or without root (limited checks):
python3 examples/system_security_audit.py
```

### Example Report
```
SYSTEM SECURITY AUDIT REPORT
======================================
System: Linux 5.15.0
Hostname: security-server
Audit Date: 2025-10-28 14:30:00

Total Findings: 8
  Critical: 1
  High:     3
  Medium:   3
  Low:      1

--- User Accounts ---
  [HIGH] Non-root users with UID 0: admin2
  Recommendation: Remove root privileges

--- SSH Configuration ---
  [HIGH] SSH allows root login
  Recommendation: Set 'PermitRootLogin no'

--- Firewall ---
  [HIGH] UFW firewall is not active
  Recommendation: Enable firewall

Overall Security Rating: ⚠️ POOR
Risk Score: 42/100
```

### Requirements
- Python 3.7+
- Linux/Unix system
- Root access recommended for complete audit

---

## 8. Malware Detection Tool

**File:** `examples/malware_detection.py`

### Description
Basic malware detection tool using signature-based and heuristic analysis. Educational tool for understanding malware detection techniques.

### Features
- Signature-based detection (hash matching)
- Heuristic analysis (suspicious patterns)
- Entropy analysis (encryption/packing detection)
- PE header inspection
- Filename pattern matching
- Risk level classification
- Detailed detection reports

### Usage
```bash
python3 examples/malware_detection.py
```

### Detection Methods

1. **Signature Matching**: Compare file hashes against known malware
2. **Content Analysis**: Scan for suspicious code patterns
   - eval(), exec() usage
   - System command execution
   - Network operations
   - Base64 encoding/decoding
3. **Entropy Analysis**: High entropy may indicate packing/encryption
4. **Filename Analysis**: Suspicious naming patterns

### Example Scan
```
MALWARE DETECTION TOOL
======================================

[1] Scanning: suspicious_script.py

--- Results ---
File: suspicious_script.py
Size: 1024 bytes
Risk Level: High

Detections:
  • [Content] Code execution via eval() (3 occurrences)
  • [Content] System command execution
  • [Entropy] High entropy (7.8) - possibly encrypted/packed
  • [Filename] Suspicious filename pattern

RECOMMENDATIONS
⚠️ HIGH RISK files detected!
  1. Isolate these files immediately
  2. Run a full antivirus scan
  3. Review system logs
```

### Requirements
- Python 3.7+
- python-magic: `pip install python-magic` (optional, for file type detection)

**Note:** This is an educational tool. Use professional antivirus software for production systems.

---

## 9. DNS Security Checker

**File:** `examples/dns_security_checker.py`

### Description
Comprehensive DNS security and configuration checker. Verify DNS settings and identify potential security issues.

### Features
- DNS resolution verification
- DNSSEC validation
- Email security (SPF, DMARC, DKIM)
- MX record analysis
- Nameserver configuration check
- CAA record verification
- Reverse DNS lookup
- DNS propagation testing
- Detailed security report

### Usage
```bash
python3 examples/dns_security_checker.py
```

### Example Scan
```
DNS SECURITY CHECKER
======================================
Target: example.com

[*] Checking DNS resolution...
  ✓ Domain resolves successfully
  IP Addresses:
    • 93.184.216.34

[*] Checking DNSSEC...
  ✗ DNSSEC is not enabled

[*] Checking SPF record...
  ✓ SPF record found
    "v=spf1 mx -all"

[*] Checking DMARC record...
  ✓ DMARC record found
    "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"

[*] Checking MX records...
  ✓ MX records found
    Priority 10: mail.example.com

DNS SECURITY REPORT
======================================
Total Findings: 3
  High:   0
  Medium: 2
  Low:    1

Security Score: 75/100
Rating: ✓ GOOD
```

### Requirements
- Python 3.7+
- dnspython: `pip install dnspython`

---

## Installation Guide

### Install All Dependencies

```bash
# Core dependencies
pip install cryptography requests beautifulsoup4 dnspython

# Optional dependencies
pip install python-magic scapy bcrypt
```

### Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv cybersec_env

# Activate (Linux/Mac)
source cybersec_env/bin/activate

# Activate (Windows)
cybersec_env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Security Best Practices

### When Using These Tools:

1. **Legal Compliance**
   - Only scan systems you own or have permission to test
   - Unauthorized scanning may be illegal
   - Respect privacy and data protection laws

2. **Ethical Usage**
   - Use for defensive security purposes only
   - Report vulnerabilities responsibly
   - Don't exploit discovered vulnerabilities

3. **Testing Environment**
   - Test on isolated systems first
   - Use virtual machines for malware analysis
   - Don't run untrusted code on production systems

4. **Data Protection**
   - Protect private keys and passwords
   - Store blocklists and logs securely
   - Don't share sensitive scan results publicly

5. **Tool Limitations**
   - These are educational tools
   - Use professional security tools for production
   - Combine multiple detection methods
   - Stay updated on security threats

---

## Troubleshooting

### Common Issues

**Permission Denied Errors:**
```bash
# For tools requiring elevated privileges:
sudo python3 examples/tool_name.py
```

**Module Not Found:**
```bash
# Install missing dependencies:
pip install <module_name>
```

**Network Tools Not Working:**
- Check firewall settings
- Verify network connectivity
- Ensure proper DNS configuration

**File Access Issues:**
- Check file permissions
- Verify file paths
- Ensure sufficient disk space

---

## Contributing

Want to add more tools or improve existing ones?

1. Follow defensive security principles
2. Include comprehensive documentation
3. Add error handling and validation
4. Write clear, commented code
5. Test thoroughly before submitting

---

## Additional Resources

### Learning Resources
- OWASP Top 10
- NIST Cybersecurity Framework
- CIS Controls
- SANS Security Resources

### Security Tools
- Wireshark (Network Analysis)
- Nmap (Port Scanning)
- Metasploit (Penetration Testing)
- Burp Suite (Web Security)

### Python Security Libraries
- pycryptodome (Cryptography)
- scapy (Packet Manipulation)
- paramiko (SSH)
- yara-python (Malware Analysis)

---

## License

These tools are provided for educational purposes. Use responsibly and legally.

---

## Support

Found a bug or have suggestions?
- Open an issue on GitHub
- Review the documentation
- Check existing solutions in the code

---

**Remember:** Security is a continuous process. Stay updated, keep learning, and always work ethically! 🔒
